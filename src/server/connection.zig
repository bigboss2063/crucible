const std = @import("std");
const xev = @import("xev").Dynamic;
const buffer = @import("buffer.zig");
const http = @import("protocol/http.zig");
const resp = @import("protocol/resp.zig");
const comptime_parser = @import("protocol/comptime_parser.zig");

pub const Limits = comptime_parser.Limits;

pub const Protocol = enum {
    unknown,
    http,
    resp,
};

pub const PersistState = enum {
    idle,
    in_progress,
    response_pending,
};

pub const MetricsBatch = struct {
    requests: u64 = 0,
    responses: u64 = 0,

    pub fn reset(self: *MetricsBatch) void {
        self.* = .{};
    }

    pub fn recordRequest(self: *MetricsBatch) void {
        self.requests += 1;
    }

    pub fn recordResponse(self: *MetricsBatch) void {
        self.responses += 1;
    }

    pub fn drain(self: *MetricsBatch) MetricsBatch {
        if (self.requests == 0 and self.responses == 0) return .{};
        const snapshot = self.*;
        self.reset();
        return snapshot;
    }

    pub fn drainInto(self: *MetricsBatch, dst: *MetricsBatch) void {
        if (self.requests == 0 and self.responses == 0) return;
        dst.requests += self.requests;
        dst.responses += self.responses;
        self.reset();
    }
};

pub const Connection = struct {
    id: usize,
    tcp: xev.TCP,
    server: ?*anyopaque,
    read_buf: buffer.LinearBuffer,
    write_buf: buffer.LinearBuffer,
    protocol: Protocol,
    http_parser: http.Parser,
    resp_parser: resp.Parser,
    keepalive: bool,
    write_in_progress: bool,
    read_needs_more: bool,
    persist_state: PersistState,
    persist_response_ok: bool,
    persist_close_after: bool,
    closing: bool,
    close_queued: bool,
    close_done: bool,
    in_pool: bool,
    generation: u64,
    read_token: u64,
    write_token: u64,
    timer_token: u64,
    timer_cancel_token: u64,
    close_token: u64,
    timer: xev.Timer,
    timer_completion: xev.Completion = .{},
    timer_cancel: xev.Completion = .{},
    read_completion: xev.Completion = .{},
    write_completion: xev.Completion = .{},
    close_completion: xev.Completion = .{},
    limits: Limits,
    pending_metrics: MetricsBatch,

    pub fn init(
        id: usize,
        allocator: std.mem.Allocator,
        read_buffer_bytes: usize,
        write_buffer_bytes: usize,
        max_request_bytes: usize,
        max_response_bytes: usize,
        limits: Limits,
    ) !Connection {
        var read_buf = try buffer.LinearBuffer.init(allocator, read_buffer_bytes, max_request_bytes);
        errdefer read_buf.deinit();
        const write_buf = try buffer.LinearBuffer.init(allocator, write_buffer_bytes, max_response_bytes);
        return .{
            .id = id,
            .tcp = undefined,
            .server = null,
            .read_buf = read_buf,
            .write_buf = write_buf,
            .protocol = .unknown,
            .http_parser = http.Parser.init(limits),
            .resp_parser = resp.Parser.init(limits),
            .keepalive = false,
            .write_in_progress = false,
            .read_needs_more = false,
            .persist_state = .idle,
            .persist_response_ok = false,
            .persist_close_after = false,
            .closing = false,
            .close_queued = false,
            .close_done = false,
            .in_pool = true,
            .generation = 0,
            .read_token = 0,
            .write_token = 0,
            .timer_token = 0,
            .timer_cancel_token = 0,
            .close_token = 0,
            .timer = try xev.Timer.init(),
            .limits = limits,
            .pending_metrics = .{},
        };
    }

    pub fn reset(self: *Connection, tcp: xev.TCP, limits: Limits) !void {
        self.tcp = tcp;
        self.server = null;
        self.read_buf.clear();
        self.write_buf.clear();
        self.protocol = .unknown;
        self.http_parser = http.Parser.init(limits);
        self.resp_parser = resp.Parser.init(limits);
        self.keepalive = false;
        self.write_in_progress = false;
        self.read_needs_more = false;
        self.persist_state = .idle;
        self.persist_response_ok = false;
        self.persist_close_after = false;
        self.closing = false;
        self.close_queued = false;
        self.close_done = false;
        self.in_pool = false;
        self.generation +%= 1;
        if (self.generation == 0) self.generation = 1;
        self.read_token = 0;
        self.write_token = 0;
        self.timer_token = 0;
        self.timer_cancel_token = 0;
        self.close_token = 0;
        self.limits = limits;
        self.timer_completion = .{};
        self.timer_cancel = .{};
        self.read_completion = .{};
        self.write_completion = .{};
        self.close_completion = .{};
        self.timer = try xev.Timer.init();
        self.pending_metrics.reset();
    }
};

pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    conns: []Connection,
    free: []usize,
    free_len: usize,
    read_buffer_bytes: usize,
    write_buffer_bytes: usize,
    max_request_bytes: usize,
    max_response_bytes: usize,
    limits: Limits,

    pub fn init(
        allocator: std.mem.Allocator,
        max_connections: usize,
        read_buffer_bytes: usize,
        write_buffer_bytes: usize,
        max_request_bytes: usize,
        max_response_bytes: usize,
        limits: Limits,
    ) !ConnectionPool {
        var conns = try allocator.alloc(Connection, max_connections);
        errdefer allocator.free(conns);
        var free = try allocator.alloc(usize, max_connections);
        errdefer allocator.free(free);

        var i: usize = 0;
        while (i < max_connections) : (i += 1) {
            conns[i] = try Connection.init(
                i,
                allocator,
                read_buffer_bytes,
                write_buffer_bytes,
                max_request_bytes,
                max_response_bytes,
                limits,
            );
            free[i] = max_connections - 1 - i;
        }

        return .{
            .allocator = allocator,
            .conns = conns,
            .free = free,
            .free_len = max_connections,
            .read_buffer_bytes = read_buffer_bytes,
            .write_buffer_bytes = write_buffer_bytes,
            .max_request_bytes = max_request_bytes,
            .max_response_bytes = max_response_bytes,
            .limits = limits,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        for (self.conns) |*conn| {
            conn.read_buf.deinit();
            conn.write_buf.deinit();
        }
        self.allocator.free(self.conns);
        self.allocator.free(self.free);
    }

    pub fn acquire(self: *ConnectionPool, tcp: xev.TCP) ?*Connection {
        if (self.free_len == 0) return null;
        self.free_len -= 1;
        const idx = self.free[self.free_len];
        var conn = &self.conns[idx];
        conn.reset(tcp, self.limits) catch {
            self.free[self.free_len] = idx;
            self.free_len += 1;
            return null;
        };
        return conn;
    }

    pub fn release(self: *ConnectionPool, conn: *Connection) void {
        if (conn.in_pool) return;
        conn.read_buf.clear();
        conn.write_buf.clear();
        conn.read_buf.shrinkToInit();
        conn.write_buf.shrinkToInit();
        conn.protocol = .unknown;
        conn.keepalive = false;
        conn.write_in_progress = false;
        conn.read_needs_more = false;
        conn.closing = false;
        conn.close_queued = false;
        conn.close_done = false;
        conn.in_pool = true;
        conn.read_token = 0;
        conn.write_token = 0;
        conn.timer_token = 0;
        conn.timer_cancel_token = 0;
        conn.close_token = 0;
        conn.pending_metrics.reset();
        self.free[self.free_len] = conn.id;
        self.free_len += 1;
    }
};

test "connection pool acquire and release" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const limits = Limits{
        .max_key_length = 64,
        .max_value_length = 64,
        .max_args = 32,
    };
    var pool = try ConnectionPool.init(allocator, 2, 64, 64, 64, 64, limits);
    defer pool.deinit();

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    const tcp1 = try xev.TCP.init(addr);
    const tcp2 = try xev.TCP.init(addr);
    const tcp3 = try xev.TCP.init(addr);
    const c1 = pool.acquire(tcp1).?;
    _ = pool.acquire(tcp2).?;
    try std.testing.expect(pool.acquire(tcp3) == null);
    pool.release(c1);
    try std.testing.expect(pool.acquire(try xev.TCP.init(addr)) != null);
}
