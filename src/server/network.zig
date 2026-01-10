const std = @import("std");
const builtin = @import("builtin");
const xev = @import("xev").Dynamic;
const cache = @import("../cache/mod.zig");
const connection = @import("connection.zig");
const execute = @import("execute.zig");
const output_buffer = @import("output_buffer.zig");
const persistence = @import("persistence.zig");
const resource_controls = @import("resource_controls.zig");
const stats = @import("stats.zig");
const http = @import("protocol/http.zig");
const resp = @import("protocol/resp.zig");
const comptime_parser = @import("protocol/comptime_parser.zig");

pub const Protocol = enum {
    auto,
    http,
    resp,
};

pub const Limits = comptime_parser.Limits;

const default_read_buffer_bytes: usize = 16 * 1024;
const default_request_bytes: usize = 1024 * 1024;

pub const ServerOptions = struct {
    allocator: std.mem.Allocator,
    cache: *cache.api.Cache,
    persist_path: ?[]const u8 = null,
    unix_path: ?[]const u8 = null,
    address: std.net.Address,
    protocol: Protocol = .auto,
    max_connections: usize = 10_000,
    keepalive_timeout_ns: u64 = 60 * std.time.ns_per_s,
    backlog: u31 = 128,
    loop_entries: u32 = 256,
    thread_pool: ?*xev.ThreadPool = null,
    maxmemory_bytes: ?u64 = null,
    evict: bool = true,
    autosweep: bool = true,
    output_limits: output_buffer.OutputLimit = .{},
};

pub const ErrorCounts = struct {
    accept: u64 = 0,
    read: u64 = 0,
    write: u64 = 0,
    parse: u64 = 0,
    protocol: u64 = 0,
    pool_full: u64 = 0,
    buffer_overflow: u64 = 0,
    cache: u64 = 0,
    timeout: u64 = 0,
};

pub const Metrics = struct {
    active_connections: usize = 0,
    total_connections: u64 = 0,
    total_requests: u64 = 0,
    total_responses: u64 = 0,
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,
    errors: ErrorCounts = .{},
};

const MetricsSnapshotFn = *const fn (*const anyopaque) Metrics;

const AtomicU64 = std.atomic.Value(u64);
const AtomicUsize = std.atomic.Value(usize);
const AtomicBool = std.atomic.Value(bool);

pub const AtomicErrorCounts = struct {
    accept: AtomicU64,
    read: AtomicU64,
    write: AtomicU64,
    parse: AtomicU64,
    protocol: AtomicU64,
    pool_full: AtomicU64,
    buffer_overflow: AtomicU64,
    cache: AtomicU64,
    timeout: AtomicU64,

    pub fn init() AtomicErrorCounts {
        return .{
            .accept = AtomicU64.init(0),
            .read = AtomicU64.init(0),
            .write = AtomicU64.init(0),
            .parse = AtomicU64.init(0),
            .protocol = AtomicU64.init(0),
            .pool_full = AtomicU64.init(0),
            .buffer_overflow = AtomicU64.init(0),
            .cache = AtomicU64.init(0),
            .timeout = AtomicU64.init(0),
        };
    }

    pub fn snapshot(self: *const AtomicErrorCounts) ErrorCounts {
        return .{
            .accept = self.accept.load(.monotonic),
            .read = self.read.load(.monotonic),
            .write = self.write.load(.monotonic),
            .parse = self.parse.load(.monotonic),
            .protocol = self.protocol.load(.monotonic),
            .pool_full = self.pool_full.load(.monotonic),
            .buffer_overflow = self.buffer_overflow.load(.monotonic),
            .cache = self.cache.load(.monotonic),
            .timeout = self.timeout.load(.monotonic),
        };
    }
};

pub const AtomicMetrics = struct {
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    total_requests: AtomicU64,
    total_responses: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    errors: AtomicErrorCounts,

    pub fn init() AtomicMetrics {
        return .{
            .active_connections = AtomicUsize.init(0),
            .total_connections = AtomicU64.init(0),
            .total_requests = AtomicU64.init(0),
            .total_responses = AtomicU64.init(0),
            .bytes_read = AtomicU64.init(0),
            .bytes_written = AtomicU64.init(0),
            .errors = AtomicErrorCounts.init(),
        };
    }

    pub fn snapshot(self: *const AtomicMetrics) Metrics {
        return .{
            .active_connections = self.active_connections.load(.monotonic),
            .total_connections = self.total_connections.load(.monotonic),
            .total_requests = self.total_requests.load(.monotonic),
            .total_responses = self.total_responses.load(.monotonic),
            .bytes_read = self.bytes_read.load(.monotonic),
            .bytes_written = self.bytes_written.load(.monotonic),
            .errors = self.errors.snapshot(),
        };
    }
};

fn snapshotAtomic(ctx_ptr: *const anyopaque) Metrics {
    const metrics = @as(*const AtomicMetrics, @ptrCast(@alignCast(ctx_ptr)));
    return metrics.snapshot();
}

fn addU64(value: *AtomicU64, delta: u64) void {
    _ = value.fetchAdd(delta, .monotonic);
}

fn addUsize(value: *AtomicUsize, delta: usize) void {
    _ = value.fetchAdd(delta, .monotonic);
}

fn subUsize(value: *AtomicUsize, delta: usize) void {
    _ = value.fetchSub(delta, .monotonic);
}

fn addErrorCounts(dst: *ErrorCounts, src: ErrorCounts) void {
    dst.accept += src.accept;
    dst.read += src.read;
    dst.write += src.write;
    dst.parse += src.parse;
    dst.protocol += src.protocol;
    dst.pool_full += src.pool_full;
    dst.buffer_overflow += src.buffer_overflow;
    dst.cache += src.cache;
    dst.timeout += src.timeout;
}

fn addMetrics(dst: *Metrics, src: Metrics) void {
    dst.active_connections += src.active_connections;
    dst.total_connections += src.total_connections;
    dst.total_requests += src.total_requests;
    dst.total_responses += src.total_responses;
    dst.bytes_read += src.bytes_read;
    dst.bytes_written += src.bytes_written;
    addErrorCounts(&dst.errors, src.errors);
}

const MetricsBatch = connection.MetricsBatch;

const MonitorEvent = struct {
    payload: []u8,
};

const MonitorQueue = struct {
    events: []MonitorEvent,
    head: usize = 0,
    tail: usize = 0,
    len: usize = 0,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !MonitorQueue {
        const cap = if (capacity == 0) 1 else capacity;
        const events = try allocator.alloc(MonitorEvent, cap);
        return .{ .events = events };
    }

    pub fn deinit(self: *MonitorQueue, allocator: std.mem.Allocator) void {
        allocator.free(self.events);
    }

    pub fn push(self: *MonitorQueue, event: MonitorEvent) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.len == self.events.len) return false;
        self.events[self.tail] = event;
        self.tail = (self.tail + 1) % self.events.len;
        self.len += 1;
        return true;
    }

    pub fn pop(self: *MonitorQueue) ?MonitorEvent {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.len == 0) return null;
        const event = self.events[self.head];
        self.head = (self.head + 1) % self.events.len;
        self.len -= 1;
        if (self.len == 0) {
            self.head = 0;
            self.tail = 0;
        }
        return event;
    }
};

const MonitorRegistry = struct {
    conns: std.ArrayListUnmanaged(*connection.Connection) = .{},

    pub fn deinit(self: *MonitorRegistry, allocator: std.mem.Allocator) void {
        self.conns.deinit(allocator);
    }
};

const MonitorTarget = struct {
    queue: *MonitorQueue,
    overflow: *AtomicBool,
    async: *xev.Async,
};

const MonitorHub = struct {
    allocator: std.mem.Allocator,
    total: AtomicUsize,
    targets: []MonitorTarget,
};

const metrics_flush_interval_ms: u64 = 50;

fn flushMetricsBatch(ctx: *ServerContext) void {
    const batch = ctx.metrics_batch.drain();
    if (batch.requests == 0 and batch.responses == 0) return;
    if (batch.requests != 0) addU64(&ctx.metrics.total_requests, batch.requests);
    if (batch.responses != 0) addU64(&ctx.metrics.total_responses, batch.responses);
}

fn flushConnectionMetrics(conn: *connection.Connection, ctx: *ServerContext) void {
    conn.pending_metrics.drainInto(ctx.metrics_batch);
}

fn recordRequest(conn: *connection.Connection) void {
    conn.pending_metrics.recordRequest();
}

fn recordResponse(conn: *connection.Connection) void {
    conn.pending_metrics.recordResponse();
}

fn setClientAddr(conn: *connection.Connection, value: []const u8) void {
    const len = @min(value.len, conn.client_addr_buf.len);
    std.mem.copyForwards(u8, conn.client_addr_buf[0..len], value[0..len]);
    conn.client_addr_len = len;
}

fn initClientAddr(conn: *connection.Connection, tcp: xev.TCP, is_unix: bool) void {
    if (is_unix) {
        setClientAddr(conn, "unix");
        return;
    }
    var addr_storage: std.posix.sockaddr.storage = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    std.posix.getpeername(tcp.fd(), @ptrCast(&addr_storage), &addr_len) catch {
        setClientAddr(conn, "unknown");
        return;
    };
    const addr = std.net.Address.initPosix(@ptrCast(&addr_storage));
    const rendered = std.fmt.bufPrint(&conn.client_addr_buf, "{f}", .{addr}) catch {
        setClientAddr(conn, "unknown");
        return;
    };
    conn.client_addr_len = rendered.len;
}

fn monitorRegister(conn: *connection.Connection, ctx: *ServerContext) bool {
    if (conn.monitoring) return true;
    ctx.monitor_registry.conns.append(ctx.options.allocator, conn) catch return false;
    conn.monitoring = true;
    if (ctx.monitor_hub) |hub| {
        _ = hub.total.fetchAdd(1, .monotonic);
    }
    return true;
}

fn monitorUnregister(conn: *connection.Connection, ctx: *ServerContext) void {
    if (!conn.monitoring) return;
    conn.monitoring = false;
    var idx: usize = 0;
    const items = ctx.monitor_registry.conns.items;
    while (idx < items.len) : (idx += 1) {
        if (items[idx] == conn) {
            const last = items.len - 1;
            ctx.monitor_registry.conns.items[idx] = ctx.monitor_registry.conns.items[last];
            ctx.monitor_registry.conns.items.len = last;
            break;
        }
    }
    if (ctx.monitor_hub) |hub| {
        _ = hub.total.fetchSub(1, .monotonic);
    }
}

fn monitorEmit(ctx: *ServerContext, origin: *connection.Connection, args: []const []const u8) void {
    if (args.len == 0) return;
    if (ctx.monitor_hub) |hub| {
        if (hub.total.load(.monotonic) == 0) return;
    } else if (ctx.monitor_registry.conns.items.len == 0) {
        return;
    }

    const allocator = ctx.options.allocator;
    const line = formatMonitorLine(allocator, origin.clientAddr(), args) catch return;
    defer allocator.free(line);

    if (ctx.monitor_hub) |hub| {
        for (hub.targets) |target| {
            const payload = allocator.alloc(u8, line.len) catch {
                target.overflow.store(true, .monotonic);
                target.async.notify() catch {};
                continue;
            };
            std.mem.copyForwards(u8, payload, line);
            if (!target.queue.push(.{ .payload = payload })) {
                allocator.free(payload);
                target.overflow.store(true, .monotonic);
            }
            target.async.notify() catch {};
        }
    } else {
        deliverMonitorLine(ctx, line);
    }
}

fn closeAllMonitors(ctx: *ServerContext) void {
    while (ctx.monitor_registry.conns.items.len != 0) {
        const idx = ctx.monitor_registry.conns.items.len - 1;
        const conn = ctx.monitor_registry.conns.items[idx];
        closeConnection(conn, ctx);
    }
}

fn clearMonitorQueue(queue: *MonitorQueue, allocator: std.mem.Allocator) void {
    while (queue.pop()) |event| {
        allocator.free(event.payload);
    }
}

fn drainMonitorQueue(ctx: *ServerContext) void {
    const queue = ctx.monitor_queue orelse return;
    if (ctx.monitor_overflow) |overflow| {
        if (overflow.swap(false, .acq_rel)) {
            closeAllMonitors(ctx);
            clearMonitorQueue(queue, ctx.options.allocator);
        }
    }
    while (queue.pop()) |event| {
        deliverMonitorLine(ctx, event.payload);
        ctx.options.allocator.free(event.payload);
    }
}

fn deliverMonitorLine(ctx: *ServerContext, line: []const u8) void {
    var idx: usize = 0;
    while (idx < ctx.monitor_registry.conns.items.len) {
        const conn = ctx.monitor_registry.conns.items[idx];
        if (conn.in_pool or conn.close_done or conn.close_queued or conn.closing) {
            monitorUnregister(conn, ctx);
            continue;
        }
        const writer = &conn.output;
        if (!writeAll(writer, line)) {
            handleOutputOverflow(conn, ctx);
            closeConnection(conn, ctx);
            continue;
        }
        queueWrite(conn, ctx);
        idx += 1;
    }
}

fn formatMonitorLine(
    allocator: std.mem.Allocator,
    client_addr: []const u8,
    args: []const []const u8,
) ![]u8 {
    var list = std.ArrayList(u8).empty;
    errdefer list.deinit(allocator);
    const ts_us = std.time.microTimestamp();
    const secs = @divFloor(ts_us, 1_000_000);
    const micros: u32 = @intCast(@mod(ts_us, 1_000_000));
    try list.print(allocator, "+{d}.{d:0>6} [0 {s}]", .{ secs, micros, client_addr });
    for (args) |arg| {
        try appendEscapedArg(&list, allocator, arg);
    }
    try list.appendSlice(allocator, "\r\n");
    return list.toOwnedSlice(allocator);
}

fn appendEscapedArg(list: *std.ArrayList(u8), allocator: std.mem.Allocator, arg: []const u8) !void {
    try list.appendSlice(allocator, " \"");
    for (arg) |ch| {
        switch (ch) {
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            else => {
                if (ch < 32 or ch >= 127) {
                    try appendHexByte(list, allocator, ch);
                } else {
                    try list.append(allocator, ch);
                }
            },
        }
    }
    try list.append(allocator, '"');
}

fn appendHexByte(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u8) !void {
    const hex = "0123456789ABCDEF";
    try list.appendSlice(allocator, "\\x");
    try list.append(allocator, hex[value >> 4]);
    try list.append(allocator, hex[value & 0xF]);
}

test "monitor queue push pop and clear" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var queue = try MonitorQueue.init(allocator, 2);
    defer queue.deinit(allocator);

    const payload1 = try allocator.dupe(u8, "a");
    const payload2 = try allocator.dupe(u8, "b");
    try std.testing.expect(queue.push(.{ .payload = payload1 }));
    try std.testing.expect(queue.push(.{ .payload = payload2 }));

    const payload3 = try allocator.dupe(u8, "c");
    if (!queue.push(.{ .payload = payload3 })) {
        allocator.free(payload3);
    }

    clearMonitorQueue(&queue, allocator);
    try std.testing.expect(queue.pop() == null);
}

test "monitor line formatting escapes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = [_][]const u8{ "a\nb", "c\rd", "e\tf", "g\"h", "i\\j", "\xff" };
    const line = try formatMonitorLine(allocator, "127.0.0.1:1", args[0..]);
    defer allocator.free(line);

    try std.testing.expect(std.mem.indexOf(u8, line, "127.0.0.1:1") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\\r") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\\t") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\\\\") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\\xFF") != null);
    try std.testing.expect(std.mem.endsWith(u8, line, "\r\n"));
}

test "metrics helpers aggregate and snapshot" {
    const errors = ErrorCounts{
        .accept = 1,
        .read = 2,
        .write = 3,
        .parse = 4,
        .protocol = 5,
        .pool_full = 6,
        .buffer_overflow = 7,
        .cache = 8,
        .timeout = 9,
    };
    var dst_errors = ErrorCounts{};
    addErrorCounts(&dst_errors, errors);
    try std.testing.expectEqual(errors.accept, dst_errors.accept);
    try std.testing.expectEqual(errors.timeout, dst_errors.timeout);

    var dst_metrics = Metrics{
        .active_connections = 1,
        .total_connections = 2,
        .total_requests = 3,
        .total_responses = 4,
        .bytes_read = 5,
        .bytes_written = 6,
        .errors = .{ .accept = 1 },
    };
    const src_metrics = Metrics{
        .active_connections = 10,
        .total_connections = 20,
        .total_requests = 30,
        .total_responses = 40,
        .bytes_read = 50,
        .bytes_written = 60,
        .errors = errors,
    };
    addMetrics(&dst_metrics, src_metrics);
    try std.testing.expectEqual(@as(usize, 11), dst_metrics.active_connections);
    try std.testing.expectEqual(@as(u64, 22), dst_metrics.total_connections);
    try std.testing.expectEqual(@as(u64, 33), dst_metrics.total_requests);
    try std.testing.expectEqual(@as(u64, 44), dst_metrics.total_responses);
    try std.testing.expectEqual(@as(u64, 55), dst_metrics.bytes_read);
    try std.testing.expectEqual(@as(u64, 66), dst_metrics.bytes_written);
    try std.testing.expectEqual(@as(u64, 2), dst_metrics.errors.accept);

    var atomic = AtomicMetrics.init();
    addUsize(&atomic.active_connections, 2);
    subUsize(&atomic.active_connections, 1);
    addU64(&atomic.total_connections, 3);
    addU64(&atomic.total_requests, 4);
    addU64(&atomic.total_responses, 5);

    const snap = atomic.snapshot();
    try std.testing.expectEqual(@as(usize, 1), snap.active_connections);
    try std.testing.expectEqual(@as(u64, 3), snap.total_connections);
    try std.testing.expectEqual(@as(u64, 4), snap.total_requests);
    try std.testing.expectEqual(@as(u64, 5), snap.total_responses);

    const snap2 = snapshotAtomic(@ptrCast(&atomic));
    try std.testing.expectEqual(@as(usize, 1), snap2.active_connections);

    var batch = MetricsBatch{ .requests = 2, .responses = 3 };
    var ctx: ServerContext = undefined;
    ctx.metrics = &atomic;
    ctx.metrics_batch = &batch;
    flushMetricsBatch(&ctx);
    try std.testing.expectEqual(@as(u64, 6), atomic.total_requests.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 8), atomic.total_responses.load(.monotonic));
}

fn startMetricsFlush(ctx: *ServerContext) void {
    if (metrics_flush_interval_ms == 0) return;
    ctx.metrics_timer.run(ctx.loop, ctx.metrics_timer_completion, metrics_flush_interval_ms, ServerContext, ctx, onMetricsFlush);
}

fn onMetricsFlush(
    ud: ?*ServerContext,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Timer.RunError!void,
) xev.CallbackAction {
    const ctx = ud.?;
    _ = result catch |err| {
        if (err == error.Canceled) return .disarm;
        return .disarm;
    };
    flushMetricsBatch(ctx);
    startMetricsFlush(ctx);
    return .disarm;
}

fn configureSocket(tcp: xev.TCP, is_unix: bool) bool {
    if (is_unix) return true;
    if (builtin.os.tag != .linux) return true;
    const fd = tcp.fd();
    const yes: c_int = 1;
    const yes_bytes = std.mem.toBytes(yes);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, &yes_bytes) catch return false;
    std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.os.linux.TCP.NODELAY, &yes_bytes) catch return false;
    std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.os.linux.TCP.QUICKACK, &yes_bytes) catch return false;
    return true;
}

fn configureListener(tcp: xev.TCP, is_unix: bool) bool {
    if (is_unix) return true;
    if (builtin.os.tag != .linux) return true;
    const fd = tcp.fd();
    const yes: c_int = 1;
    const yes_bytes = std.mem.toBytes(yes);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, &yes_bytes) catch return false;
    return true;
}

const PersistNotify = struct {
    allocator: std.mem.Allocator,
    queue: *PersistQueue,
    async: *xev.Async,
    conn: *connection.Connection,
    generation: u64,
    ok: bool = false,
    next: ?*PersistNotify = null,
};

const PersistQueue = struct {
    mutex: std.Thread.Mutex = .{},
    head: ?*PersistNotify = null,
    tail: ?*PersistNotify = null,

    pub fn init() PersistQueue {
        return .{};
    }

    pub fn deinit(self: *PersistQueue) void {
        self.mutex.lock();
        var node = self.head;
        self.head = null;
        self.tail = null;
        self.mutex.unlock();

        while (node) |notify| {
            const next = notify.next;
            notify.allocator.destroy(notify);
            node = next;
        }
    }

    pub fn push(self: *PersistQueue, notify: *PersistNotify) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        notify.next = null;
        if (self.tail) |tail| {
            tail.next = notify;
        } else {
            self.head = notify;
        }
        self.tail = notify;
    }

    pub fn pop(self: *PersistQueue) ?*PersistNotify {
        self.mutex.lock();
        defer self.mutex.unlock();
        const head = self.head orelse return null;
        self.head = head.next;
        if (self.head == null) {
            self.tail = null;
        }
        head.next = null;
        return head;
    }
};

const ServerContext = struct {
    loop: *xev.Loop,
    pool: *connection.ConnectionPool,
    options: *const ServerOptions,
    limits: Limits,
    metrics: *AtomicMetrics,
    metrics_snapshot: MetricsSnapshotFn,
    metrics_snapshot_ctx: *const anyopaque,
    start_time_ms: u64,
    active_connections: *AtomicUsize,
    cache: *cache.api.Cache,
    persistence: *persistence.Manager,
    persist_queue: *PersistQueue,
    persist_async: *xev.Async,
    resource_controls: ?*resource_controls.ResourceControls,
    metrics_batch: *MetricsBatch,
    metrics_timer: *xev.Timer,
    metrics_timer_completion: *xev.Completion,
    monitor_registry: *MonitorRegistry,
    monitor_queue: ?*MonitorQueue,
    monitor_overflow: ?*AtomicBool,
    monitor_hub: ?*MonitorHub,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    cache: *cache.api.Cache,
    options: ServerOptions,
    limits: Limits,
    loop: xev.Loop,
    listener: xev.TCP,
    accept_completion: xev.Completion = .{},
    unix_listener: ?xev.TCP = null,
    unix_accept_completion: xev.Completion = .{},
    shutdown_async: xev.Async,
    shutdown_completion: xev.Completion = .{},
    persist_queue: PersistQueue,
    persist_async: xev.Async,
    persist_async_completion: xev.Completion = .{},
    pool: connection.ConnectionPool,
    metrics: *AtomicMetrics,
    owns_metrics: bool = false,
    metrics_batch: MetricsBatch,
    metrics_timer: xev.Timer,
    metrics_timer_completion: xev.Completion = .{},
    monitor_registry: MonitorRegistry,
    start_time_ms: u64,
    persistence: *persistence.Manager,
    context: ServerContext,
    bound_address: std.net.Address,
    resource_controls: resource_controls.ResourceControls,

    pub fn init(opts: ServerOptions) !Server {
        var server: Server = undefined;
        try server.initInPlace(opts);
        return server;
    }

    pub fn initInPlace(self: *Server, opts: ServerOptions) !void {
        try xev.detect();
        if (opts.unix_path != null and !std.net.has_unix_sockets) return error.UnixSocketUnsupported;
        const limits = Limits{
            .max_key_length = default_request_bytes,
            .max_value_length = default_request_bytes,
            .max_args = 32,
        };
        const metrics = try opts.allocator.create(AtomicMetrics);
        metrics.* = AtomicMetrics.init();
        errdefer opts.allocator.destroy(metrics);
        const start_time_ms = @as(u64, @intCast(std.time.milliTimestamp()));
        const persistence_mgr = try opts.allocator.create(persistence.Manager);
        persistence_mgr.* = persistence.Manager.init(opts.allocator, opts.cache, opts.persist_path);
        errdefer opts.allocator.destroy(persistence_mgr);
        var loop = try xev.Loop.init(.{
            .entries = opts.loop_entries,
            .thread_pool = opts.thread_pool,
        });
        errdefer loop.deinit();

        var shutdown_async = try xev.Async.init();
        errdefer shutdown_async.deinit();

        var persist_async = try xev.Async.init();
        errdefer persist_async.deinit();

        const metrics_timer = try xev.Timer.init();

        var listener = try xev.TCP.init(opts.address);
        errdefer closeTcpImmediate(listener);
        if (!configureListener(listener, false)) return error.SocketOptionFailed;
        try listener.bind(opts.address);
        try listener.listen(opts.backlog);

        var unix_listener: ?xev.TCP = null;
        if (opts.unix_path) |path| {
            const unix_addr = try std.net.Address.initUnix(path);
            std.posix.unlink(path) catch {};
            var unix_tcp = try xev.TCP.init(unix_addr);
            errdefer closeTcpImmediate(unix_tcp);
            if (!configureListener(unix_tcp, true)) return error.SocketOptionFailed;
            try unix_tcp.bind(unix_addr);
            try unix_tcp.listen(opts.backlog);
            unix_listener = unix_tcp;
        }

        const bound_address = try getBoundAddress(listener);
        var pool = try connection.ConnectionPool.init(
            opts.allocator,
            opts.max_connections,
            default_read_buffer_bytes,
            output_buffer.default_inline_bytes,
            output_buffer.default_chunk_bytes,
            limits,
            opts.output_limits,
        );
        errdefer pool.deinit();

        self.* = Server{
            .allocator = opts.allocator,
            .cache = opts.cache,
            .options = opts,
            .limits = limits,
            .loop = loop,
            .listener = listener,
            .unix_listener = unix_listener,
            .pool = pool,
            .metrics = metrics,
            .owns_metrics = true,
            .metrics_batch = .{},
            .metrics_timer = metrics_timer,
            .monitor_registry = .{},
            .start_time_ms = start_time_ms,
            .persistence = persistence_mgr,
            .context = undefined,
            .bound_address = bound_address,
            .shutdown_async = shutdown_async,
            .persist_queue = PersistQueue.init(),
            .persist_async = persist_async,
            .resource_controls = resource_controls.ResourceControls.init(opts.maxmemory_bytes, opts.evict, opts.autosweep),
        };
    }

    pub fn deinit(self: *Server) void {
        self.resource_controls.stop();
        closeTcpImmediate(self.listener);
        if (self.unix_listener) |listener| {
            closeTcpImmediate(listener);
        }
        self.persistence.waitForIdle();
        self.persistence.drainPendingPath();
        self.pool.deinit();
        self.monitor_registry.deinit(self.allocator);
        self.shutdown_async.deinit();
        self.persist_async.deinit();
        self.persist_queue.deinit();
        self.loop.deinit();
        self.allocator.destroy(self.persistence);
        if (self.owns_metrics) {
            self.allocator.destroy(self.metrics);
        }
    }

    pub fn run(self: *Server) !void {
        self.context = .{
            .loop = &self.loop,
            .pool = &self.pool,
            .options = &self.options,
            .limits = self.limits,
            .metrics = self.metrics,
            .metrics_snapshot = snapshotAtomic,
            .metrics_snapshot_ctx = self.metrics,
            .start_time_ms = self.start_time_ms,
            .active_connections = &self.metrics.active_connections,
            .cache = self.cache,
            .persistence = self.persistence,
            .persist_queue = &self.persist_queue,
            .persist_async = &self.persist_async,
            .resource_controls = &self.resource_controls,
            .metrics_batch = &self.metrics_batch,
            .metrics_timer = &self.metrics_timer,
            .metrics_timer_completion = &self.metrics_timer_completion,
            .monitor_registry = &self.monitor_registry,
            .monitor_queue = null,
            .monitor_overflow = null,
            .monitor_hub = null,
        };
        try self.resource_controls.start(self.cache);
        startMetricsFlush(&self.context);
        self.shutdown_async.wait(&self.loop, &self.shutdown_completion, Server, self, onServerShutdownAsync);
        self.persist_async.wait(&self.loop, &self.persist_async_completion, Server, self, onServerPersistAsync);
        self.queueAccept();
        try self.loop.run(.until_done);
        flushMetricsBatch(&self.context);
    }

    pub fn stop(self: *Server) void {
        self.resource_controls.stop();
        self.shutdown_async.notify() catch {};
    }

    pub fn address(self: *const Server) std.net.Address {
        return self.bound_address;
    }

    pub fn metricsSnapshot(self: *const Server) Metrics {
        return self.metrics.snapshot();
    }

    fn queueAccept(self: *Server) void {
        self.queueAcceptTcp();
        self.queueAcceptUnix();
    }

    fn queueAcceptTcp(self: *Server) void {
        self.listener.accept(&self.loop, &self.accept_completion, Server, self, onAcceptTcp);
    }

    fn queueAcceptUnix(self: *Server) void {
        if (self.unix_listener) |listener| {
            listener.accept(&self.loop, &self.unix_accept_completion, Server, self, onAcceptUnix);
        }
    }
};

fn onServerShutdownAsync(
    _: ?*Server,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.Async.WaitError!void,
) xev.CallbackAction {
    _ = result catch |err| {
        if (err == error.Canceled) return .disarm;
        return .disarm;
    };
    loop.stop();
    return .disarm;
}

fn onServerPersistAsync(
    ud: ?*Server,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Async.WaitError!void,
) xev.CallbackAction {
    const server = ud.?;
    _ = result catch |err| {
        if (err == error.Canceled) return .disarm;
        return .disarm;
    };
    drainPersistQueue(&server.context);
    return .rearm;
}

fn persistNotify(ctx_ptr: *anyopaque, ok: bool) void {
    const ctx = @as(*PersistNotify, @ptrCast(@alignCast(ctx_ptr)));
    ctx.ok = ok;
    ctx.queue.push(ctx);
    ctx.async.notify() catch {};
}

fn drainPersistQueue(ctx: *ServerContext) void {
    while (ctx.persist_queue.pop()) |notify| {
        handlePersistCompletion(ctx, notify);
        notify.allocator.destroy(notify);
    }
}

fn handleAccept(server: *Server, result: xev.AcceptError!xev.TCP, is_unix: bool) void {
    if (result) |tcp| {
        addU64(&server.metrics.total_connections, 1);
        if (!configureSocket(tcp, is_unix)) {
            addU64(&server.metrics.errors.accept, 1);
            closeTcpImmediate(tcp);
            return;
        }
        if (server.pool.acquire(tcp)) |conn| {
            conn.server = &server.context;
            initClientAddr(conn, tcp, is_unix);
            addUsize(&server.metrics.active_connections, 1);
            startKeepalive(conn, &server.context);
            queueRead(conn, &server.context);
        } else {
            addU64(&server.metrics.errors.pool_full, 1);
            closeTcpImmediate(tcp);
        }
    } else |_| {
        addU64(&server.metrics.errors.accept, 1);
    }
}

fn onAcceptTcp(
    ud: ?*Server,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.AcceptError!xev.TCP,
) xev.CallbackAction {
    const server = ud.?;
    _ = loop;
    handleAccept(server, result, false);
    server.queueAcceptTcp();
    return .disarm;
}

fn onAcceptUnix(
    ud: ?*Server,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.AcceptError!xev.TCP,
) xev.CallbackAction {
    const server = ud.?;
    _ = loop;
    handleAccept(server, result, true);
    server.queueAcceptUnix();
    return .disarm;
}

fn queueRead(conn: *connection.Connection, ctx: *ServerContext) void {
    const read_chunk = default_read_buffer_bytes;
    const needs_reserve = !conn.read_needs_more or conn.read_buf.availableTail() < read_chunk;
    if (needs_reserve) {
        if (!conn.read_buf.reserve(read_chunk)) {
            addU64(&ctx.metrics.errors.buffer_overflow, 1);
            closeConnection(conn, ctx);
            return;
        }
    }
    var slice = conn.read_buf.tailSlice();
    if (slice.len == 0) {
        addU64(&ctx.metrics.errors.buffer_overflow, 1);
        closeConnection(conn, ctx);
        return;
    }
    if (slice.len > read_chunk) slice = slice[0..read_chunk];
    conn.read_token = conn.generation;
    const read_buf = xev.ReadBuffer{ .slice = slice };
    conn.tcp.read(ctx.loop, &conn.read_completion, read_buf, connection.Connection, conn, onRead);
}

fn onRead(
    ud: ?*connection.Connection,
    loop: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    _: xev.ReadBuffer,
    result: xev.ReadError!usize,
) xev.CallbackAction {
    const conn = ud.?;
    if (conn.in_pool) return .disarm;
    if (conn.read_token != conn.generation) return .disarm;
    conn.read_token = 0;
    const ctx = @as(*ServerContext, @ptrCast(@alignCast(conn.server.?)));
    _ = loop;
    defer maybeRelease(conn, ctx);

    const read_len = result catch {
        addU64(&ctx.metrics.errors.read, 1);
        closeConnection(conn, ctx);
        return .disarm;
    };

    if (read_len == 0) {
        closeConnection(conn, ctx);
        return .disarm;
    }

    conn.read_buf.commitWrite(read_len);
    addU64(&ctx.metrics.bytes_read, @as(u64, @intCast(read_len)));
    resetKeepalive(conn, ctx);

    processIncoming(conn, ctx);
    if (!conn.closing and conn.persist_state == .idle) {
        queueRead(conn, ctx);
    }
    return .disarm;
}

fn processIncoming(conn: *connection.Connection, ctx: *ServerContext) void {
    conn.defer_writes = true;
    defer {
        conn.defer_writes = false;
        queueWrite(conn, ctx);
        flushConnectionMetrics(conn, ctx);
    }
    while (true) {
        if (conn.protocol == .unknown) {
            const proto = detectProtocol(conn, ctx.options.protocol);
            switch (proto) {
                .needs_more => return,
                .unknown => {
                    addU64(&ctx.metrics.errors.protocol, 1);
                    closeConnection(conn, ctx);
                    return;
                },
                .http => conn.protocol = .http,
                .resp => conn.protocol = .resp,
            }
        }

        const data = conn.read_buf.readable();
        if (data.len == 0) return;

        switch (conn.protocol) {
            .http => {
                const res = conn.http_parser.parse(data, false);
                switch (res) {
                    .ok => |parsed| {
                        conn.read_needs_more = false;
                        conn.keepalive = parsed.keepalive;
                        conn.read_buf.consume(parsed.consumed);
                        recordRequest(conn);
                        handleHttpCommand(conn, ctx, parsed.command);
                        if (conn.persist_state != .idle) return;
                        if (conn.closing) return;
                    },
                    .needs_more => {
                        conn.read_needs_more = true;
                        return;
                    },
                    .err => {
                        conn.read_needs_more = false;
                        addU64(&ctx.metrics.errors.parse, 1);
                        const wrote = switch (res.err) {
                            http.Error.KeyTooLarge => writeHttpError(conn, ctx, 414, "URI Too Long"),
                            http.Error.ValueTooLarge => writeHttpError(conn, ctx, 413, "Payload Too Large"),
                            else => writeHttpBadRequest(conn, ctx),
                        };
                        if (wrote) recordResponse(conn);
                        conn.closing = true;
                        return;
                    },
                }
            },
            .resp => {
                const res = conn.resp_parser.parse(data, false);
                switch (res) {
                    .ok => |parsed| {
                        conn.read_needs_more = false;
                        conn.read_buf.consume(parsed.consumed);
                        recordRequest(conn);
                        const emit = parsed.command != .monitor and (!conn.monitoring or parsed.command == .ping);
                        if (emit) {
                            monitorEmit(ctx, conn, parsed.args[0..parsed.args_len]);
                        }
                        handleRespCommand(conn, ctx, parsed.command);
                        if (conn.persist_state != .idle) return;
                        if (conn.closing) return;
                        continue;
                    },
                    .needs_more => {
                        conn.read_needs_more = true;
                        return;
                    },
                    .err => {
                        conn.read_needs_more = false;
                        addU64(&ctx.metrics.errors.parse, 1);
                        const msg = if (res.err == resp.Error.ValueTooLarge) "ERR value too large" else "ERR protocol error";
                        if (writeRespErrorResponse(conn, ctx, msg)) {
                            recordResponse(conn);
                        }
                        conn.closing = true;
                        return;
                    },
                }
            },
            .unknown => return,
        }
    }
}

fn handleHttpCommand(conn: *connection.Connection, ctx: *ServerContext, cmd: http.Command) void {
    switch (cmd) {
        .save => |save_cmd| {
            _ = handlePersistCommand(conn, ctx, true, save_cmd.path, save_cmd.fast);
            return;
        },
        .load => |load_cmd| {
            _ = handlePersistCommand(conn, ctx, false, load_cmd.path, load_cmd.fast);
            return;
        },
        else => {},
    }

    var snapshot: ?stats.StatsSnapshot = null;
    switch (cmd) {
        .stats => {
            const metrics = ctx.metrics_snapshot(ctx.metrics_snapshot_ctx);
            snapshot = stats.build(ctx.cache, metrics, ctx.start_time_ms);
        },
        else => {},
    }
    const writer = &conn.output;
    const result = execute.executeHttp(
        ctx.cache,
        cmd,
        ctx.resource_controls,
        conn.keepalive,
        writer,
        snapshot,
    ) catch {
        handleOutputOverflow(conn, ctx);
        return;
    };
    if (result.cache_error) addU64(&ctx.metrics.errors.cache, 1);
    recordResponse(conn);
    if (result.close) conn.closing = true;
    queueWrite(conn, ctx);
}

fn handleRespCommand(conn: *connection.Connection, ctx: *ServerContext, cmd: resp.Command) void {
    if (conn.monitoring) {
        switch (cmd) {
            .ping => {
                const writer = &conn.output;
                if (!writeRespSimple(writer, "PONG")) {
                    handleOutputOverflow(conn, ctx);
                    closeConnection(conn, ctx);
                    return;
                }
                recordResponse(conn);
                queueWrite(conn, ctx);
            },
            else => {
                closeConnection(conn, ctx);
            },
        }
        return;
    }

    if (cmd == .monitor) {
        if (!monitorRegister(conn, ctx)) {
            const writer = &conn.output;
            if (!writeRespError(writer, "ERR monitor unavailable")) {
                handleOutputOverflow(conn, ctx);
                closeConnection(conn, ctx);
                return;
            }
            recordResponse(conn);
            queueWrite(conn, ctx);
            return;
        }
        const writer = &conn.output;
        if (!writeRespSimple(writer, "OK")) {
            monitorUnregister(conn, ctx);
            handleOutputOverflow(conn, ctx);
            closeConnection(conn, ctx);
            return;
        }
        recordResponse(conn);
        queueWrite(conn, ctx);
        return;
    }

    switch (cmd) {
        .save => |save_cmd| {
            _ = handlePersistCommand(conn, ctx, true, save_cmd.path, save_cmd.fast);
            return;
        },
        .load => |load_cmd| {
            _ = handlePersistCommand(conn, ctx, false, load_cmd.path, load_cmd.fast);
            return;
        },
        else => {},
    }

    var snapshot: ?stats.StatsSnapshot = null;
    switch (cmd) {
        .info, .stats => {
            const metrics = ctx.metrics_snapshot(ctx.metrics_snapshot_ctx);
            snapshot = stats.build(ctx.cache, metrics, ctx.start_time_ms);
        },
        else => {},
    }
    const writer = &conn.output;
    const result = execute.executeResp(
        ctx.cache,
        cmd,
        ctx.resource_controls,
        writer,
        snapshot,
    ) catch {
        handleOutputOverflow(conn, ctx);
        return;
    };
    if (result.cache_error) addU64(&ctx.metrics.errors.cache, 1);
    recordResponse(conn);
    queueWrite(conn, ctx);
}

fn handlePersistCommand(
    conn: *connection.Connection,
    ctx: *ServerContext,
    is_save: bool,
    path_override: ?[]const u8,
    fast: bool,
) bool {
    const allocator = ctx.options.allocator;
    const notify = allocator.create(PersistNotify) catch {
        if (!writePersistFailure(conn, ctx, "ERR persistence failed", 500, "Internal Server Error")) {
            handleOutputOverflow(conn, ctx);
        }
        return false;
    };
    notify.* = .{
        .allocator = allocator,
        .queue = ctx.persist_queue,
        .async = ctx.persist_async,
        .conn = conn,
        .generation = conn.generation,
    };

    conn.persist_state = .in_progress;
    conn.persist_response_ok = false;
    conn.persist_close_after = conn.protocol == .http and !conn.keepalive;

    const status = if (is_save)
        ctx.persistence.startSave(path_override, fast, notify, persistNotify)
    else
        ctx.persistence.startLoad(path_override, fast, notify, persistNotify);

    switch (status) {
        .ok => {
            cancelKeepalive(conn, ctx);
            return true;
        },
        .disabled => {
            conn.persist_state = .idle;
            conn.persist_close_after = false;
            allocator.destroy(notify);
            if (!writePersistFailure(conn, ctx, "ERR path not provided", 400, "Bad Request")) {
                handleOutputOverflow(conn, ctx);
            }
        },
        .busy_save => {
            conn.persist_state = .idle;
            conn.persist_close_after = false;
            allocator.destroy(notify);
            if (!writePersistFailure(conn, ctx, "ERR save already in progress", 409, "Conflict")) {
                handleOutputOverflow(conn, ctx);
            }
        },
        .busy_load => {
            conn.persist_state = .idle;
            conn.persist_close_after = false;
            allocator.destroy(notify);
            if (!writePersistFailure(conn, ctx, "ERR load already in progress", 409, "Conflict")) {
                handleOutputOverflow(conn, ctx);
            }
        },
        .failed => {
            conn.persist_state = .idle;
            conn.persist_close_after = false;
            allocator.destroy(notify);
            if (!writePersistFailure(conn, ctx, "ERR persistence failed", 500, "Internal Server Error")) {
                handleOutputOverflow(conn, ctx);
            }
        },
    }
    return false;
}

fn writePersistFailure(
    conn: *connection.Connection,
    ctx: *ServerContext,
    resp_msg: []const u8,
    http_code: u16,
    http_reason: []const u8,
) bool {
    const writer = &conn.output;
    const wrote = switch (conn.protocol) {
        .http => writeHttpResponse(writer, http_code, http_reason, conn.keepalive),
        .resp => writeRespError(writer, resp_msg),
        .unknown => false,
    };
    if (!wrote) return false;
    recordResponse(conn);
    if (conn.protocol == .http and !conn.keepalive) {
        conn.closing = true;
    }
    queueWrite(conn, ctx);
    return true;
}

fn handlePersistCompletion(ctx: *ServerContext, notify: *PersistNotify) void {
    const conn = notify.conn;
    if (conn.in_pool) return;
    if (conn.generation != notify.generation) return;
    if (conn.persist_state == .idle) return;
    if (conn.closing or conn.close_queued or conn.close_done) {
        conn.persist_state = .idle;
        conn.persist_close_after = false;
        return;
    }
    finishPersistResponse(conn, ctx, notify.ok);
}

fn finishPersistResponse(conn: *connection.Connection, ctx: *ServerContext, ok: bool) void {
    if (conn.write_in_progress) {
        conn.persist_state = .response_pending;
        conn.persist_response_ok = ok;
        return;
    }

    const writer = &conn.output;
    const wrote = switch (conn.protocol) {
        .http => if (ok)
            writeHttpResponseWithBody(writer, 200, "OK", "OK", conn.keepalive)
        else
            writeHttpResponse(writer, 500, "Internal Server Error", conn.keepalive),
        .resp => if (ok)
            writeRespSimple(writer, "OK")
        else
            writeRespError(writer, "ERR persistence failed"),
        .unknown => false,
    };

    if (!wrote) {
        handleOutputOverflow(conn, ctx);
        conn.persist_state = .idle;
        conn.persist_close_after = false;
        return;
    }

    conn.persist_state = .idle;
    conn.persist_response_ok = false;
    if (conn.persist_close_after) {
        conn.persist_close_after = false;
        conn.closing = true;
    } else {
        conn.persist_close_after = false;
    }

    recordResponse(conn);
    if (!conn.closing) {
        resetKeepalive(conn, ctx);
    }
    queueWrite(conn, ctx);

    if (!conn.closing) {
        if (conn.read_buf.readable().len > 0) {
            processIncoming(conn, ctx);
            if (!conn.closing and conn.persist_state == .idle) {
                queueRead(conn, ctx);
            }
        } else {
            queueRead(conn, ctx);
        }
    }
}

fn handleOutputOverflow(conn: *connection.Connection, ctx: *ServerContext) void {
    addU64(&ctx.metrics.errors.buffer_overflow, 1);
    conn.closing = true;
    if (conn.output.limit_exceeded and !conn.write_in_progress) {
        conn.output.dropQueued();
        closeConnection(conn, ctx);
    }
}

fn queueWrite(conn: *connection.Connection, ctx: *ServerContext) void {
    if (conn.defer_writes) return;
    if (conn.write_in_progress) return;
    if (conn.output.limit_exceeded) {
        conn.output.dropQueued();
        closeConnection(conn, ctx);
        return;
    }
    const write_slice = conn.output.nextWriteSlice() orelse {
        if (conn.closing) closeConnection(conn, ctx);
        return;
    };
    conn.write_in_progress = true;
    conn.write_token = conn.generation;
    conn.write_source = write_slice.source;
    const write_buf = xev.WriteBuffer{ .slice = write_slice.slice };
    conn.tcp.write(ctx.loop, &conn.write_completion, write_buf, connection.Connection, conn, onWrite);
}

fn onWrite(
    ud: ?*connection.Connection,
    loop: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    _: xev.WriteBuffer,
    result: xev.WriteError!usize,
) xev.CallbackAction {
    const conn = ud.?;
    if (conn.in_pool) return .disarm;
    if (conn.write_token != conn.generation) return .disarm;
    conn.write_token = 0;
    const ctx = @as(*ServerContext, @ptrCast(@alignCast(conn.server.?)));
    _ = loop;
    defer maybeRelease(conn, ctx);

    const written = result catch {
        addU64(&ctx.metrics.errors.write, 1);
        closeConnection(conn, ctx);
        return .disarm;
    };

    conn.write_in_progress = false;
    if (conn.write_source) |source| {
        conn.output.consumeWrite(source, written);
    }
    conn.write_source = null;
    addU64(&ctx.metrics.bytes_written, @as(u64, @intCast(written)));
    if (conn.output.limit_exceeded) {
        conn.output.dropQueued();
        closeConnection(conn, ctx);
        return .disarm;
    }
    if (conn.persist_state == .idle) {
        resetKeepalive(conn, ctx);
    }
    if (conn.persist_state == .response_pending) {
        finishPersistResponse(conn, ctx, conn.persist_response_ok);
    } else {
        queueWrite(conn, ctx);
    }
    return .disarm;
}

fn maybeRelease(conn: *connection.Connection, ctx: *ServerContext) void {
    if (!conn.close_done) return;
    if (conn.in_pool) return;
    if (conn.read_token != 0) return;
    if (conn.write_token != 0) return;
    if (conn.timer_token != 0) return;
    if (conn.timer_cancel_token != 0) return;
    if (conn.close_token != 0) return;
    ctx.pool.release(conn);
}

fn closeConnection(conn: *connection.Connection, ctx: *ServerContext) void {
    if (conn.in_pool or conn.close_done) return;
    if (conn.close_queued) return;
    monitorUnregister(conn, ctx);
    if (conn.write_in_progress) {
        conn.closing = true;
        cancelKeepalive(conn, ctx);
        return;
    }
    conn.closing = true;
    conn.close_queued = true;
    conn.close_token = conn.generation;
    cancelKeepalive(conn, ctx);
    if (builtin.os.tag != .windows) {
        std.posix.shutdown(conn.tcp.fd(), .both) catch {};
    }
    conn.tcp.close(ctx.loop, &conn.close_completion, connection.Connection, conn, onCloseConnection);
}

fn onCloseConnection(
    ud: ?*connection.Connection,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.TCP,
    _: xev.CloseError!void,
) xev.CallbackAction {
    const conn = ud.?;
    if (conn.in_pool) return .disarm;
    if (conn.close_token != conn.generation) return .disarm;
    const ctx = @as(*ServerContext, @ptrCast(@alignCast(conn.server.?)));
    conn.close_token = 0;
    conn.close_done = true;
    subUsize(ctx.active_connections, 1);
    defer maybeRelease(conn, ctx);
    return .disarm;
}

const DetectResult = enum {
    http,
    resp,
    needs_more,
    unknown,
};

fn detectProtocol(conn: *connection.Connection, mode: Protocol) DetectResult {
    if (mode == .http) return .http;
    if (mode == .resp) return .resp;

    const data = conn.read_buf.readable();
    if (data.len == 0) return .needs_more;

    if (data[0] == '*' or data[0] == '$') return .resp;
    if (data.len < 4) return .needs_more;
    if (std.mem.startsWith(u8, data, "GET ") or
        std.mem.startsWith(u8, data, "PUT ") or
        std.mem.startsWith(u8, data, "POST ") or
        std.mem.startsWith(u8, data, "DELETE "))
    {
        return .http;
    }
    return .unknown;
}

fn writeHttpBadRequest(conn: *connection.Connection, ctx: *ServerContext) bool {
    return writeHttpError(conn, ctx, 400, "Bad Request");
}

fn writeHttpError(conn: *connection.Connection, ctx: *ServerContext, code: u16, reason: []const u8) bool {
    const writer = &conn.output;
    if (!writeHttpResponse(writer, code, reason, false)) {
        handleOutputOverflow(conn, ctx);
        closeConnection(conn, ctx);
        return false;
    }
    queueWrite(conn, ctx);
    return true;
}

fn writeRespErrorResponse(conn: *connection.Connection, ctx: *ServerContext, msg: []const u8) bool {
    const writer = &conn.output;
    if (!writeRespError(writer, msg)) {
        handleOutputOverflow(conn, ctx);
        closeConnection(conn, ctx);
        return false;
    }
    queueWrite(conn, ctx);
    return true;
}

fn startKeepalive(conn: *connection.Connection, ctx: *ServerContext) void {
    if (ctx.options.keepalive_timeout_ns == 0) return;
    const ms = @as(u64, @intCast(ctx.options.keepalive_timeout_ns / std.time.ns_per_ms));
    conn.timer_token = conn.generation;
    conn.timer.run(ctx.loop, &conn.timer_completion, ms, connection.Connection, conn, onKeepalive);
}

fn resetKeepalive(conn: *connection.Connection, ctx: *ServerContext) void {
    if (ctx.options.keepalive_timeout_ns == 0) return;
    const ms = @as(u64, @intCast(ctx.options.keepalive_timeout_ns / std.time.ns_per_ms));
    conn.timer_token = conn.generation;
    conn.timer.reset(ctx.loop, &conn.timer_completion, &conn.timer_cancel, ms, connection.Connection, conn, onKeepalive);
    if (conn.timer_cancel.state() == .active) {
        conn.timer_cancel_token = conn.generation;
    } else {
        conn.timer_cancel_token = 0;
    }
}

fn cancelKeepalive(conn: *connection.Connection, ctx: *ServerContext) void {
    if (ctx.options.keepalive_timeout_ns == 0) return;
    if (conn.timer_token == 0) return;
    if (conn.timer_cancel_token != 0) return;
    conn.timer_cancel_token = conn.generation;
    conn.timer.cancel(ctx.loop, &conn.timer_completion, &conn.timer_cancel, connection.Connection, conn, onKeepaliveCancel);
}

fn onKeepalive(
    ud: ?*connection.Connection,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Timer.RunError!void,
) xev.CallbackAction {
    const conn = ud.?;
    if (conn.in_pool) return .disarm;
    if (conn.timer_token != conn.generation) return .disarm;
    conn.timer_token = 0;
    const ctx = @as(*ServerContext, @ptrCast(@alignCast(conn.server.?)));
    defer maybeRelease(conn, ctx);
    _ = result catch |err| {
        if (err == error.Canceled) return .disarm;
        addU64(&ctx.metrics.errors.timeout, 1);
        closeConnection(conn, ctx);
        return .disarm;
    };
    addU64(&ctx.metrics.errors.timeout, 1);
    closeConnection(conn, ctx);
    return .disarm;
}

fn onKeepaliveCancel(
    ud: ?*connection.Connection,
    _: *xev.Loop,
    _: *xev.Completion,
    _: xev.Timer.CancelError!void,
) xev.CallbackAction {
    const conn = ud orelse return .disarm;
    if (conn.in_pool) return .disarm;
    if (conn.timer_cancel_token != conn.generation) return .disarm;
    conn.timer_cancel_token = 0;
    const ctx = @as(*ServerContext, @ptrCast(@alignCast(conn.server.?)));
    defer maybeRelease(conn, ctx);
    return .disarm;
}

fn closeTcpImmediate(tcp: xev.TCP) void {
    if (builtin.os.tag == .windows) return;
    std.posix.close(tcp.fd());
}

fn writeHttpResponseWithBody(
    writer: anytype,
    code: u16,
    reason: []const u8,
    body: []const u8,
    keepalive: bool,
) bool {
    var header_buf: [256]u8 = undefined;
    const conn = if (keepalive) "keep-alive" else "close";
    const header = std.fmt.bufPrint(
        &header_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: {s}\r\n\r\n",
        .{ code, reason, body.len, conn },
    ) catch return false;
    if (!writeAll(writer, header)) return false;
    return writeAll(writer, body);
}

fn writeHttpResponse(writer: anytype, code: u16, reason: []const u8, keepalive: bool) bool {
    var header_buf: [256]u8 = undefined;
    const conn = if (keepalive) "keep-alive" else "close";
    const header = std.fmt.bufPrint(&header_buf, "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\nConnection: {s}\r\n\r\n", .{
        code,
        reason,
        conn,
    }) catch return false;
    return writeAll(writer, header);
}

fn writeRespSimple(writer: anytype, msg: []const u8) bool {
    if (!writeAll(writer, "+")) return false;
    if (!writeAll(writer, msg)) return false;
    return writeAll(writer, "\r\n");
}

fn writeRespError(writer: anytype, msg: []const u8) bool {
    if (!writeAll(writer, "-")) return false;
    if (!writeAll(writer, msg)) return false;
    return writeAll(writer, "\r\n");
}

fn writeAll(writer: anytype, data: []const u8) bool {
    if (data.len == 0) return true;
    writer.writeAll(data) catch return false;
    return true;
}

fn getBoundAddress(listener: xev.TCP) !std.net.Address {
    var addr: std.posix.sockaddr align(4) = undefined;
    var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
    try std.posix.getsockname(listener.fd(), &addr, &len);
    return std.net.Address.initPosix(&addr);
}

const AcceptToken = struct {
    fd: std.posix.fd_t,
    is_unix: bool,
};

const WorkerQueue = struct {
    tokens: []AcceptToken,
    head: usize = 0,
    tail: usize = 0,
    len: usize = 0,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !WorkerQueue {
        const cap = if (capacity == 0) 1 else capacity;
        const tokens = try allocator.alloc(AcceptToken, cap);
        return .{ .tokens = tokens };
    }

    pub fn deinit(self: *WorkerQueue, allocator: std.mem.Allocator) void {
        allocator.free(self.tokens);
    }

    pub fn push(self: *WorkerQueue, token: AcceptToken) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.len == self.tokens.len) return false;
        self.tokens[self.tail] = token;
        self.tail = (self.tail + 1) % self.tokens.len;
        self.len += 1;
        return true;
    }

    pub fn pop(self: *WorkerQueue) ?AcceptToken {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.len == 0) return null;
        const token = self.tokens[self.head];
        self.head = (self.head + 1) % self.tokens.len;
        self.len -= 1;
        if (self.len == 0) {
            self.head = 0;
            self.tail = 0;
        }
        return token;
    }
};

const Worker = struct {
    allocator: std.mem.Allocator,
    id: usize,
    loop: xev.Loop,
    pool: connection.ConnectionPool,
    queue: WorkerQueue,
    persist_queue: PersistQueue,
    monitor_registry: MonitorRegistry,
    monitor_queue: MonitorQueue,
    monitor_overflow: AtomicBool,
    async: xev.Async,
    async_completion: xev.Completion = .{},
    thread: ?std.Thread = null,
    options: ServerOptions,
    limits: Limits,
    context: ServerContext,
    connections: AtomicU64,
    metrics: AtomicMetrics,
    metrics_batch: MetricsBatch,
    metrics_timer: xev.Timer,
    metrics_timer_completion: xev.Completion = .{},

    fn initInPlace(
        self: *Worker,
        allocator: std.mem.Allocator,
        id: usize,
        cache_ptr: *cache.api.Cache,
        active_connections: *AtomicUsize,
        options: ServerOptions,
        pool_size: usize,
        queue_capacity: usize,
        limits: Limits,
        persistence_ptr: *persistence.Manager,
        metrics_snapshot: MetricsSnapshotFn,
        metrics_snapshot_ctx: *const anyopaque,
        start_time_ms: u64,
    ) !void {
        var loop = try xev.Loop.init(.{
            .entries = options.loop_entries,
            .thread_pool = options.thread_pool,
        });
        errdefer loop.deinit();

        var pool = try connection.ConnectionPool.init(
            allocator,
            pool_size,
            default_read_buffer_bytes,
            output_buffer.default_inline_bytes,
            output_buffer.default_chunk_bytes,
            limits,
            options.output_limits,
        );
        errdefer pool.deinit();

        var queue = try WorkerQueue.init(allocator, queue_capacity);
        errdefer queue.deinit(allocator);

        var monitor_queue = try MonitorQueue.init(allocator, queue_capacity);
        errdefer monitor_queue.deinit(allocator);

        const async = try xev.Async.init();
        errdefer async.deinit();

        const metrics_timer = try xev.Timer.init();

        self.* = Worker{
            .allocator = allocator,
            .id = id,
            .loop = loop,
            .pool = pool,
            .queue = queue,
            .persist_queue = PersistQueue.init(),
            .monitor_registry = .{},
            .monitor_queue = monitor_queue,
            .monitor_overflow = AtomicBool.init(false),
            .async = async,
            .options = options,
            .limits = limits,
            .context = undefined,
            .connections = AtomicU64.init(0),
            .metrics = AtomicMetrics.init(),
            .metrics_batch = .{},
            .metrics_timer = metrics_timer,
        };
        self.context = .{
            .loop = &self.loop,
            .pool = &self.pool,
            .options = &self.options,
            .limits = limits,
            .metrics = &self.metrics,
            .metrics_snapshot = metrics_snapshot,
            .metrics_snapshot_ctx = metrics_snapshot_ctx,
            .start_time_ms = start_time_ms,
            .active_connections = active_connections,
            .cache = cache_ptr,
            .persistence = persistence_ptr,
            .persist_queue = &self.persist_queue,
            .persist_async = &self.async,
            .resource_controls = null,
            .metrics_batch = &self.metrics_batch,
            .metrics_timer = &self.metrics_timer,
            .metrics_timer_completion = &self.metrics_timer_completion,
            .monitor_registry = &self.monitor_registry,
            .monitor_queue = &self.monitor_queue,
            .monitor_overflow = &self.monitor_overflow,
            .monitor_hub = null,
        };
    }

    fn start(self: *Worker) !void {
        self.thread = try std.Thread.spawn(.{}, workerMain, .{self});
    }

    fn stop(self: *Worker) void {
        self.loop.stop();
        self.async.notify() catch {};
    }

    fn join(self: *Worker) void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    fn deinit(self: *Worker) void {
        self.pool.deinit();
        self.queue.deinit(self.allocator);
        self.persist_queue.deinit();
        self.monitor_queue.deinit(self.allocator);
        self.monitor_registry.deinit(self.allocator);
        self.async.deinit();
        self.loop.deinit();
    }
};

const ThreadedMetricsContext = struct {
    base: *AtomicMetrics,
    workers: []Worker,
};

fn snapshotThreaded(ctx_ptr: *const anyopaque) Metrics {
    const ctx = @as(*const ThreadedMetricsContext, @ptrCast(@alignCast(ctx_ptr)));
    var metrics = ctx.base.snapshot();
    for (ctx.workers) |*worker| {
        addMetrics(&metrics, worker.metrics.snapshot());
    }
    return metrics;
}

fn workerMain(worker: *Worker) void {
    startMetricsFlush(&worker.context);
    worker.async.wait(&worker.loop, &worker.async_completion, Worker, worker, onWorkerAsync);
    worker.loop.run(.until_done) catch {};
    flushMetricsBatch(&worker.context);
}

fn onWorkerAsync(
    ud: ?*Worker,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Async.WaitError!void,
) xev.CallbackAction {
    const worker = ud.?;
    _ = result catch |err| {
        if (err == error.Canceled) return .disarm;
        return .disarm;
    };

    drainPersistQueue(&worker.context);
    drainMonitorQueue(&worker.context);

    while (worker.queue.pop()) |token| {
        const tcp = xev.TCP.initFd(token.fd);
        if (worker.pool.acquire(tcp)) |conn| {
            conn.server = &worker.context;
            initClientAddr(conn, tcp, token.is_unix);
            addU64(&worker.connections, 1);
            startKeepalive(conn, &worker.context);
            queueRead(conn, &worker.context);
        } else {
            addU64(&worker.context.metrics.errors.pool_full, 1);
            subUsize(worker.context.active_connections, 1);
            closeTcpImmediate(tcp);
        }
    }

    return .rearm;
}

pub const ThreadedServer = struct {
    allocator: std.mem.Allocator,
    cache: *cache.api.Cache,
    options: ServerOptions,
    threads: usize,
    metrics: *AtomicMetrics,
    start_time_ms: u64,
    persistence: *persistence.Manager,
    loop: xev.Loop,
    listener: xev.TCP,
    accept_completion: xev.Completion = .{},
    unix_listener: ?xev.TCP = null,
    unix_accept_completion: xev.Completion = .{},
    shutdown_async: xev.Async,
    shutdown_completion: xev.Completion = .{},
    workers: []Worker,
    metrics_context: *ThreadedMetricsContext,
    next_worker: AtomicUsize,
    bound_address: std.net.Address,
    resource_controls: resource_controls.ResourceControls,
    monitor_hub: *MonitorHub,

    pub fn init(opts: ServerOptions, threads: usize) !ThreadedServer {
        try xev.detect();
        if (opts.unix_path != null and !std.net.has_unix_sockets) return error.UnixSocketUnsupported;
        const limits = Limits{
            .max_key_length = default_request_bytes,
            .max_value_length = default_request_bytes,
            .max_args = 32,
        };

        const resolved_threads = if (threads == 0)
            std.Thread.getCpuCount() catch 1
        else
            threads;
        const worker_count = if (resolved_threads == 0) 1 else resolved_threads;

        const metrics = try opts.allocator.create(AtomicMetrics);
        metrics.* = AtomicMetrics.init();
        errdefer opts.allocator.destroy(metrics);
        const start_time_ms = @as(u64, @intCast(std.time.milliTimestamp()));
        const persistence_mgr = try opts.allocator.create(persistence.Manager);
        persistence_mgr.* = persistence.Manager.init(opts.allocator, opts.cache, opts.persist_path);
        errdefer opts.allocator.destroy(persistence_mgr);

        var loop = try xev.Loop.init(.{
            .entries = opts.loop_entries,
            .thread_pool = opts.thread_pool,
        });
        errdefer loop.deinit();

        var shutdown_async = try xev.Async.init();
        errdefer shutdown_async.deinit();

        var listener = try xev.TCP.init(opts.address);
        errdefer closeTcpImmediate(listener);
        if (!configureListener(listener, false)) return error.SocketOptionFailed;
        try listener.bind(opts.address);
        try listener.listen(opts.backlog);

        var unix_listener: ?xev.TCP = null;
        if (opts.unix_path) |path| {
            const unix_addr = try std.net.Address.initUnix(path);
            std.posix.unlink(path) catch {};
            var unix_tcp = try xev.TCP.init(unix_addr);
            errdefer closeTcpImmediate(unix_tcp);
            if (!configureListener(unix_tcp, true)) return error.SocketOptionFailed;
            try unix_tcp.bind(unix_addr);
            try unix_tcp.listen(opts.backlog);
            unix_listener = unix_tcp;
        }

        const bound_address = try getBoundAddress(listener);

        var workers = try opts.allocator.alloc(Worker, worker_count);
        var inited: usize = 0;
        errdefer {
            var idx: usize = 0;
            while (idx < inited) : (idx += 1) {
                workers[idx].stop();
            }
            idx = 0;
            while (idx < inited) : (idx += 1) {
                workers[idx].join();
                workers[idx].deinit();
            }
            opts.allocator.free(workers);
        }

        const metrics_context = try opts.allocator.create(ThreadedMetricsContext);
        metrics_context.* = .{
            .base = metrics,
            .workers = workers,
        };
        errdefer opts.allocator.destroy(metrics_context);

        var i: usize = 0;
        const base = opts.max_connections / worker_count;
        const extra = opts.max_connections % worker_count;
        while (i < worker_count) : (i += 1) {
            const bump: usize = if (i < extra) 1 else 0;
            const pool_size = base + bump;
            const queue_cap = if (pool_size < 64) 64 else pool_size;
            var worker_opts = opts;
            worker_opts.max_connections = pool_size;
            try workers[i].initInPlace(
                opts.allocator,
                i,
                opts.cache,
                &metrics.active_connections,
                worker_opts,
                pool_size,
                queue_cap,
                limits,
                persistence_mgr,
                snapshotThreaded,
                metrics_context,
                start_time_ms,
            );
            inited += 1;
        }

        const monitor_hub = try opts.allocator.create(MonitorHub);
        errdefer opts.allocator.destroy(monitor_hub);
        var monitor_targets = try opts.allocator.alloc(MonitorTarget, worker_count);
        errdefer opts.allocator.free(monitor_targets);
        var ti: usize = 0;
        while (ti < worker_count) : (ti += 1) {
            monitor_targets[ti] = .{
                .queue = &workers[ti].monitor_queue,
                .overflow = &workers[ti].monitor_overflow,
                .async = &workers[ti].async,
            };
        }
        monitor_hub.* = .{
            .allocator = opts.allocator,
            .total = AtomicUsize.init(0),
            .targets = monitor_targets,
        };

        i = 0;
        while (i < worker_count) : (i += 1) {
            workers[i].context.monitor_hub = monitor_hub;
        }

        i = 0;
        while (i < worker_count) : (i += 1) {
            try workers[i].start();
        }

        return .{
            .allocator = opts.allocator,
            .cache = opts.cache,
            .options = opts,
            .threads = worker_count,
            .metrics = metrics,
            .start_time_ms = start_time_ms,
            .persistence = persistence_mgr,
            .loop = loop,
            .listener = listener,
            .unix_listener = unix_listener,
            .workers = workers,
            .metrics_context = metrics_context,
            .next_worker = AtomicUsize.init(0),
            .bound_address = bound_address,
            .shutdown_async = shutdown_async,
            .resource_controls = resource_controls.ResourceControls.init(opts.maxmemory_bytes, opts.evict, opts.autosweep),
            .monitor_hub = monitor_hub,
        };
    }

    pub fn deinit(self: *ThreadedServer) void {
        self.stop();
        self.persistence.waitForIdle();
        self.persistence.drainPendingPath();
        var i: usize = 0;
        while (i < self.workers.len) : (i += 1) {
            self.workers[i].join();
            self.workers[i].deinit();
        }
        self.allocator.free(self.workers);
        self.allocator.destroy(self.metrics_context);
        self.allocator.free(self.monitor_hub.targets);
        self.allocator.destroy(self.monitor_hub);
        self.resource_controls.stop();
        closeTcpImmediate(self.listener);
        if (self.unix_listener) |listener| {
            closeTcpImmediate(listener);
        }
        self.shutdown_async.deinit();
        self.loop.deinit();
        self.allocator.destroy(self.persistence);
        self.allocator.destroy(self.metrics);
    }

    pub fn run(self: *ThreadedServer) !void {
        for (self.workers) |*worker| {
            worker.context.resource_controls = &self.resource_controls;
        }
        try self.resource_controls.start(self.cache);
        self.shutdown_async.wait(&self.loop, &self.shutdown_completion, ThreadedServer, self, onThreadedShutdownAsync);
        self.queueAccept();
        try self.loop.run(.until_done);
    }

    pub fn stop(self: *ThreadedServer) void {
        self.resource_controls.stop();
        self.shutdown_async.notify() catch {};
        for (self.workers) |*worker| {
            worker.stop();
        }
    }

    pub fn address(self: *const ThreadedServer) std.net.Address {
        return self.bound_address;
    }

    pub fn metricsSnapshot(self: *const ThreadedServer) Metrics {
        var metrics = self.metrics.snapshot();
        for (self.workers) |*worker| {
            addMetrics(&metrics, worker.metrics.snapshot());
        }
        return metrics;
    }

    fn queueAccept(self: *ThreadedServer) void {
        self.queueAcceptTcp();
        self.queueAcceptUnix();
    }

    fn queueAcceptTcp(self: *ThreadedServer) void {
        self.listener.accept(&self.loop, &self.accept_completion, ThreadedServer, self, onThreadedAcceptTcp);
    }

    fn queueAcceptUnix(self: *ThreadedServer) void {
        if (self.unix_listener) |listener| {
            listener.accept(&self.loop, &self.unix_accept_completion, ThreadedServer, self, onThreadedAcceptUnix);
        }
    }

    fn dispatch(self: *ThreadedServer, token: AcceptToken) bool {
        if (self.workers.len == 0) return false;
        const idx = self.next_worker.fetchAdd(1, .monotonic) % self.workers.len;
        const worker = &self.workers[idx];
        if (!worker.queue.push(token)) return false;
        worker.async.notify() catch {};
        return true;
    }
};

fn onThreadedShutdownAsync(
    _: ?*ThreadedServer,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.Async.WaitError!void,
) xev.CallbackAction {
    _ = result catch |err| {
        if (err == error.Canceled) return .disarm;
        return .disarm;
    };
    loop.stop();
    return .disarm;
}

fn handleThreadedAccept(server: *ThreadedServer, result: xev.AcceptError!xev.TCP, is_unix: bool) void {
    if (result) |tcp| {
        addU64(&server.metrics.total_connections, 1);
        if (!configureSocket(tcp, is_unix)) {
            addU64(&server.metrics.errors.accept, 1);
            closeTcpImmediate(tcp);
            return;
        }
        const active = server.metrics.active_connections.fetchAdd(1, .monotonic) + 1;
        if (active > server.options.max_connections) {
            subUsize(&server.metrics.active_connections, 1);
            addU64(&server.metrics.errors.pool_full, 1);
            closeTcpImmediate(tcp);
        } else if (!server.dispatch(.{ .fd = tcp.fd(), .is_unix = is_unix })) {
            subUsize(&server.metrics.active_connections, 1);
            addU64(&server.metrics.errors.pool_full, 1);
            closeTcpImmediate(tcp);
        }
    } else |_| {
        addU64(&server.metrics.errors.accept, 1);
    }
}

fn onThreadedAcceptTcp(
    ud: ?*ThreadedServer,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.AcceptError!xev.TCP,
) xev.CallbackAction {
    const server = ud.?;
    _ = loop;
    handleThreadedAccept(server, result, false);
    server.queueAcceptTcp();
    return .disarm;
}

fn onThreadedAcceptUnix(
    ud: ?*ThreadedServer,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: xev.AcceptError!xev.TCP,
) xev.CallbackAction {
    const server = ud.?;
    _ = loop;
    handleThreadedAccept(server, result, true);
    server.queueAcceptUnix();
    return .disarm;
}

const TestServer = struct {
    server: *Server,
    thread: std.Thread,

    fn start(opts: ServerOptions) !TestServer {
        const server_ptr = try opts.allocator.create(Server);
        errdefer opts.allocator.destroy(server_ptr);
        try server_ptr.initInPlace(opts);
        errdefer server_ptr.deinit();
        const thread = try std.Thread.spawn(.{}, Server.run, .{server_ptr});
        std.Thread.sleep(10 * std.time.ns_per_ms);
        return .{ .server = server_ptr, .thread = thread };
    }

    fn stop(self: *TestServer) void {
        self.shutdown();
        self.deinit();
    }

    fn shutdown(self: *TestServer) void {
        self.server.stop();
        self.thread.join();
    }

    fn deinit(self: *TestServer) void {
        self.server.deinit();
        self.server.allocator.destroy(self.server);
    }
};

const TestThreadedServer = struct {
    server: *ThreadedServer,
    thread: std.Thread,

    fn start(opts: ServerOptions, threads: usize) !TestThreadedServer {
        const server_ptr = try opts.allocator.create(ThreadedServer);
        errdefer opts.allocator.destroy(server_ptr);
        server_ptr.* = try ThreadedServer.init(opts, threads);
        errdefer server_ptr.deinit();
        const thread = try std.Thread.spawn(.{}, ThreadedServer.run, .{server_ptr});
        std.Thread.sleep(10 * std.time.ns_per_ms);
        return .{ .server = server_ptr, .thread = thread };
    }

    fn stop(self: *TestThreadedServer) void {
        self.shutdown();
        self.deinit();
    }

    fn shutdown(self: *TestThreadedServer) void {
        self.server.stop();
        self.thread.join();
    }

    fn deinit(self: *TestThreadedServer) void {
        self.server.deinit();
        self.server.allocator.destroy(self.server);
    }
};

fn connectRetry(addr: std.net.Address) !std.net.Stream {
    var attempt: usize = 0;
    while (attempt < 10) : (attempt += 1) {
        if (std.net.tcpConnectToAddress(addr)) |stream| {
            return stream;
        } else |_| {
            std.Thread.sleep(5 * std.time.ns_per_ms);
        }
    }
    return error.ConnectionRefused;
}

fn connectUnixRetry(path: []const u8) !std.net.Stream {
    var attempt: usize = 0;
    while (attempt < 10) : (attempt += 1) {
        if (std.net.connectUnixSocket(path)) |stream| {
            return stream;
        } else |_| {
            std.Thread.sleep(5 * std.time.ns_per_ms);
        }
    }
    return error.ConnectionRefused;
}

fn readHttpResponse(stream: *std.net.Stream, buf: []u8) ![]const u8 {
    var used: usize = 0;
    while (used < buf.len) {
        const n = try stream.read(buf[used..]);
        if (n == 0) break;
        used += n;
        if (std.mem.indexOf(u8, buf[0..used], "\r\n\r\n")) |idx| {
            const header_end = idx + 4;
            const length = parseContentLength(buf[0..header_end]);
            if (used >= header_end + length) {
                return buf[0 .. header_end + length];
            }
        }
    }
    return error.UnexpectedEof;
}

fn parseContentLength(header: []const u8) usize {
    const needle = "Content-Length:";
    if (std.mem.indexOf(u8, header, needle)) |idx| {
        var i = idx + needle.len;
        while (i < header.len and (header[i] == ' ' or header[i] == '\t')) : (i += 1) {}
        const end = std.mem.indexOfScalarPos(u8, header, i, '\r') orelse header.len;
        return std.fmt.parseInt(usize, header[i..end], 10) catch 0;
    }
    return 0;
}

fn waitForMetricsSnapshot(server: anytype, min_requests: u64, min_responses: u64) Metrics {
    var attempt: usize = 0;
    while (attempt < 50) : (attempt += 1) {
        const metrics = server.metricsSnapshot();
        if (metrics.total_requests >= min_requests and metrics.total_responses >= min_responses) {
            return metrics;
        }
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    return server.metricsSnapshot();
}

test "server accepts HTTP connections" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .http,
    });
    defer harness.stop();

    const bound = harness.server.address();
    var stream = try connectRetry(bound);
    defer stream.close();

    try stream.writeAll("GET /k HTTP/1.1\r\nConnection: close\r\n\r\n");
    var buf: [256]u8 = undefined;
    const res = try readHttpResponse(&stream, &buf);
    try std.testing.expect(std.mem.indexOf(u8, res, "404") != null);
}

test "unix socket accepts RESP connections" {
    if (!std.net.has_unix_sockets) return;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const socket_path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "crucible.sock",
    });
    defer allocator.free(socket_path);
    std.posix.unlink(socket_path) catch {};

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .resp,
        .unix_path = socket_path,
    });
    defer harness.stop();
    defer std.posix.unlink(socket_path) catch {};

    var stream = try connectUnixRetry(socket_path);
    defer stream.close();

    try stream.writeAll("*1\r\n$4\r\nPING\r\n");
    var buf: [64]u8 = undefined;
    var used: usize = 0;
    var attempt: usize = 0;
    while (attempt < 5 and used < buf.len) : (attempt += 1) {
        const n = try stream.read(buf[used..]);
        if (n == 0) break;
        used += n;
        if (std.mem.indexOf(u8, buf[0..used], "+PONG\r\n") != null) break;
    }
    try std.testing.expect(std.mem.indexOf(u8, buf[0..used], "+PONG\r\n") != null);
}

test "http end-to-end commands with keepalive" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .http,
    });
    defer harness.stop();

    var stream = try connectRetry(harness.server.address());
    defer stream.close();

    try stream.writeAll("POST /k HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\nv");
    var buf: [512]u8 = undefined;
    var res = try readHttpResponse(&stream, &buf);
    try std.testing.expect(std.mem.indexOf(u8, res, "201") != null);

    try stream.writeAll("GET /k HTTP/1.1\r\nConnection: keep-alive\r\n\r\n");
    res = try readHttpResponse(&stream, &buf);
    try std.testing.expect(std.mem.indexOf(u8, res, "200") != null);
    try std.testing.expect(std.mem.indexOf(u8, res, "\r\n\r\nv") != null);

    try stream.writeAll("PUT /k HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nvv");
    res = try readHttpResponse(&stream, &buf);
    try std.testing.expect(std.mem.indexOf(u8, res, "200") != null);

    try stream.writeAll("DELETE /k HTTP/1.1\r\nConnection: close\r\n\r\n");
    res = try readHttpResponse(&stream, &buf);
    try std.testing.expect(std.mem.indexOf(u8, res, "200") != null);
}

test "http ops endpoints return health and stats" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .http,
    });
    defer harness.stop();

    var stream = try connectRetry(harness.server.address());
    defer stream.close();

    try stream.writeAll("GET /@health HTTP/1.1\r\nConnection: keep-alive\r\n\r\n");
    var buf: [512]u8 = undefined;
    var res = try readHttpResponse(&stream, &buf);
    try std.testing.expect(std.mem.indexOf(u8, res, "200") != null);
    try std.testing.expect(std.mem.indexOf(u8, res, "\r\n\r\nOK") != null);

    try stream.writeAll("GET /@stats HTTP/1.1\r\nConnection: close\r\n\r\n");
    res = try readHttpResponse(&stream, &buf);
    try std.testing.expect(std.mem.indexOf(u8, res, "200") != null);
    try std.testing.expect(std.mem.indexOf(u8, res, "\"server\"") != null);
}

test "http malformed request returns 400 and closes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .http,
    });
    defer harness.stop();

    var stream = try connectRetry(harness.server.address());
    defer stream.close();

    try stream.writeAll("TRACE /k HTTP/1.1\r\n\r\n");
    var buf: [256]u8 = undefined;
    const res = try readHttpResponse(&stream, &buf);
    try std.testing.expect(std.mem.indexOf(u8, res, "400") != null);
    const n = try stream.read(&buf);
    try std.testing.expect(n == 0);
}

fn churnWorker(addr: std.net.Address, iterations: usize, sleep_ns: u64) void {
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const stream = std.net.tcpConnectToAddress(addr) catch continue;
        if (i % 3 == 0) {
            std.Thread.sleep(sleep_ns);
        } else if (i % 3 == 1) {
            stream.writeAll("GET /k HTTP/1.1\r\n") catch {};
        } else {
            stream.writeAll("GET /k HTTP/1.1\r\nConnection: close\r\n\r\n") catch {};
        }
        stream.close();
    }
}

test "threaded server connection churn" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestThreadedServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .auto,
        .keepalive_timeout_ns = 5 * std.time.ns_per_ms,
    }, 2);
    defer harness.stop();

    const worker_count = 4;
    const iterations = 300;
    const sleep_ns = 10 * std.time.ns_per_ms;

    var threads: [worker_count]std.Thread = undefined;
    var i: usize = 0;
    while (i < worker_count) : (i += 1) {
        threads[i] = try std.Thread.spawn(.{}, churnWorker, .{ harness.server.address(), iterations, sleep_ns });
    }
    for (threads) |thread| {
        thread.join();
    }
    std.Thread.sleep(20 * std.time.ns_per_ms);
}

test "resp end-to-end and pipeline" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .auto,
    });
    defer harness.stop();

    var stream = try connectRetry(harness.server.address());
    defer stream.close();

    const value_len: usize = 1024;
    const value = try allocator.alloc(u8, value_len);
    defer allocator.free(value);
    @memset(value, 'a');

    var header_buf: [128]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &header_buf,
        "*3\r\n$3\r\nSET\r\n$1\r\na\r\n${d}\r\n",
        .{value_len},
    );
    try stream.writeAll(header);
    try stream.writeAll(value);
    try stream.writeAll("\r\n");
    var buf: [256]u8 = undefined;
    const n = try stream.read(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "+OK") != null);

    const pipeline: usize = 32;
    var i: usize = 0;
    while (i < pipeline) : (i += 1) {
        try stream.writeAll("*2\r\n$3\r\nGET\r\n$1\r\na\r\n");
    }

    var resp_buf = std.ArrayList(u8).empty;
    defer resp_buf.deinit(allocator);

    var tmp: [4096]u8 = undefined;
    var seen: usize = 0;
    var attempt: usize = 0;
    var resp_header_buf: [32]u8 = undefined;
    const resp_header = try std.fmt.bufPrint(&resp_header_buf, "${d}\r\n", .{value_len});
    while (attempt < 200 and seen < pipeline) : (attempt += 1) {
        const read_n = try stream.read(&tmp);
        if (read_n == 0) break;
        try resp_buf.appendSlice(allocator, tmp[0..read_n]);
        seen = std.mem.count(u8, resp_buf.items, resp_header);
    }
    try std.testing.expectEqual(pipeline, seen);
}

test "resp large response grows buffers" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .resp,
    });
    defer harness.stop();

    var stream = try connectRetry(harness.server.address());
    defer stream.close();

    const value_len = output_buffer.default_inline_bytes + 1024;
    const value = try allocator.alloc(u8, value_len);
    defer allocator.free(value);
    @memset(value, 'a');

    var header_buf: [128]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &header_buf,
        "*3\r\n$3\r\nSET\r\n$1\r\na\r\n${d}\r\n",
        .{value_len},
    );
    try stream.writeAll(header);
    try stream.writeAll(value);
    try stream.writeAll("\r\n");

    var ack_buf: [64]u8 = undefined;
    var ack_used: usize = 0;
    while (ack_used < ack_buf.len) {
        const n = try stream.read(ack_buf[ack_used..]);
        if (n == 0) break;
        ack_used += n;
        if (std.mem.indexOf(u8, ack_buf[0..ack_used], "+OK\r\n") != null) break;
    }
    try std.testing.expect(std.mem.indexOf(u8, ack_buf[0..ack_used], "+OK\r\n") != null);

    try stream.writeAll("*2\r\n$3\r\nGET\r\n$1\r\na\r\n");

    var resp_buf = std.ArrayList(u8).empty;
    defer resp_buf.deinit(allocator);

    var tmp: [1024]u8 = undefined;
    var bulk_ok = false;
    var attempt: usize = 0;
    while (attempt < 200 and !bulk_ok) : (attempt += 1) {
        const n = try stream.read(&tmp);
        if (n == 0) break;
        try resp_buf.appendSlice(allocator, tmp[0..n]);
        const data = resp_buf.items;
        const dollar = std.mem.indexOfScalar(u8, data, '$') orelse continue;
        const line_end = std.mem.indexOfPos(u8, data, dollar, "\r\n") orelse continue;
        const len_slice = data[dollar + 1 .. line_end];
        const bulk_len = std.fmt.parseInt(usize, len_slice, 10) catch continue;
        const needed = line_end + 2 + bulk_len + 2;
        if (data.len < needed) continue;
        const value_slice = data[line_end + 2 .. line_end + 2 + bulk_len];
        bulk_ok = std.mem.eql(u8, value_slice, value);
    }

    try std.testing.expect(bulk_ok);
}

test "resp ops commands return pong and stats" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .resp,
    });
    defer harness.stop();

    var stream = try connectRetry(harness.server.address());
    defer stream.close();

    try stream.writeAll("*1\r\n$4\r\nPING\r\n");
    var buf: [1024]u8 = undefined;
    var n = try stream.read(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "+PONG") != null);

    try stream.writeAll("*1\r\n$4\r\nINFO\r\n");
    n = try stream.read(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "cache.items") != null);

    try stream.writeAll("*1\r\n$5\r\nSTATS\r\n");
    n = try stream.read(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "cache.items") != null);
}

test "resp monitor streams commands and closes on non-ping" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .resp,
    });
    defer harness.stop();

    var monitor = try connectRetry(harness.server.address());
    defer monitor.close();

    try monitor.writeAll("*1\r\n$7\r\nMONITOR\r\n");
    var ok_buf: [64]u8 = undefined;
    var ok_used: usize = 0;
    var ok_found = false;
    var attempt: usize = 0;
    while (attempt < 5 and ok_used < ok_buf.len) : (attempt += 1) {
        const n = try monitor.read(ok_buf[ok_used..]);
        if (n == 0) break;
        ok_used += n;
        if (std.mem.indexOf(u8, ok_buf[0..ok_used], "+OK\r\n") != null) {
            ok_found = true;
            break;
        }
    }
    try std.testing.expect(ok_found);

    var client = try connectRetry(harness.server.address());
    defer client.close();
    const monitor_requests: usize = 8;
    var req_idx: usize = 0;
    while (req_idx < monitor_requests) : (req_idx += 1) {
        try client.writeAll("*2\r\n$3\r\nGET\r\n$1\r\na\r\n");
    }
    var client_buf: [128]u8 = undefined;
    _ = try client.read(&client_buf);

    var monitor_buf = std.ArrayList(u8).empty;
    defer monitor_buf.deinit(allocator);
    var tmp: [256]u8 = undefined;
    var seen: usize = 0;
    attempt = 0;
    while (attempt < 50 and seen < monitor_requests) : (attempt += 1) {
        const n = try monitor.read(&tmp);
        if (n == 0) break;
        try monitor_buf.appendSlice(allocator, tmp[0..n]);
        const data = monitor_buf.items;
        if (std.mem.indexOf(u8, data, "[0 127.0.0.1:") != null) {
            seen = std.mem.count(u8, data, "\"GET\" \"a\"");
        }
    }
    try std.testing.expect(seen >= monitor_requests);

    var monitor2 = try connectRetry(harness.server.address());
    defer monitor2.close();
    try monitor2.writeAll("*1\r\n$7\r\nMONITOR\r\n");
    var ok2_buf: [64]u8 = undefined;
    var ok2_used: usize = 0;
    var ok2_found = false;
    attempt = 0;
    while (attempt < 5 and ok2_used < ok2_buf.len) : (attempt += 1) {
        const n = try monitor2.read(ok2_buf[ok2_used..]);
        if (n == 0) break;
        ok2_used += n;
        if (std.mem.indexOf(u8, ok2_buf[0..ok2_used], "+OK\r\n") != null) {
            ok2_found = true;
            break;
        }
    }
    try std.testing.expect(ok2_found);

    try monitor2.writeAll("*2\r\n$3\r\nGET\r\n$1\r\nb\r\n");
    var closed = false;
    attempt = 0;
    while (attempt < 10) : (attempt += 1) {
        const n = try monitor2.read(&tmp);
        if (n == 0) {
            closed = true;
            break;
        }
    }
    try std.testing.expect(closed);
}

test "resp malformed request returns error and closes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .resp,
    });
    defer harness.stop();

    var stream = try connectRetry(harness.server.address());
    defer stream.close();

    try stream.writeAll("*2\r\n$3\r\nGET\r\n$4\r\nshort\r\n");
    var buf: [256]u8 = undefined;
    const n = try stream.read(&buf);
    try std.testing.expect(n > 0);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "-ERR") != null);
    const n2 = try stream.read(&buf);
    try std.testing.expect(n2 == 0);
}

test "concurrent connections" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .http,
        .max_connections = 16,
    });
    defer harness.stop();

    const bound = harness.server.address();
    var threads: [8]std.Thread = undefined;
    var i: usize = 0;
    while (i < threads.len) : (i += 1) {
        threads[i] = try std.Thread.spawn(.{}, struct {
            fn run(address: std.net.Address) void {
                var stream = std.net.tcpConnectToAddress(address) catch return;
                defer stream.close();
                stream.writeAll("GET /k HTTP/1.1\r\nConnection: close\r\n\r\n") catch return;
                var buf: [128]u8 = undefined;
                _ = stream.read(&buf) catch return;
            }
        }.run, .{bound});
    }
    for (threads) |t| t.join();
}

test "metrics snapshot tracks requests and bytes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .http,
    });
    var stopped = false;
    defer if (!stopped) harness.stop();

    var stream = try connectRetry(harness.server.address());
    defer stream.close();

    try stream.writeAll("GET /k HTTP/1.1\r\nConnection: close\r\n\r\n");
    var buf: [256]u8 = undefined;
    _ = try readHttpResponse(&stream, &buf);

    harness.shutdown();
    const metrics = waitForMetricsSnapshot(harness.server, 1, 1);
    harness.deinit();
    stopped = true;

    try std.testing.expectEqual(@as(usize, 0), metrics.active_connections);
    try std.testing.expect(metrics.total_connections >= 1);
    try std.testing.expect(metrics.total_requests >= 1);
    try std.testing.expect(metrics.total_responses >= 1);
    try std.testing.expect(metrics.bytes_read > 0);
    try std.testing.expect(metrics.bytes_written > 0);
}

test "pool exhaustion increments pool_full" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .http,
        .max_connections = 1,
    });
    var stopped = false;
    defer if (!stopped) harness.stop();

    var stream1 = try connectRetry(harness.server.address());
    var stream1_closed = false;
    defer if (!stream1_closed) stream1.close();
    try stream1.writeAll("GET /a HTTP/1.1\r\nConnection: keep-alive\r\n\r\n");
    var buf: [256]u8 = undefined;
    _ = try readHttpResponse(&stream1, &buf);
    std.Thread.sleep(5 * std.time.ns_per_ms);

    var stream2 = try connectRetry(harness.server.address());
    defer stream2.close();
    try stream2.writeAll("GET /b HTTP/1.1\r\nConnection: close\r\n\r\n");
    var buf2: [128]u8 = undefined;
    const n = stream2.read(&buf2) catch |err| switch (err) {
        error.ConnectionResetByPeer => 0,
        else => return err,
    };
    if (n > 0) {
        try std.testing.expect(std.mem.indexOf(u8, buf2[0..n], "HTTP/1.1") == null);
    }

    stream1.close();
    stream1_closed = true;

    harness.shutdown();
    const metrics = harness.server.metricsSnapshot();
    harness.deinit();
    stopped = true;

    try std.testing.expect(metrics.errors.pool_full >= 1);
}

test "threaded server dispatches across workers" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache.engine.deinit(cache_instance);

    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var harness = try TestThreadedServer.start(.{
        .allocator = allocator,
        .cache = cache_instance,
        .address = addr,
        .protocol = .http,
        .max_connections = 8,
    }, 2);
    var stopped = false;
    defer if (!stopped) harness.stop();

    const bound = harness.server.address();
    var stream1 = try connectRetry(bound);
    defer stream1.close();
    try stream1.writeAll("GET /a HTTP/1.1\r\nConnection: close\r\n\r\n");
    var buf: [256]u8 = undefined;
    _ = try readHttpResponse(&stream1, &buf);

    var stream2 = try connectRetry(bound);
    defer stream2.close();
    try stream2.writeAll("GET /b HTTP/1.1\r\nConnection: close\r\n\r\n");
    _ = try readHttpResponse(&stream2, &buf);

    std.Thread.sleep(10 * std.time.ns_per_ms);
    harness.shutdown();
    const metrics = waitForMetricsSnapshot(harness.server, 2, 2);
    const w0 = harness.server.workers[0].connections.load(.monotonic);
    const w1 = harness.server.workers[1].connections.load(.monotonic);
    harness.deinit();
    stopped = true;

    try std.testing.expect(metrics.total_connections >= 2);
    try std.testing.expect(metrics.total_requests >= 2);
    try std.testing.expect(metrics.active_connections == 0);
    try std.testing.expect(w0 > 0);
    try std.testing.expect(w1 > 0);
}
