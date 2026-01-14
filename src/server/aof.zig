const std = @import("std");
const builtin = @import("builtin");
const cache_mod = @import("../cache/mod.zig");

pub const AppendFsync = enum {
    always,
    everysec,
    no,
};

pub const StartStatus = enum {
    ok,
    disabled,
    busy,
    failed,
};

pub const CompletionFn = *const fn (ctx: *anyopaque, ok: bool) void;

pub const ReplayStats = struct {
    applied: u64 = 0,
    skipped: u64 = 0,
    deleted: u64 = 0,
};

pub const Options = struct {
    path: ?[]const u8 = null,
    enabled: bool = false,
    append_fsync: AppendFsync = .everysec,
    auto_rewrite_percentage: u32 = 100,
    auto_rewrite_min_size: u64 = 64 * 1024 * 1024,
};

pub const RecordKind = enum(u8) {
    set = 1,
    del = 2,
    expire = 3,
};

const header_magic = [_]u8{ 'C', 'R', 'U', 'C', 'A', 'O', 'F', 0 };
const header_version: u32 = 1;
const header_len: usize = header_magic.len + 4 + 4;
const record_header_len: usize = 1 + 4 + 4 + 4 + 8 + 8 + 4;

const QueueNode = struct {
    payload: []u8,
    next: ?*QueueNode = null,
};

const Queue = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    head: ?*QueueNode = null,
    tail: ?*QueueNode = null,
    closed: bool = false,

    fn push(self: *Queue, node: *QueueNode) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.closed) return false;
        node.next = null;
        if (self.tail) |tail| {
            tail.next = node;
        } else {
            self.head = node;
        }
        self.tail = node;
        self.cond.signal();
        return true;
    }

    fn pop(self: *Queue) ?*QueueNode {
        const node = self.head orelse return null;
        self.head = node.next;
        if (self.head == null) {
            self.tail = null;
        }
        node.next = null;
        return node;
    }

    fn close(self: *Queue) void {
        self.mutex.lock();
        self.closed = true;
        self.cond.broadcast();
        self.mutex.unlock();
    }

    fn drain(self: *Queue, allocator: std.mem.Allocator) void {
        self.mutex.lock();
        var node = self.head;
        self.head = null;
        self.tail = null;
        self.mutex.unlock();
        while (node) |entry| {
            const next = entry.next;
            allocator.free(entry.payload);
            allocator.destroy(entry);
            node = next;
        }
    }
};

const SwapState = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    requested: bool = false,
    paused: bool = false,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    cache: *cache_mod.api.Cache,
    options: Options,
    file: ?std.fs.File = null,
    writer_thread: ?std.Thread = null,
    queue: Queue = .{},
    failed: std.atomic.Value(bool) = .init(false),
    size_mutex: std.Thread.Mutex = .{},
    current_size: u64 = 0,
    base_size: u64 = 0,
    rewrite_mutex: std.Thread.Mutex = .{},
    rewrite_active: bool = false,
    rewrite_buffer: std.ArrayList(u8) = std.ArrayList(u8).empty,
    swap_state: SwapState = .{},
    reset_base_after_swap: std.atomic.Value(bool) = .init(false),

    pub fn init(allocator: std.mem.Allocator, cache: *cache_mod.api.Cache, options: Options) Manager {
        return .{
            .allocator = allocator,
            .cache = cache,
            .options = options,
        };
    }

    pub fn enabled(self: *const Manager) bool {
        return self.options.enabled and self.options.path != null;
    }

    pub fn start(self: *Manager) !void {
        if (!self.enabled()) return;
        const path = self.options.path.?;
        var file = try openAofFile(path);
        const size = (try file.stat()).size;
        try file.seekFromEnd(0);
        self.file = file;
        self.current_size = size;
        self.base_size = size;
        self.writer_thread = try std.Thread.spawn(.{}, writerMain, .{self});
    }

    pub fn deinit(self: *Manager) void {
        if (self.enabled()) {
            self.queue.close();
            if (self.writer_thread) |thread| {
                thread.join();
            }
            if (self.file) |file| {
                file.close();
            }
        }
        self.queue.drain(self.allocator);
        self.rewrite_buffer.deinit(self.allocator);
    }

    pub fn appendSet(self: *Manager, key: []const u8, value: []const u8, flags: u32, cas: u64, expire_unix_ns: u64) !void {
        if (!self.enabled()) return error.Disabled;
        if (self.failed.load(.acquire)) return error.PersistenceFailed;
        const payload = try encodeRecord(self.allocator, .{
            .kind = .set,
            .key = key,
            .value = value,
            .flags = flags,
            .cas = cas,
            .expire_unix_ns = expire_unix_ns,
        });
        try self.enqueue(payload);
    }

    pub fn appendDel(self: *Manager, key: []const u8) !void {
        if (!self.enabled()) return error.Disabled;
        if (self.failed.load(.acquire)) return error.PersistenceFailed;
        const payload = try encodeRecord(self.allocator, .{
            .kind = .del,
            .key = key,
            .value = "",
            .flags = 0,
            .cas = 0,
            .expire_unix_ns = 0,
        });
        try self.enqueue(payload);
    }

    pub fn appendExpire(self: *Manager, key: []const u8, expire_unix_ns: u64) !void {
        if (!self.enabled()) return error.Disabled;
        if (self.failed.load(.acquire)) return error.PersistenceFailed;
        const payload = try encodeRecord(self.allocator, .{
            .kind = .expire,
            .key = key,
            .value = "",
            .flags = 0,
            .cas = 0,
            .expire_unix_ns = expire_unix_ns,
        });
        try self.enqueue(payload);
    }

    pub fn startRewrite(
        self: *Manager,
        completion_ctx: *anyopaque,
        completion_fn: CompletionFn,
    ) StartStatus {
        if (!self.enabled()) return .disabled;
        self.rewrite_mutex.lock();
        if (self.rewrite_active) {
            self.rewrite_mutex.unlock();
            return .busy;
        }
        self.rewrite_active = true;
        self.rewrite_mutex.unlock();

        const task = self.allocator.create(RewriteTask) catch {
            self.rewrite_mutex.lock();
            self.rewrite_active = false;
            self.rewrite_mutex.unlock();
            return .failed;
        };
        task.* = .{
            .manager = self,
            .completion_ctx = completion_ctx,
            .completion_fn = completion_fn,
        };
        const thread = std.Thread.spawn(.{}, rewriteMain, .{task}) catch {
            self.allocator.destroy(task);
            self.rewrite_mutex.lock();
            self.rewrite_active = false;
            self.rewrite_mutex.unlock();
            return .failed;
        };
        thread.detach();
        return .ok;
    }

    fn enqueue(self: *Manager, payload: []u8) !void {
        const node = try self.allocator.create(QueueNode);
        node.* = .{ .payload = payload };
        if (!self.queue.push(node)) {
            self.allocator.free(payload);
            self.allocator.destroy(node);
            return error.Disabled;
        }
    }
};

const Record = struct {
    kind: RecordKind,
    key: []const u8,
    value: []const u8,
    flags: u32,
    cas: u64,
    expire_unix_ns: u64,
};

pub fn replay(allocator: std.mem.Allocator, cache: *cache_mod.api.Cache, path: []const u8) !ReplayStats {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
    defer file.close();

    const header = try readHeader(&file);
    if (header.version != header_version) return error.UnsupportedVersion;

    var stats = ReplayStats{};
    const now_time = cache_mod.engine.now();
    const unix_now_ns = @as(u64, @intCast(now_time));

    while (true) {
        var header_buf: [record_header_len]u8 = undefined;
        const n = try file.read(&header_buf);
        if (n == 0) break;
        if (n < record_header_len) break;

        const kind = @as(RecordKind, @enumFromInt(header_buf[0]));
        const key_len = readIntFromBuf(u32, header_buf[1..5]);
        const value_len = readIntFromBuf(u32, header_buf[5..9]);
        const flags = readIntFromBuf(u32, header_buf[9..13]);
        const cas = readIntFromBuf(u64, header_buf[13..21]);
        const expire_unix_ns = readIntFromBuf(u64, header_buf[21..29]);
        const payload_crc = readIntFromBuf(u32, header_buf[29..33]);

        const payload_len = @as(usize, key_len) + @as(usize, value_len);
        const payload = try allocator.alloc(u8, payload_len);
        defer allocator.free(payload);
        if (payload_len > 0) {
            const read_payload = try file.readAll(payload);
            if (read_payload != payload_len) break;
        }
        if (!checkCrc(payload, payload_crc)) return error.RecordCrcMismatch;

        const key = payload[0..@as(usize, key_len)];
        const value = payload[@as(usize, key_len)..payload_len];

        switch (kind) {
            .set => {
                if (expire_unix_ns > 0 and expire_unix_ns <= unix_now_ns) {
                    stats.skipped += 1;
                    continue;
                }
                const opts = cache_mod.api.StoreOptions{
                    .time = now_time,
                    .expires = if (expire_unix_ns > 0) @as(i64, @intCast(expire_unix_ns)) else 0,
                    .flags = flags,
                    .restore_cas = cache_mod.engine.usecas(cache) and cas != 0,
                    .cas = cas,
                };
                _ = try cache_mod.engine.store(cache, key, value, opts);
                stats.applied += 1;
            },
            .del => {
                _ = cache_mod.engine.delete(cache, key, .{ .time = now_time });
                stats.deleted += 1;
            },
            .expire => {
                if (expire_unix_ns == 0 or expire_unix_ns <= unix_now_ns) {
                    _ = cache_mod.engine.delete(cache, key, .{ .time = now_time });
                    stats.deleted += 1;
                    continue;
                }
                const entry = try cache_mod.engine.load(cache, key, .{
                    .time = now_time,
                    .update = (struct {
                        fn apply(
                            _: u32,
                            _: i64,
                            _: []const u8,
                            value_slice: []const u8,
                            _: i64,
                            flags_slice: u32,
                            _: u64,
                            udata: ?*anyopaque,
                        ) ?cache_mod.api.Update {
                            const exp = @as(*const u64, @ptrCast(@alignCast(udata.?))).*;
                            return .{ .value = value_slice, .flags = flags_slice, .expires = @as(i64, @intCast(exp)) };
                        }
                    }).apply,
                    .udata = @constCast(@ptrCast(&expire_unix_ns)),
                });
                if (entry) |handle| {
                    handle.release();
                }
                stats.applied += 1;
            },
        }
    }

    return stats;
}

const Header = struct {
    version: u32,
    flags: u32,
};

fn readHeader(reader: anytype) !Header {
    var magic: [header_magic.len]u8 = undefined;
    try readExact(reader, &magic);
    if (!std.mem.eql(u8, magic[0..], header_magic[0..])) return error.InvalidHeader;
    return .{
        .version = try readInt(reader, u32),
        .flags = try readInt(reader, u32),
    };
}

fn writeHeader(writer: anytype) !void {
    try writer.writeAll(header_magic[0..]);
    try writeInt(writer, u32, header_version);
    try writeInt(writer, u32, 0);
}

fn encodeRecord(allocator: std.mem.Allocator, rec: Record) ![]u8 {
    if (rec.key.len > std.math.maxInt(u32)) return error.RecordTooLarge;
    if (rec.value.len > std.math.maxInt(u32)) return error.RecordTooLarge;

    const total_len = record_header_len + rec.key.len + rec.value.len;
    var buf = try allocator.alloc(u8, total_len);
    buf[0] = @intFromEnum(rec.kind);
    writeIntToBuf(u32, buf[1..5], @as(u32, @intCast(rec.key.len)));
    writeIntToBuf(u32, buf[5..9], @as(u32, @intCast(rec.value.len)));
    writeIntToBuf(u32, buf[9..13], rec.flags);
    writeIntToBuf(u64, buf[13..21], rec.cas);
    writeIntToBuf(u64, buf[21..29], rec.expire_unix_ns);
    std.mem.copyForwards(u8, buf[record_header_len..][0..rec.key.len], rec.key);
    std.mem.copyForwards(u8, buf[record_header_len + rec.key.len ..][0..rec.value.len], rec.value);

    var crc_state = std.hash.Crc32.init();
    crc_state.update(buf[record_header_len..]);
    writeIntToBuf(u32, buf[29..33], crc_state.final());

    return buf;
}

fn openAofFile(path: []const u8) !std.fs.File {
    var file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = false });
    const stat = try file.stat();
    if (stat.size == 0) {
        try writeHeader(&file);
        try file.sync();
    } else if (stat.size < header_len) {
        return error.InvalidHeader;
    } else {
        try file.seekTo(0);
        _ = try readHeader(&file);
    }
    try file.seekFromEnd(0);
    return file;
}

fn writerMain(manager: *Manager) void {
    var last_fsync: i128 = 0;
    while (true) {
        if (manager.swap_state.requested) {
            handleSwap(manager) catch {
                manager.failed.store(true, .release);
            };
            continue;
        }

        manager.queue.mutex.lock();
        while (manager.queue.head == null and !manager.queue.closed and !manager.swap_state.requested) {
            manager.queue.cond.wait(&manager.queue.mutex);
        }
        if (manager.queue.closed and manager.queue.head == null) {
            manager.queue.mutex.unlock();
            break;
        }
        if (manager.swap_state.requested) {
            manager.queue.mutex.unlock();
            continue;
        }
        const node = manager.queue.pop();
        manager.queue.mutex.unlock();
        if (node == null) continue;

        const payload = node.?.payload;
        const write_ok = writePayload(manager, payload) catch false;
        manager.allocator.free(payload);
        manager.allocator.destroy(node.?);
        if (!write_ok) {
            manager.failed.store(true, .release);
            continue;
        }

        if (manager.options.append_fsync != .no) {
            const now = std.time.nanoTimestamp();
            if (manager.options.append_fsync == .always or now - last_fsync >= std.time.ns_per_s) {
                last_fsync = now;
                if (manager.file) |file| {
                    file.sync() catch {
                        manager.failed.store(true, .release);
                    };
                }
            }
        }

        if (shouldRewrite(manager)) {
            _ = manager.startRewrite(&manager.rewrite_buffer, rewriteCompletion);
        }
    }
}

fn writePayload(manager: *Manager, payload: []const u8) !bool {
    const file = manager.file orelse return false;
    try file.writeAll(payload);
    manager.size_mutex.lock();
    manager.current_size += payload.len;
    manager.size_mutex.unlock();

    manager.rewrite_mutex.lock();
    if (manager.rewrite_active) {
        manager.rewrite_buffer.appendSlice(manager.allocator, payload) catch {
            manager.failed.store(true, .release);
        };
    }
    manager.rewrite_mutex.unlock();

    return true;
}

fn shouldRewrite(manager: *Manager) bool {
    if (!manager.enabled()) return false;
    if (manager.options.auto_rewrite_min_size == 0) return false;
    manager.rewrite_mutex.lock();
    const active = manager.rewrite_active;
    manager.rewrite_mutex.unlock();
    if (active) return false;

    manager.size_mutex.lock();
    const current_size = manager.current_size;
    const base_size = manager.base_size;
    manager.size_mutex.unlock();

    if (current_size < manager.options.auto_rewrite_min_size) return false;
    if (base_size == 0) return false;

    const growth = current_size * 100 / base_size;
    return growth >= (100 + manager.options.auto_rewrite_percentage);
}

const RewriteTask = struct {
    manager: *Manager,
    completion_ctx: *anyopaque,
    completion_fn: CompletionFn,
};

fn rewriteCompletion(_: *anyopaque, _: bool) void {}

fn rewriteMain(task: *RewriteTask) void {
    defer task.manager.allocator.destroy(task);
    var ok = true;
    rewriteFile(task.manager) catch {
        ok = false;
    };
    task.completion_fn(task.completion_ctx, ok);
}

fn rewriteFile(manager: *Manager) !void {
    const path = manager.options.path orelse return error.Disabled;
    const tmp_path = try std.fmt.allocPrint(manager.allocator, "{s}.rewrite", .{path});
    defer manager.allocator.free(tmp_path);
    var swap_requested = false;
    errdefer {
        manager.rewrite_mutex.lock();
        manager.rewrite_active = false;
        manager.rewrite_buffer.items.len = 0;
        manager.rewrite_mutex.unlock();

        if (swap_requested) {
            manager.swap_state.mutex.lock();
            manager.swap_state.requested = false;
            manager.swap_state.cond.broadcast();
            manager.swap_state.mutex.unlock();
        }
    }

    var file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
    errdefer std.fs.cwd().deleteFile(tmp_path) catch {};
    defer file.close();

    try writeHeader(&file);

    const now_time = cache_mod.engine.now();
    var ctx = RewriteContext{
        .manager = manager,
        .file = &file,
        .now_time = now_time,
        .err = null,
    };

    const res = cache_mod.engine.iter(manager.cache, .{
        .time = now_time,
        .entry = rewriteIterEntry,
        .udata = &ctx,
    });
    if (ctx.err) |err| return err;
    if (res == .Canceled) return error.SaveCanceled;

    try flushRewriteBuffer(manager, &file);

    manager.swap_state.mutex.lock();
    manager.swap_state.requested = true;
    manager.queue.cond.broadcast();
    while (!manager.swap_state.paused) {
        manager.swap_state.cond.wait(&manager.swap_state.mutex);
    }
    manager.swap_state.mutex.unlock();
    swap_requested = true;

    try flushRewriteBuffer(manager, &file);
    try file.sync();
    try std.fs.cwd().rename(tmp_path, path);
    try syncParentDir(path);

    manager.reset_base_after_swap.store(true, .release);

    manager.rewrite_mutex.lock();
    manager.rewrite_active = false;
    manager.rewrite_mutex.unlock();

    manager.swap_state.mutex.lock();
    manager.swap_state.requested = false;
    manager.swap_state.cond.broadcast();
    manager.swap_state.mutex.unlock();
}

const RewriteContext = struct {
    manager: *Manager,
    file: *std.fs.File,
    now_time: i64,
    err: ?anyerror,
};

fn rewriteIterEntry(
    _: u32,
    _: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) cache_mod.api.IterAction {
    const ctx = @as(*RewriteContext, @ptrCast(@alignCast(udata.?)));
    if (ctx.err != null) return .Stop;
    var expire_unix_ns: u64 = 0;
    if (expires > 0) {
        if (expires <= ctx.now_time) return .Continue;
        expire_unix_ns = @as(u64, @intCast(expires));
    }

    const payload = encodeRecord(ctx.manager.allocator, .{
        .kind = .set,
        .key = key,
        .value = value,
        .flags = flags,
        .cas = cas,
        .expire_unix_ns = expire_unix_ns,
    }) catch |err| {
        ctx.err = err;
        return .Stop;
    };
    defer ctx.manager.allocator.free(payload);
    ctx.file.writeAll(payload) catch |err| {
        ctx.err = err;
        return .Stop;
    };
    return .Continue;
}

fn flushRewriteBuffer(manager: *Manager, file: *std.fs.File) !void {
    var buf = std.ArrayList(u8).empty;
    manager.rewrite_mutex.lock();
    if (manager.rewrite_buffer.items.len > 0) {
        buf = manager.rewrite_buffer;
        manager.rewrite_buffer = std.ArrayList(u8).empty;
    }
    manager.rewrite_mutex.unlock();

    defer buf.deinit(manager.allocator);
    if (buf.items.len == 0) return;
    try file.writeAll(buf.items);
}

fn handleSwap(manager: *Manager) !void {
    if (manager.file) |file| {
        try file.sync();
        file.close();
        manager.file = null;
    }

    manager.swap_state.mutex.lock();
    manager.swap_state.paused = true;
    manager.swap_state.cond.broadcast();
    while (manager.swap_state.requested) {
        manager.swap_state.cond.wait(&manager.swap_state.mutex);
    }
    manager.swap_state.paused = false;
    manager.swap_state.mutex.unlock();

    if (!manager.enabled()) return;
    const path = manager.options.path.?;
    var file = try openAofFile(path);
    const size = (try file.stat()).size;
    try file.seekFromEnd(0);
    manager.file = file;
    manager.size_mutex.lock();
    manager.current_size = size;
    if (manager.reset_base_after_swap.swap(false, .acq_rel)) {
        manager.base_size = size;
    }
    manager.size_mutex.unlock();
}

fn writeInt(writer: anytype, comptime T: type, value: T) !void {
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &buf, value, .little);
    try writer.writeAll(&buf);
}

fn readInt(reader: anytype, comptime T: type) !T {
    var buf: [@sizeOf(T)]u8 = undefined;
    try readExact(reader, &buf);
    return std.mem.readInt(T, &buf, .little);
}

fn writeIntToBuf(comptime T: type, buf: []u8, value: T) void {
    std.mem.writeInt(T, buf[0..@sizeOf(T)], value, .little);
}

fn readIntFromBuf(comptime T: type, buf: []const u8) T {
    return std.mem.readInt(T, buf[0..@sizeOf(T)], .little);
}

fn readExact(reader: anytype, buf: []u8) !void {
    var offset: usize = 0;
    while (offset < buf.len) {
        const n = try reader.read(buf[offset..]);
        if (n == 0) return error.UnexpectedEof;
        offset += n;
    }
}

fn checkCrc(data: []const u8, expected: u32) bool {
    var crc_state = std.hash.Crc32.init();
    crc_state.update(data);
    return crc_state.final() == expected;
}

fn syncParentDir(path: []const u8) !void {
    if (builtin.os.tag == .windows) return;

    const dir_path = std.fs.path.dirname(path) orelse ".";
    var dir = if (std.fs.path.isAbsolute(path))
        try std.fs.openDirAbsolute(dir_path, .{})
    else
        try std.fs.cwd().openDir(dir_path, .{});
    defer dir.close();

    const rc = std.posix.system.fsync(dir.fd);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return,
        .BADF, .INVAL, .ROFS => return,
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .DQUOT => return error.DiskQuota,
        else => return error.Unexpected,
    }
}

// Tests

test "aof record encode and replay" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "appendonly.aof",
    });
    defer allocator.free(path);

    const cache1 = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache1);

    const now_time = cache_mod.engine.now();
    const expire_unix_ns = @as(u64, @intCast(now_time + 5 * std.time.ns_per_s));
    _ = try cache_mod.engine.store(cache1, "k", "v", .{ .expires = @as(i64, @intCast(expire_unix_ns)) });
    const entry = try cache_mod.engine.load(cache1, "k", .{});
    try std.testing.expect(entry != null);
    const flags = entry.?.flags();
    const cas = entry.?.cas();
    entry.?.release();

    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try writeHeader(&file);

    const record = try encodeRecord(allocator, .{
        .kind = .set,
        .key = "k",
        .value = "v",
        .flags = flags,
        .cas = cas,
        .expire_unix_ns = expire_unix_ns,
    });
    defer allocator.free(record);
    try file.writeAll(record);
    try file.sync();

    const cache2 = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache2);

    _ = try replay(allocator, cache2, path);
    const loaded = try cache_mod.engine.load(cache2, "k", .{});
    try std.testing.expect(loaded != null);
    loaded.?.release();
}

test "aof replay skips expired record" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "expired.aof",
    });
    defer allocator.free(path);

    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try writeHeader(&file);

    const now_time = cache_mod.engine.now();
    const expired_ns = @as(u64, @intCast(now_time - std.time.ns_per_ms));
    const record = try encodeRecord(allocator, .{
        .kind = .set,
        .key = "k",
        .value = "v",
        .flags = 0,
        .cas = 0,
        .expire_unix_ns = expired_ns,
    });
    defer allocator.free(record);
    try file.writeAll(record);
    try file.sync();

    const cache = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache);

    _ = try replay(allocator, cache, path);
    const loaded = try cache_mod.engine.load(cache, "k", .{});
    try std.testing.expect(loaded == null);
}

test "aof rewrite rebuilds from cache" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "rewrite.aof",
    });
    defer allocator.free(path);

    const cache = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache);

    _ = try cache_mod.engine.store(cache, "k", "v", .{});

    var mgr = Manager.init(allocator, cache, .{ .path = path, .enabled = true });
    try mgr.start();
    defer mgr.deinit();

    const RewriteWaiter = struct {
        mutex: std.Thread.Mutex = .{},
        cond: std.Thread.Condition = .{},
        done: bool = false,
        ok: bool = false,
    };

    var waiter = RewriteWaiter{};
    const status = mgr.startRewrite(&waiter, (struct {
        fn notify(ctx_ptr: *anyopaque, ok: bool) void {
            const ctx = @as(*RewriteWaiter, @ptrCast(@alignCast(ctx_ptr)));
            ctx.mutex.lock();
            ctx.done = true;
            ctx.ok = ok;
            ctx.cond.signal();
            ctx.mutex.unlock();
        }
    }).notify);
    try std.testing.expect(status == .ok);

    waiter.mutex.lock();
    while (!waiter.done) {
        waiter.cond.wait(&waiter.mutex);
    }
    const ok = waiter.ok;
    waiter.mutex.unlock();
    try std.testing.expect(ok);

    const cache2 = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache2);

    _ = try replay(allocator, cache2, path);
    const loaded = try cache_mod.engine.load(cache2, "k", .{});
    try std.testing.expect(loaded != null);
    if (loaded) |handle| {
        defer handle.release();
        try std.testing.expectEqualStrings("v", handle.value());
    }
}

test "aof replay applies expire and delete records" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "mutations.aof",
    });
    defer allocator.free(path);

    const cache = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache);

    var mgr = Manager.init(allocator, cache, .{ .path = path, .enabled = true });
    try mgr.start();
    try mgr.appendSet("alive", "v", 0, 0, 0);
    const now_time = cache_mod.engine.now();
    const future_ns = @as(u64, @intCast(now_time + 2 * std.time.ns_per_s));
    try mgr.appendExpire("alive", future_ns);
    try mgr.appendSet("gone", "v", 0, 0, 0);
    const past_ns = @as(u64, @intCast(now_time - std.time.ns_per_s));
    try mgr.appendExpire("gone", past_ns);
    try mgr.appendSet("todel", "v", 0, 0, 0);
    try mgr.appendDel("todel");
    mgr.deinit();

    const cache2 = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache2);

    _ = try replay(allocator, cache2, path);
    const alive = try cache_mod.engine.load(cache2, "alive", .{});
    try std.testing.expect(alive != null);
    if (alive) |handle| {
        defer handle.release();
        try std.testing.expectEqualStrings("v", handle.value());
    }
    try std.testing.expect((try cache_mod.engine.load(cache2, "gone", .{})) == null);
    try std.testing.expect((try cache_mod.engine.load(cache2, "todel", .{})) == null);
}

test "aof rewrite start status" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "status.aof",
    });
    defer allocator.free(path);

    const cache = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache);

    var mgr = Manager.init(allocator, cache, .{ .path = null, .enabled = false });
    var ctx: u8 = 0;
    try std.testing.expectEqual(StartStatus.disabled, mgr.startRewrite(&ctx, rewriteCompletion));

    mgr.options.path = path;
    mgr.options.enabled = true;
    mgr.rewrite_mutex.lock();
    mgr.rewrite_active = true;
    mgr.rewrite_mutex.unlock();
    try std.testing.expectEqual(StartStatus.busy, mgr.startRewrite(&ctx, rewriteCompletion));

    mgr.rewrite_mutex.lock();
    mgr.rewrite_active = false;
    mgr.rewrite_mutex.unlock();
}

test "aof replay rejects invalid header and crc mismatch" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const bad_path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "bad.aof",
    });
    defer allocator.free(bad_path);

    var bad_file = try std.fs.cwd().createFile(bad_path, .{ .truncate = true });
    defer bad_file.close();
    try bad_file.writeAll("BADMAGIC");
    try bad_file.sync();

    const cache = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache);
    try std.testing.expectError(error.InvalidHeader, replay(allocator, cache, bad_path));

    const crc_path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "crc.aof",
    });
    defer allocator.free(crc_path);

    var crc_file = try std.fs.cwd().createFile(crc_path, .{ .truncate = true });
    defer crc_file.close();
    try writeHeader(&crc_file);
    var record = try encodeRecord(allocator, .{
        .kind = .set,
        .key = "k",
        .value = "v",
        .flags = 0,
        .cas = 0,
        .expire_unix_ns = 0,
    });
    record[record_header_len] ^= 0xff;
    defer allocator.free(record);
    try crc_file.writeAll(record);
    try crc_file.sync();

    try std.testing.expectError(error.RecordCrcMismatch, replay(allocator, cache, crc_path));

    const version_path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "version.aof",
    });
    defer allocator.free(version_path);

    var version_file = try std.fs.cwd().createFile(version_path, .{ .truncate = true });
    defer version_file.close();
    var header_buf: [header_len]u8 = undefined;
    std.mem.copyForwards(u8, header_buf[0..header_magic.len], header_magic[0..]);
    std.mem.writeInt(u32, header_buf[header_magic.len .. header_magic.len + 4], header_version + 1, .little);
    std.mem.writeInt(u32, header_buf[header_magic.len + 4 .. header_len], 0, .little);
    try version_file.writeAll(&header_buf);
    try version_file.sync();

    try std.testing.expectError(error.UnsupportedVersion, replay(allocator, cache, version_path));
}

test "aof append disabled returns error" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const cache = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache);

    var mgr = Manager.init(allocator, cache, .{ .path = null, .enabled = false });
    try std.testing.expectError(error.Disabled, mgr.appendSet("k", "v", 0, 0, 0));
    try std.testing.expectError(error.Disabled, mgr.appendDel("k"));
    try std.testing.expectError(error.Disabled, mgr.appendExpire("k", 0));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "failed.aof",
    });
    defer allocator.free(path);

    var failed_mgr = Manager.init(allocator, cache, .{ .path = path, .enabled = true });
    failed_mgr.failed.store(true, .release);
    try std.testing.expectError(error.PersistenceFailed, failed_mgr.appendSet("k", "v", 0, 0, 0));
}

test "aof shouldRewrite honors thresholds" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "threshold.aof",
    });
    defer allocator.free(path);

    const cache = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 1 });
    defer cache_mod.engine.deinit(cache);

    var mgr = Manager.init(allocator, cache, .{
        .path = path,
        .enabled = true,
        .auto_rewrite_percentage = 0,
        .auto_rewrite_min_size = 10,
    });
    mgr.size_mutex.lock();
    mgr.base_size = 10;
    mgr.current_size = 20;
    mgr.size_mutex.unlock();
    try std.testing.expect(shouldRewrite(&mgr));
}
