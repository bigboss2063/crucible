const std = @import("std");
const builtin = @import("builtin");
const lz4 = @import("lz4");
const cache_mod = @import("../cache/mod.zig");

pub const SaveOptions = struct {
    path: []const u8,
    fast: bool = false,
    block_size: usize = default_block_size,
    temp_suffix: []const u8 = ".tmp",
};

pub const LoadOptions = struct {
    path: []const u8,
    fast: bool = false,
};

pub const SaveStats = struct {
    entries: u64 = 0,
    skipped: u64 = 0,
    blocks: u64 = 0,
    bytes_written: u64 = 0,
};

pub const LoadStats = struct {
    inserted: u64 = 0,
    skipped: u64 = 0,
};

pub const StartStatus = enum {
    ok,
    disabled,
    busy_save,
    busy_load,
    failed,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    cache: *cache_mod.api.Cache,
    default_path: ?[]const u8,
    state: std.atomic.Value(u8),

    pub fn init(allocator: std.mem.Allocator, cache: *cache_mod.api.Cache, default_path: ?[]const u8) Manager {
        return .{
            .allocator = allocator,
            .cache = cache,
            .default_path = default_path,
            .state = std.atomic.Value(u8).init(@intFromEnum(State.idle)),
        };
    }

    pub fn enabled(self: *const Manager) bool {
        return self.default_path != null;
    }

    pub fn startSave(self: *Manager, path_override: ?[]const u8, fast: bool) StartStatus {
        return self.start(.save, path_override, fast);
    }

    pub fn startLoad(self: *Manager, path_override: ?[]const u8, fast: bool) StartStatus {
        return self.start(.load, path_override, fast);
    }

    pub fn waitForIdle(self: *Manager) void {
        while (self.state.load(.acquire) != @intFromEnum(State.idle)) {
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    fn start(self: *Manager, kind: TaskKind, path_override: ?[]const u8, fast: bool) StartStatus {
        if (self.default_path == null) return .disabled;

        const path = path_override orelse self.default_path.?;
        if (path.len == 0) return .disabled;

        const desired_state = if (kind == .save) State.saving else State.loading;
        const expected = @intFromEnum(State.idle);
        if (self.state.cmpxchgStrong(expected, @intFromEnum(desired_state), .acq_rel, .acquire) != null) {
            const current = self.state.load(.acquire);
            return if (current == @intFromEnum(State.saving)) .busy_save else .busy_load;
        }

        const path_copy = self.allocator.dupe(u8, path) catch {
            self.state.store(@intFromEnum(State.idle), .release);
            return .failed;
        };

        const task = self.allocator.create(BackgroundTask) catch {
            self.allocator.free(path_copy);
            self.state.store(@intFromEnum(State.idle), .release);
            return .failed;
        };

        task.* = .{
            .allocator = self.allocator,
            .cache = self.cache,
            .state = &self.state,
            .kind = kind,
            .path = path_copy,
            .fast = fast,
        };

        const thread = std.Thread.spawn(.{}, backgroundTaskMain, .{task}) catch {
            self.allocator.free(path_copy);
            self.allocator.destroy(task);
            self.state.store(@intFromEnum(State.idle), .release);
            return .failed;
        };
        thread.detach();
        return .ok;
    }
};

const State = enum(u8) {
    idle = 0,
    saving = 1,
    loading = 2,
};

const TaskKind = enum {
    save,
    load,
};

const BackgroundTask = struct {
    allocator: std.mem.Allocator,
    cache: *cache_mod.api.Cache,
    state: *std.atomic.Value(u8),
    kind: TaskKind,
    path: []u8,
    fast: bool,
};

fn backgroundTaskMain(task: *BackgroundTask) void {
    defer task.state.store(@intFromEnum(State.idle), .release);
    defer task.allocator.free(task.path);
    defer task.allocator.destroy(task);

    switch (task.kind) {
        .save => _ = saveSnapshot(task.allocator, task.cache, .{ .path = task.path, .fast = task.fast }) catch {},
        .load => _ = loadSnapshot(task.allocator, task.cache, .{ .path = task.path, .fast = task.fast }) catch {},
    }
}

const default_block_size: usize = 1024 * 1024;
const header_magic = [_]u8{ 'C', 'R', 'U', 'C', 'I', 'B', 'L', 0 };
const header_version: u32 = 1;
const compression_lz4: u32 = 1;
const block_tag = [_]u8{ 'C', 'R', 'U', 'C' };
const header_len: usize = header_magic.len + 4 + 4 + 8 + 4;
const block_header_len: usize = 4 + 4 + 4 + 4;
const record_header_len: usize = 4 + 4 + 8 + 4 + 8;
const flag_cas_enabled: u32 = 1;

const Header = struct {
    version: u32,
    flags: u32,
    saved_unix_ns: u64,
    compression: u32,
};

pub fn saveSnapshot(allocator: std.mem.Allocator, cache: *cache_mod.api.Cache, opts: SaveOptions) !SaveStats {
    if (opts.path.len == 0) return error.EmptyPath;

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ opts.path, opts.temp_suffix });
    defer allocator.free(tmp_path);

    var file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
    errdefer std.fs.cwd().deleteFile(tmp_path) catch {};
    defer file.close();

    var shared = SharedFile{ .file = file };

    const now_time = cache_mod.engine.now();
    const saved_unix_ns = @as(u64, @intCast(now_time));
    const usecas = cache_mod.engine.usecas(cache);

    var stats = SaveStats{};
    try writeHeader(shared.file, .{
        .version = header_version,
        .flags = if (usecas) flag_cas_enabled else 0,
        .saved_unix_ns = saved_unix_ns,
        .compression = compression_lz4,
    });
    stats.bytes_written += header_len;

    if (opts.fast) {
        try saveFast(allocator, cache, &shared, now_time, opts.block_size, &stats);
    } else {
        try saveSingle(allocator, cache, &shared, now_time, opts.block_size, &stats);
    }

    try shared.file.sync();
    try std.fs.cwd().rename(tmp_path, opts.path);
    try syncParentDir(opts.path);

    return stats;
}

pub fn loadSnapshot(allocator: std.mem.Allocator, cache: *cache_mod.api.Cache, opts: LoadOptions) !LoadStats {
    if (opts.path.len == 0) return error.EmptyPath;

    var file = try std.fs.cwd().openFile(opts.path, .{});
    defer file.close();

    const header = try readHeader(&file);
    if (header.version != header_version) return error.UnsupportedVersion;
    if (header.compression != compression_lz4) return error.UnsupportedCompression;

    var stats = LoadStats{};
    const now_time = cache_mod.engine.now();
    const unix_now_ns = @as(u64, @intCast(now_time));
    const restore_cas = cache_mod.engine.usecas(cache) and (header.flags & flag_cas_enabled) != 0;

    if (opts.fast) {
        try loadFast(allocator, cache, opts.path, header.saved_unix_ns, unix_now_ns, now_time, restore_cas, &stats);
    } else {
        try loadSingle(allocator, cache, &file, header.saved_unix_ns, unix_now_ns, now_time, restore_cas, &stats);
    }

    return stats;
}

fn saveSingle(
    allocator: std.mem.Allocator,
    cache: *cache_mod.api.Cache,
    shared: *SharedFile,
    now_time: i64,
    block_size: usize,
    stats: *SaveStats,
) !void {
    var writer = BlockWriter.init(allocator, shared, block_size);
    defer writer.deinit();

    var ctx = SaveContext{
        .writer = &writer,
        .stats = stats,
        .err = null,
    };

    const res = cache_mod.engine.iter(cache, .{
        .time = now_time,
        .entry = saveIterEntry,
        .udata = &ctx,
    });
    if (ctx.err) |err| return err;
    if (res == .Canceled) return error.SaveCanceled;

    try writer.flush(stats);
}

fn saveFast(
    allocator: std.mem.Allocator,
    cache: *cache_mod.api.Cache,
    shared: *SharedFile,
    now_time: i64,
    block_size: usize,
    stats: *SaveStats,
) !void {
    const shard_count = @as(usize, cache_mod.engine.nshards(cache));
    const cpu_count = std.Thread.getCpuCount() catch 1;
    var worker_count: usize = if (shard_count == 0) 1 else shard_count;
    if (worker_count > cpu_count) worker_count = cpu_count;
    if (worker_count == 0) worker_count = 1;

    var workers = try allocator.alloc(SaveWorker, worker_count);
    defer allocator.free(workers);

    var threads = try allocator.alloc(std.Thread, worker_count);
    defer allocator.free(threads);

    var i: usize = 0;
    while (i < worker_count) : (i += 1) {
        workers[i] = .{
            .allocator = allocator,
            .cache = cache,
            .shared = shared,
            .now_time = now_time,
            .block_size = block_size,
            .start = i,
            .step = worker_count,
            .stats = SaveStats{},
            .err = null,
        };
        threads[i] = try std.Thread.spawn(.{}, saveWorkerMain, .{&workers[i]});
    }

    for (threads) |thread| {
        thread.join();
    }

    var combined = SaveStats{};
    for (workers) |*worker| {
        if (worker.err) |err| return err;
        combined.entries += worker.stats.entries;
        combined.skipped += worker.stats.skipped;
        combined.blocks += worker.stats.blocks;
        combined.bytes_written += worker.stats.bytes_written;
    }

    stats.entries = combined.entries;
    stats.skipped = combined.skipped;
    stats.blocks = combined.blocks;
    stats.bytes_written += combined.bytes_written;
}

fn loadSingle(
    allocator: std.mem.Allocator,
    cache: *cache_mod.api.Cache,
    reader: anytype,
    saved_unix_ns: u64,
    unix_now_ns: u64,
    now_time: i64,
    restore_cas: bool,
    stats: *LoadStats,
) !void {
    while (true) {
        var tag: [block_tag.len]u8 = undefined;
        const read_tag = try reader.read(&tag);
        if (read_tag == 0) break;
        if (read_tag != tag.len) return error.UnexpectedEof;
        if (!std.mem.eql(u8, tag[0..], block_tag[0..])) return error.BlockMalformed;

        const crc = try readInt(reader, u32);
        const decomp_len = try readInt(reader, u32);
        const comp_len = try readInt(reader, u32);

        if (decomp_len == 0 and comp_len == 0) continue;

        const comp_buf = try allocator.alloc(u8, @as(usize, comp_len));
        defer allocator.free(comp_buf);
        try readExact(reader, comp_buf);

        if (!checkCrc(comp_buf, crc)) return error.BlockCrcMismatch;

        const decomp_buf = try allocator.alloc(u8, @as(usize, decomp_len));
        defer allocator.free(decomp_buf);
        const out_len = try lz4.decompressSafe(comp_buf, decomp_buf);
        if (out_len != decomp_len) return error.BlockMalformed;

        try loadRecords(cache, decomp_buf[0..out_len], saved_unix_ns, unix_now_ns, now_time, restore_cas, stats);
    }
}

fn loadFast(
    allocator: std.mem.Allocator,
    cache: *cache_mod.api.Cache,
    path: []const u8,
    saved_unix_ns: u64,
    unix_now_ns: u64,
    now_time: i64,
    restore_cas: bool,
    stats: *LoadStats,
) !void {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    try file.seekTo(@as(u64, header_len));

    var blocks = std.ArrayList(BlockInfo).empty;
    defer blocks.deinit(allocator);

    while (true) {
        var tag: [block_tag.len]u8 = undefined;
        const read_tag = try file.read(&tag);
        if (read_tag == 0) break;
        if (read_tag != tag.len) return error.UnexpectedEof;
        if (!std.mem.eql(u8, tag[0..], block_tag[0..])) return error.BlockMalformed;

        const crc = try readInt(&file, u32);
        const decomp_len = try readInt(&file, u32);
        const comp_len = try readInt(&file, u32);
        const payload_offset = try file.getPos();

        try blocks.append(allocator, .{
            .payload_offset = payload_offset,
            .compressed_len = comp_len,
            .decompressed_len = decomp_len,
            .crc = crc,
        });

        try file.seekBy(@as(i64, @intCast(comp_len)));
    }

    const block_count = blocks.items.len;
    if (block_count == 0) return;

    const cpu_count = std.Thread.getCpuCount() catch 1;
    var worker_count: usize = if (block_count < cpu_count) block_count else cpu_count;
    if (worker_count == 0) worker_count = 1;

    var workers = try allocator.alloc(LoadWorker, worker_count);
    defer allocator.free(workers);

    var threads = try allocator.alloc(std.Thread, worker_count);
    defer allocator.free(threads);

    var i: usize = 0;
    while (i < worker_count) : (i += 1) {
        workers[i] = .{
            .allocator = allocator,
            .cache = cache,
            .path = path,
            .blocks = blocks.items,
            .start = i,
            .step = worker_count,
            .saved_unix_ns = saved_unix_ns,
            .unix_now_ns = unix_now_ns,
            .now_time = now_time,
            .restore_cas = restore_cas,
            .stats = LoadStats{},
            .err = null,
        };
        threads[i] = try std.Thread.spawn(.{}, loadWorkerMain, .{&workers[i]});
    }

    for (threads) |thread| {
        thread.join();
    }

    var combined = LoadStats{};
    for (workers) |*worker| {
        if (worker.err) |err| return err;
        combined.inserted += worker.stats.inserted;
        combined.skipped += worker.stats.skipped;
    }

    stats.* = combined;
}

const SharedFile = struct {
    file: std.fs.File,
    lock: std.Thread.Mutex = .{},

    fn writeBlock(self: *SharedFile, header: []const u8, payload: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.file.writeAll(header);
        try self.file.writeAll(payload);
    }
};

const BlockWriter = struct {
    allocator: std.mem.Allocator,
    shared: *SharedFile,
    block_size: usize,
    buffer: std.ArrayList(u8),
    compressed: std.ArrayList(u8),

    fn init(allocator: std.mem.Allocator, shared: *SharedFile, block_size: usize) BlockWriter {
        return .{
            .allocator = allocator,
            .shared = shared,
            .block_size = if (block_size == 0) default_block_size else block_size,
            .buffer = std.ArrayList(u8).empty,
            .compressed = std.ArrayList(u8).empty,
        };
    }

    fn deinit(self: *BlockWriter) void {
        self.buffer.deinit(self.allocator);
        self.compressed.deinit(self.allocator);
    }

    fn appendEntry(
        self: *BlockWriter,
        key: []const u8,
        value: []const u8,
        ttl_ns: u64,
        flags: u32,
        cas: u64,
        stats: *SaveStats,
    ) !void {
        if (key.len > std.math.maxInt(u32)) return error.RecordTooLarge;
        if (value.len > std.math.maxInt(u32)) return error.RecordTooLarge;

        const record_len = record_header_len + key.len + value.len;
        if (self.buffer.items.len > 0 and self.buffer.items.len + record_len > self.block_size) {
            try self.flush(stats);
        }

        try self.buffer.ensureUnusedCapacity(self.allocator, record_len);

        try appendInt(u32, &self.buffer, @as(u32, @intCast(key.len)));
        try appendInt(u32, &self.buffer, @as(u32, @intCast(value.len)));
        try appendInt(u64, &self.buffer, ttl_ns);
        try appendInt(u32, &self.buffer, flags);
        try appendInt(u64, &self.buffer, cas);
        self.buffer.appendSliceAssumeCapacity(key);
        self.buffer.appendSliceAssumeCapacity(value);

        if (self.buffer.items.len >= self.block_size) {
            try self.flush(stats);
        }
    }

    fn flush(self: *BlockWriter, stats: *SaveStats) !void {
        if (self.buffer.items.len == 0) return;

        const comp_bound = lz4.compressBound(self.buffer.items.len);
        try self.compressed.ensureTotalCapacity(self.allocator, comp_bound);
        self.compressed.items.len = comp_bound;
        const comp_len = try lz4.compressDefault(self.buffer.items, self.compressed.items);
        self.compressed.items.len = comp_len;

        var crc_state = std.hash.Crc32.init();
        crc_state.update(self.compressed.items);
        const crc = crc_state.final();

        var header_buf: [block_header_len]u8 = undefined;
        std.mem.copyForwards(u8, header_buf[0..4], block_tag[0..]);
        writeIntToBuf(u32, header_buf[4..8], crc);
        writeIntToBuf(u32, header_buf[8..12], @as(u32, @intCast(self.buffer.items.len)));
        writeIntToBuf(u32, header_buf[12..16], @as(u32, @intCast(comp_len)));

        try self.shared.writeBlock(header_buf[0..], self.compressed.items);

        stats.blocks += 1;
        stats.bytes_written += header_buf.len + comp_len;
        self.buffer.items.len = 0;
    }
};

const SaveContext = struct {
    writer: *BlockWriter,
    stats: *SaveStats,
    err: ?anyerror,
};

fn saveIterEntry(
    _: u32,
    time_value: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) cache_mod.api.IterAction {
    const ctx = @as(*SaveContext, @ptrCast(@alignCast(udata.?)));
    if (ctx.err != null) return .Stop;

    var ttl_ns: u64 = 0;
    if (expires > 0) {
        if (expires <= time_value) {
            ctx.stats.skipped += 1;
            return .Continue;
        }
        ttl_ns = @as(u64, @intCast(expires - time_value));
    }

    ctx.writer.appendEntry(key, value, ttl_ns, flags, cas, ctx.stats) catch |err| {
        ctx.err = err;
        return .Stop;
    };

    ctx.stats.entries += 1;
    return .Continue;
}

const SaveWorker = struct {
    allocator: std.mem.Allocator,
    cache: *cache_mod.api.Cache,
    shared: *SharedFile,
    now_time: i64,
    block_size: usize,
    start: usize,
    step: usize,
    stats: SaveStats,
    err: ?anyerror,
};

fn saveWorkerMain(worker: *SaveWorker) void {
    var writer = BlockWriter.init(worker.allocator, worker.shared, worker.block_size);
    defer writer.deinit();

    var ctx = SaveContext{
        .writer = &writer,
        .stats = &worker.stats,
        .err = null,
    };

    const shard_count = @as(usize, cache_mod.engine.nshards(worker.cache));
    var shard_idx = worker.start;
    while (shard_idx < shard_count) : (shard_idx += worker.step) {
        const res = cache_mod.engine.iter(worker.cache, .{
            .time = worker.now_time,
            .oneshard = true,
            .oneshardidx = @as(u32, @intCast(shard_idx)),
            .entry = saveIterEntry,
            .udata = &ctx,
        });
        if (ctx.err != null) {
            worker.err = ctx.err;
            return;
        }
        if (res == .Canceled) {
            worker.err = error.SaveCanceled;
            return;
        }
    }

    writer.flush(&worker.stats) catch |err| {
        worker.err = err;
    };
}

const BlockInfo = struct {
    payload_offset: u64,
    compressed_len: u32,
    decompressed_len: u32,
    crc: u32,
};

const LoadWorker = struct {
    allocator: std.mem.Allocator,
    cache: *cache_mod.api.Cache,
    path: []const u8,
    blocks: []const BlockInfo,
    start: usize,
    step: usize,
    saved_unix_ns: u64,
    unix_now_ns: u64,
    now_time: i64,
    restore_cas: bool,
    stats: LoadStats,
    err: ?anyerror,
};

fn loadWorkerMain(worker: *LoadWorker) void {
    var file = std.fs.cwd().openFile(worker.path, .{}) catch |err| {
        worker.err = err;
        return;
    };
    defer file.close();

    var comp_buf = std.ArrayList(u8).empty;
    defer comp_buf.deinit(worker.allocator);
    var decomp_buf = std.ArrayList(u8).empty;
    defer decomp_buf.deinit(worker.allocator);

    var i: usize = worker.start;
    while (i < worker.blocks.len) : (i += worker.step) {
        const info = worker.blocks[i];
        file.seekTo(info.payload_offset) catch |err| {
            worker.err = err;
            return;
        };

        comp_buf.resize(worker.allocator, @as(usize, info.compressed_len)) catch |err| {
            worker.err = err;
            return;
        };
        readExact(&file, comp_buf.items) catch |err| {
            worker.err = err;
            return;
        };

        if (!checkCrc(comp_buf.items, info.crc)) {
            worker.err = error.BlockCrcMismatch;
            return;
        }

        decomp_buf.resize(worker.allocator, @as(usize, info.decompressed_len)) catch |err| {
            worker.err = err;
            return;
        };
        const out_len = lz4.decompressSafe(comp_buf.items, decomp_buf.items) catch |err| {
            worker.err = err;
            return;
        };
        if (out_len != info.decompressed_len) {
            worker.err = error.BlockMalformed;
            return;
        }

        loadRecords(worker.cache, decomp_buf.items[0..out_len], worker.saved_unix_ns, worker.unix_now_ns, worker.now_time, worker.restore_cas, &worker.stats) catch |err| {
            worker.err = err;
            return;
        };
    }
}

fn loadRecords(
    cache: *cache_mod.api.Cache,
    buf: []const u8,
    saved_unix_ns: u64,
    unix_now_ns: u64,
    now_time: i64,
    restore_cas: bool,
    stats: *LoadStats,
) !void {
    var pos: usize = 0;
    while (pos < buf.len) {
        if (buf.len - pos < record_header_len) return error.RecordMalformed;
        const key_len = readIntFromBuf(u32, buf[pos .. pos + 4]);
        pos += 4;
        const value_len = readIntFromBuf(u32, buf[pos .. pos + 4]);
        pos += 4;
        const ttl_ns = readIntFromBuf(u64, buf[pos .. pos + 8]);
        pos += 8;
        const flags = readIntFromBuf(u32, buf[pos .. pos + 4]);
        pos += 4;
        const cas = readIntFromBuf(u64, buf[pos .. pos + 8]);
        pos += 8;

        const needed = @as(usize, key_len) + @as(usize, value_len);
        if (buf.len - pos < needed) return error.RecordMalformed;

        const key_len_usize = @as(usize, key_len);
        const value_len_usize = @as(usize, value_len);
        const key = buf[pos .. pos + key_len_usize];
        pos += key_len_usize;
        const value = buf[pos .. pos + value_len_usize];
        pos += value_len_usize;

        if (ttl_ns > 0) {
            const expires = std.math.add(u64, saved_unix_ns, ttl_ns) catch return error.RecordMalformed;
            if (expires <= unix_now_ns) {
                stats.skipped += 1;
                continue;
            }
            const remaining = expires - unix_now_ns;
            const ttl_i64 = std.math.cast(i64, remaining) orelse return error.RecordMalformed;
            _ = try cache_mod.engine.store(cache, key, value, .{
                .time = now_time,
                .ttl = ttl_i64,
                .flags = flags,
                .restore_cas = restore_cas,
                .cas = cas,
            });
        } else {
            _ = try cache_mod.engine.store(cache, key, value, .{
                .time = now_time,
                .flags = flags,
                .restore_cas = restore_cas,
                .cas = cas,
            });
        }
        stats.inserted += 1;
    }
}

fn writeHeader(writer: anytype, header: Header) !void {
    try writer.writeAll(header_magic[0..]);
    try writeInt(writer, u32, header.version);
    try writeInt(writer, u32, header.flags);
    try writeInt(writer, u64, header.saved_unix_ns);
    try writeInt(writer, u32, header.compression);
}

fn readHeader(reader: anytype) !Header {
    var magic: [header_magic.len]u8 = undefined;
    try readExact(reader, &magic);
    if (!std.mem.eql(u8, magic[0..], header_magic[0..])) return error.InvalidHeader;
    return .{
        .version = try readInt(reader, u32),
        .flags = try readInt(reader, u32),
        .saved_unix_ns = try readInt(reader, u64),
        .compression = try readInt(reader, u32),
    };
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

fn appendInt(comptime T: type, list: *std.ArrayList(u8), value: T) !void {
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &buf, value, .little);
    list.appendSliceAssumeCapacity(&buf);
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

test "snapshot preserves cas when enabled" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "snap.cas",
    });
    defer allocator.free(path);

    const cache1 = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4, .usecas = true });
    defer cache_mod.engine.deinit(cache1);

    _ = try cache_mod.engine.store(cache1, "k", "v", .{});
    const entry = try cache_mod.engine.load(cache1, "k", .{});
    try std.testing.expect(entry != null);
    const cas_value = entry.?.cas();
    entry.?.release();

    _ = try saveSnapshot(allocator, cache1, .{ .path = path, .fast = true });

    const cache2 = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4, .usecas = true });
    defer cache_mod.engine.deinit(cache2);

    _ = try loadSnapshot(allocator, cache2, .{ .path = path, .fast = true });
    const loaded = try cache_mod.engine.load(cache2, "k", .{});
    try std.testing.expect(loaded != null);
    try std.testing.expectEqual(cas_value, loaded.?.cas());
    loaded.?.release();
}

test "snapshot load skips expired ttl" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "snap.ttl",
    });
    defer allocator.free(path);

    const cache1 = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache1);

    const ttl_ns = @as(i64, @intCast(30 * std.time.ns_per_ms));
    _ = try cache_mod.engine.store(cache1, "k", "v", .{ .ttl = ttl_ns });

    _ = try saveSnapshot(allocator, cache1, .{ .path = path });

    std.Thread.sleep(50 * std.time.ns_per_ms);

    const cache2 = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache2);

    _ = try loadSnapshot(allocator, cache2, .{ .path = path });
    const loaded = try cache_mod.engine.load(cache2, "k", .{});
    try std.testing.expect(loaded == null);
}

test "snapshot detects crc mismatch" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "snap.crc",
    });
    defer allocator.free(path);

    const cache1 = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache1);

    _ = try cache_mod.engine.store(cache1, "k", "v", .{});
    _ = try saveSnapshot(allocator, cache1, .{ .path = path });

    var file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();

    const size = (try file.stat()).size;
    var buf = try allocator.alloc(u8, @as(usize, @intCast(size)));
    defer allocator.free(buf);
    _ = try file.readAll(buf);

    const payload_offset = header_len + block_header_len;
    if (buf.len > payload_offset) {
        buf[payload_offset] ^= 0xff;
        try file.seekTo(0);
        try file.writeAll(buf);
        try file.sync();
    }

    try std.testing.expectError(error.BlockCrcMismatch, loadSnapshot(allocator, cache1, .{ .path = path }));
}
