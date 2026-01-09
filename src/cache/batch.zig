const std = @import("std");
const api = @import("api.zig");
const shard_mod = @import("shard.zig");

pub const Batch = struct {
    cache: *Cache,
    shard: ?*shard_mod.Shard,
    time: i64,
    threaded: bool,
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    yield: ?api.YieldFn = null,
    udata: ?*anyopaque = null,
    usethreadbatch: bool = false,
    usecas: bool = false,
    nosixpack: bool = false,
    noevict: bool = false,
    allowshrink: bool = false,
    nshards: usize = 0,
    loadfactor: u8 = 75,
    shrinkfactor: u8 = 10,
    seed: u64 = 0,
    notify: ?api.NotifyFn = null,
    evicted: ?api.EvictedFn = null,
    shards: []shard_mod.Shard = &.{},
};

threadlocal var tls_batch: Batch = undefined;
threadlocal var tls_in_use: bool = false;

pub fn begin(cache: *Cache) !*Batch {
    if (cache.usethreadbatch) {
        if (@import("builtin").mode == .Debug and tls_in_use) {
            return error.BatchReentrant;
        }
        tls_in_use = true;
        tls_batch = .{
            .cache = cache,
            .shard = null,
            .time = 0,
            .threaded = true,
        };
        return &tls_batch;
    }

    const batch = try cache.allocator.create(Batch);
    batch.* = .{
        .cache = cache,
        .shard = null,
        .time = 0,
        .threaded = false,
    };
    return batch;
}

pub fn end(batch: *Batch) void {
    var shard = batch.shard;
    while (shard) |current| {
        const next = current.next;
        current.next = null;
        current.unlock();
        shard = next;
    }

    if (batch.threaded) {
        if (@import("builtin").mode == .Debug) {
            tls_in_use = false;
        }
    } else {
        batch.cache.allocator.destroy(batch);
    }
}

pub fn lock(batch: ?*Batch, shard: *shard_mod.Shard, yield: ?api.YieldFn, udata: ?*anyopaque) void {
    if (batch) |b| {
        const tag = @intFromPtr(b);
        const acquired = shard.lockTagged(tag, yield, udata);
        if (acquired) {
            shard.next = b.shard;
            b.shard = shard;
        }
        return;
    }

    shard.lockExclusive(yield, udata);
}

const ThreadBatchCtx = struct {
    cache: *Cache,
    first: usize = 0,
    same: bool = false,
};

fn threadBatchWorker(ctx: *ThreadBatchCtx) void {
    const first = begin(ctx.cache) catch return;
    ctx.first = @intFromPtr(first);
    end(first);

    const second = begin(ctx.cache) catch return;
    ctx.same = @intFromPtr(second) == ctx.first;
    end(second);
}

test "batch begin/end uses thread local" {
    var cache = Cache{
        .allocator = std.testing.allocator,
        .yield = null,
        .udata = null,
        .usethreadbatch = true,
        .shards = &.{},
    };

    const batch = try begin(&cache);
    try std.testing.expect(batch.threaded);
    try std.testing.expect(batch == &tls_batch);
    end(batch);
}

test "batch non-thread allocates and frees" {
    var cache = Cache{
        .allocator = std.testing.allocator,
        .yield = null,
        .udata = null,
        .usethreadbatch = false,
        .shards = &.{},
    };

    const batch = try begin(&cache);
    try std.testing.expect(!batch.threaded);
    end(batch);
}

test "thread local batch reuse across threads" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var cache = Cache{
        .allocator = std.testing.allocator,
        .yield = null,
        .udata = null,
        .usethreadbatch = true,
        .shards = &.{},
    };

    var ctxs: [2]ThreadBatchCtx = undefined;
    ctxs[0] = .{ .cache = &cache };
    ctxs[1] = .{ .cache = &cache };
    var threads: [ctxs.len]std.Thread = undefined;
    for (ctxs, 0..) |_, i| {
        threads[i] = try std.Thread.spawn(.{}, threadBatchWorker, .{&ctxs[i]});
    }
    for (threads) |thread| {
        thread.join();
    }

    try std.testing.expect(ctxs[0].same);
    try std.testing.expect(ctxs[1].same);
    try std.testing.expect(ctxs[0].first != 0 and ctxs[1].first != 0);
    try std.testing.expect(ctxs[0].first != ctxs[1].first);
}

test "batch begin detects reentrant in debug" {
    if (@import("builtin").mode != .Debug) return error.SkipZigTest;

    var cache = Cache{
        .allocator = std.testing.allocator,
        .yield = null,
        .udata = null,
        .usethreadbatch = true,
        .shards = &.{},
    };

    const batch = try begin(&cache);
    defer end(batch);
    try std.testing.expectError(error.BatchReentrant, begin(&cache));
}

test "batch lock links shard and releases" {
    var shard = try shard_mod.Shard.init(std.testing.allocator, 8, .{});
    defer shard.deinit();

    var cache = Cache{
        .allocator = std.testing.allocator,
        .yield = null,
        .udata = null,
        .usethreadbatch = false,
        .shards = &.{},
    };

    const batch = try begin(&cache);
    lock(batch, &shard, null, null);
    try std.testing.expect(batch.shard != null);
    end(batch);
    try std.testing.expectEqual(@as(usize, 0), @atomicLoad(usize, &shard.lock, .acquire));
}
