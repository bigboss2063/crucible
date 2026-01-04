const std = @import("std");
const api = @import("api.zig");
const batch = @import("batch.zig");
const bucket = @import("bucket.zig");
const entry = @import("entry.zig");
const hash = @import("hash.zig");
const map = @import("map.zig");
const shard_mod = @import("shard.zig");

const CacheImpl = batch.Cache;
const BatchImpl = batch.Batch;

const default_shards: usize = 4096;
const default_loadfactor: u8 = 75;
const min_loadfactor: u8 = 55;
const max_loadfactor: u8 = 95;
const shrink_factor: u8 = 10;
const init_cap: usize = 64;

const NotifyKind = enum {
    Inserted,
    Replaced,
    Deleted,
    Expired,
    Cleared,
    LowMem,
};

pub fn init(opts: api.Options) !*api.Cache {
    const impl = try createImpl(opts);
    return @ptrCast(impl);
}

pub fn deinit(cache_ptr: *api.Cache) void {
    destroyImpl(cacheImpl(cache_ptr));
}

pub fn begin(cache_ptr: *api.Cache) !*api.Batch {
    const impl = cacheImpl(cache_ptr);
    const batch_ptr = try batch.begin(impl);
    return @ptrCast(batch_ptr);
}

pub fn end(batch_ptr: *api.Batch) void {
    batch.end(batchImpl(batch_ptr));
}

pub fn store(cache_ptr: *api.Cache, key: []const u8, value: []const u8, opts: api.StoreOptions) !api.StoreResult {
    return storeImpl(cacheImpl(cache_ptr), null, key, value, opts);
}

pub fn storeBatch(batch_ptr: *api.Batch, key: []const u8, value: []const u8, opts: api.StoreOptions) !api.StoreResult {
    const batch_impl = batchImpl(batch_ptr);
    return storeImpl(batch_impl.cache, batch_impl, key, value, opts);
}

pub fn load(cache_ptr: *api.Cache, key: []const u8, opts: api.LoadOptions) !?api.Entry {
    return loadImpl(cacheImpl(cache_ptr), null, key, opts);
}

pub fn loadBatch(batch_ptr: *api.Batch, key: []const u8, opts: api.LoadOptions) !?api.Entry {
    const batch_impl = batchImpl(batch_ptr);
    return loadImpl(batch_impl.cache, batch_impl, key, opts);
}

pub fn delete(cache_ptr: *api.Cache, key: []const u8, opts: api.DeleteOptions) api.DeleteResult {
    return deleteImpl(cacheImpl(cache_ptr), null, key, opts);
}

pub fn deleteBatch(batch_ptr: *api.Batch, key: []const u8, opts: api.DeleteOptions) api.DeleteResult {
    const batch_impl = batchImpl(batch_ptr);
    return deleteImpl(batch_impl.cache, batch_impl, key, opts);
}

pub fn iter(cache_ptr: *api.Cache, opts: api.IterOptions) api.IterResult {
    return iterImpl(cacheImpl(cache_ptr), null, opts);
}

pub fn iterBatch(batch_ptr: *api.Batch, opts: api.IterOptions) api.IterResult {
    const batch_impl = batchImpl(batch_ptr);
    return iterImpl(batch_impl.cache, batch_impl, opts);
}

pub fn entryIter(cache_ptr: *api.Cache, time: i64, cursor: *u64) ?api.Entry {
    const impl = cacheImpl(cache_ptr);
    const res = entryIterImpl(impl, time, cursor);
    return if (res) |ent| makeEntryHandle(impl, ent) else null;
}

pub fn sweep(cache_ptr: *api.Cache, swept: ?*usize, kept: ?*usize, opts: api.SweepOptions) void {
    sweepImpl(cacheImpl(cache_ptr), null, swept, kept, opts);
}

pub fn sweepBatch(batch_ptr: *api.Batch, swept: ?*usize, kept: ?*usize, opts: api.SweepOptions) void {
    const batch_impl = batchImpl(batch_ptr);
    sweepImpl(batch_impl.cache, batch_impl, swept, kept, opts);
}

pub fn sweepPoll(cache_ptr: *api.Cache, opts: api.SweepPollOptions) f64 {
    return sweepPollImpl(cacheImpl(cache_ptr), null, opts);
}

pub fn sweepPollBatch(batch_ptr: *api.Batch, opts: api.SweepPollOptions) f64 {
    const batch_impl = batchImpl(batch_ptr);
    return sweepPollImpl(batch_impl.cache, batch_impl, opts);
}

pub fn clear(cache_ptr: *api.Cache, opts: api.ClearOptions) void {
    clearImpl(cacheImpl(cache_ptr), null, opts);
}

pub fn clearBatch(batch_ptr: *api.Batch, opts: api.ClearOptions) void {
    const batch_impl = batchImpl(batch_ptr);
    clearImpl(batch_impl.cache, batch_impl, opts);
}

pub fn count(cache_ptr: *api.Cache, opts: api.CountOptions) usize {
    return countImpl(cacheImpl(cache_ptr), null, opts);
}

pub fn total(cache_ptr: *api.Cache, opts: api.TotalOptions) u64 {
    return totalImpl(cacheImpl(cache_ptr), null, opts);
}

pub fn size(cache_ptr: *api.Cache, opts: api.SizeOptions) usize {
    return sizeImpl(cacheImpl(cache_ptr), null, opts);
}

pub fn nshards(cache_ptr: *api.Cache) u32 {
    return @as(u32, @intCast(cacheImpl(cache_ptr).nshards));
}

pub fn usecas(cache_ptr: *api.Cache) bool {
    return cacheImpl(cache_ptr).usecas;
}

pub fn now() i64 {
    return @as(i64, @intCast(std.time.nanoTimestamp()));
}

fn makeEntryHandle(cache: *CacheImpl, ent: *entry.Entry) api.Entry {
    return .{
        ._ptr = ent,
        ._allocator = cache.allocator,
        ._usecas = cache.usecas,
    };
}

fn createImpl(opts: api.Options) !*CacheImpl {
    const allocator = opts.allocator orelse std.heap.page_allocator;
    const shard_count = if (opts.nshards == 0) default_shards else @as(usize, opts.nshards);
    const loadfactor = clampLoadFactor(opts.loadfactor);

    const cache = try allocator.create(CacheImpl);
    errdefer allocator.destroy(cache);

    cache.* = .{
        .allocator = allocator,
        .yield = opts.yield,
        .udata = opts.udata,
        .usethreadbatch = opts.usethreadbatch,
        .usecas = opts.usecas,
        .nosixpack = opts.nosixpack,
        .noevict = opts.noevict,
        .allowshrink = opts.allowshrink,
        .nshards = shard_count,
        .loadfactor = loadfactor,
        .shrinkfactor = shrink_factor,
        .seed = opts.seed,
        .notify = opts.notify,
        .evicted = opts.evicted,
        .shards = &.{},
    };

    cache.shards = try allocator.alloc(shard_mod.Shard, shard_count);
    errdefer allocator.free(cache.shards);

    const map_opts = map.Options{
        .load_factor = loadfactor,
        .shrink_factor = shrink_factor,
        .allow_shrink = opts.allowshrink,
        .usecas = opts.usecas,
    };

    for (cache.shards, 0..) |*shard, i| {
        _ = i;
        shard.* = try shard_mod.Shard.init(allocator, init_cap, map_opts);
    }

    return cache;
}

fn destroyImpl(cache: *CacheImpl) void {
    for (cache.shards) |*shard| {
        shard.deinit();
    }
    cache.allocator.free(cache.shards);
    cache.allocator.destroy(cache);
}

fn storeImpl(cache: *CacheImpl, batch_ptr: ?*BatchImpl, key: []const u8, value: []const u8, opts: api.StoreOptions) !api.StoreResult {
    const now_time = if (opts.time > 0) opts.time else now();
    var expires: i64 = 0;
    if (opts.expires > 0) {
        expires = opts.expires;
    } else if (opts.ttl > 0) {
        expires = addClampI64(now_time, opts.ttl);
    }

    const fhash = hash.th64(key, cache.seed);
    const shard_idx = @as(usize, (fhash >> 32) % cache.nshards);
    const map_hash = @as(u32, @truncate(fhash));
    const shard = &cache.shards[shard_idx];

    lockShard(cache, batch_ptr, shard);
    defer unlockShard(batch_ptr, shard);

    if (opts.keepttl) {
        if (shard.map.lookup(key, map_hash)) |old_entry| {
            if (entry.isAlive(old_entry, now_time)) {
                expires = entry.expires(old_entry);
            }
        }
    }

    const count_before = shard.map.count;
    const cas = if (cache.usecas) blk: {
        if (opts.restore_cas and opts.cas != 0) {
            if (opts.cas > shard.cas) {
                shard.cas = opts.cas;
            }
            break :blk opts.cas;
        }
        break :blk shard.nextCas();
    } else 0;
    const entry_opts = entry.EntryOptions{
        .expires = expires,
        .flags = opts.flags,
        .cas = cas,
        .usecas = cache.usecas,
        .nosixpack = cache.nosixpack,
    };
    const new_entry = entry.create(cache.allocator, key, value, entry_opts) catch return error.OutOfMemory;
    entry.setTime(new_entry, now_time);

    if (opts.lowmem and cache.noevict) {
        entry.release(new_entry, cache.allocator);
        return error.OutOfMemory;
    }

    var old_entry = shard.map.insert(new_entry, map_hash) catch {
        entry.release(new_entry, cache.allocator);
        return error.OutOfMemory;
    };
    const inserted_new = old_entry == null;

    if (old_entry) |old| {
        if (!entry.isAlive(old, now_time)) {
            emitNotify(cache, shard_idx, .Expired, null, old, now_time);
            entry.release(old, cache.allocator);
            old_entry = null;
        }
    }

    var put_back_status: ?api.StoreResult = null;
    if (old_entry) |old| {
        if (opts.casop) {
            if (!cache.usecas or opts.cas != entry.cas(old, cache.usecas)) {
                put_back_status = .Found;
            }
        } else if (opts.nx) {
            put_back_status = .Found;
        }
    } else if (opts.xx or opts.casop) {
        if (shard.map.delete(key, map_hash)) |removed| {
            entry.release(removed, cache.allocator);
            if (inserted_new) {
                shard.map.total -= 1;
            }
        }
        return .NotFound;
    }

    if (put_back_status) |status| {
        const replaced = shard.map.insert(old_entry.?, map_hash) catch {
            entry.release(new_entry, cache.allocator);
            return error.OutOfMemory;
        };
        if (replaced) |replaced_entry| {
            std.debug.assert(replaced_entry == new_entry);
            entry.release(replaced_entry, cache.allocator);
        } else {
            entry.release(new_entry, cache.allocator);
        }
        return status;
    }

    if (old_entry) |old| {
        if (opts.entry) |entry_cb| {
            const val_slice = entry.value(old, cache.usecas);
            const oexpires = entry.expires(old);
            const oflags = entry.flags(old);
            const ocas = entry.cas(old, cache.usecas);
            if (!entry_cb(@as(u32, @intCast(shard_idx)), now_time, key, val_slice, oexpires, oflags, ocas, opts.udata)) {
                const replaced = shard.map.insert(old, map_hash) catch {
                    entry.release(new_entry, cache.allocator);
                    return error.OutOfMemory;
                };
                if (replaced) |replaced_entry| {
                    std.debug.assert(replaced_entry == new_entry);
                    entry.release(replaced_entry, cache.allocator);
                } else {
                    entry.release(new_entry, cache.allocator);
                }
                return .Canceled;
            }
        }
    }

    if (old_entry) |old| {
        emitNotify(cache, shard_idx, .Replaced, new_entry, old, now_time);
        entry.release(old, cache.allocator);
        return .Replaced;
    }

    if (opts.lowmem and shard.map.count > count_before) {
        autoEvictEntry(cache, shard, shard_idx, map_hash, now_time);
    }
    emitNotify(cache, shard_idx, .Inserted, new_entry, null, now_time);
    return .Inserted;
}

fn loadImpl(cache: *CacheImpl, batch_ptr: ?*BatchImpl, key: []const u8, opts: api.LoadOptions) !?api.Entry {
    const now_time = if (opts.time > 0) opts.time else now();

    const fhash = hash.th64(key, cache.seed);
    const shard_idx = @as(usize, (fhash >> 32) % cache.nshards);
    const map_hash = @as(u32, @truncate(fhash));
    const shard = &cache.shards[shard_idx];

    lockShard(cache, batch_ptr, shard);
    defer unlockShard(batch_ptr, shard);

    const current = shard.map.lookup(key, map_hash) orelse return null;
    if (!entry.isAlive(current, now_time)) {
        if (shard.map.delete(key, map_hash)) |removed| {
            emitNotify(cache, shard_idx, .Expired, null, removed, now_time);
            entry.release(removed, cache.allocator);
        }
        return null;
    }

    if (!opts.notouch) {
        entry.setTime(current, now_time);
    }

    var result_entry = current;
    if (opts.update) |update_cb| {
        var buf: [128]u8 = undefined;
        const key_slice = entry.key(current, cache.usecas, &buf);
        const value_slice = entry.value(current, cache.usecas);
        const expires = entry.expires(current);
        const flags = entry.flags(current);
        const cas_value = entry.cas(current, cache.usecas);
        const update = update_cb(@as(u32, @intCast(shard_idx)), now_time, key_slice, value_slice, expires, flags, cas_value, opts.udata);
        if (update) |upd| {
            const cas = shard.nextCas();
            const new_entry = entry.create(cache.allocator, key_slice, upd.value, .{
                .expires = upd.expires,
                .flags = upd.flags,
                .cas = cas,
                .usecas = cache.usecas,
                .nosixpack = cache.nosixpack,
            }) catch return error.OutOfMemory;
            entry.setTime(new_entry, now_time);
            const replaced = shard.map.insert(new_entry, map_hash) catch {
                entry.release(new_entry, cache.allocator);
                return error.OutOfMemory;
            };
            if (replaced) |old_entry| {
                emitNotify(cache, shard_idx, .Replaced, new_entry, old_entry, now_time);
                entry.release(old_entry, cache.allocator);
            }
            result_entry = new_entry;
        }
    }

    entry.retain(result_entry);
    return makeEntryHandle(cache, result_entry);
}

fn deleteImpl(cache: *CacheImpl, batch_ptr: ?*BatchImpl, key: []const u8, opts: api.DeleteOptions) api.DeleteResult {
    const now_time = if (opts.time > 0) opts.time else now();

    const fhash = hash.th64(key, cache.seed);
    const shard_idx = @as(usize, (fhash >> 32) % cache.nshards);
    const map_hash = @as(u32, @truncate(fhash));
    const shard = &cache.shards[shard_idx];

    lockShard(cache, batch_ptr, shard);
    defer unlockShard(batch_ptr, shard);

    const current = shard.map.delete(key, map_hash) orelse return .NotFound;
    if (!entry.isAlive(current, now_time)) {
        emitNotify(cache, shard_idx, .Expired, null, current, now_time);
        entry.release(current, cache.allocator);
        _ = shard.map.tryShrink() catch {};
        return .NotFound;
    }

    if (opts.entry) |entry_cb| {
        var buf: [128]u8 = undefined;
        const key_slice = entry.key(current, cache.usecas, &buf);
        const value_slice = entry.value(current, cache.usecas);
        const expires = entry.expires(current);
        const flags = entry.flags(current);
        const cas_value = entry.cas(current, cache.usecas);
        if (!entry_cb(@as(u32, @intCast(shard_idx)), now_time, key_slice, value_slice, expires, flags, cas_value, opts.udata)) {
            const replaced = shard.map.insert(current, map_hash) catch unreachable;
            if (replaced) |replaced_entry| {
                entry.release(replaced_entry, cache.allocator);
            }
            return .Canceled;
        }
    }

    emitNotify(cache, shard_idx, .Deleted, null, current, now_time);
    entry.release(current, cache.allocator);
    _ = shard.map.tryShrink() catch {};
    return .Deleted;
}

fn iterImpl(cache: *CacheImpl, batch_ptr: ?*BatchImpl, opts: api.IterOptions) api.IterResult {
    const now_time = if (opts.time > 0) opts.time else now();

    const shard_count = cache.nshards;
    if (opts.oneshard) {
        const idx = @as(usize, opts.oneshardidx);
        if (idx >= shard_count) {
            return .Finished;
        }
        return iterShard(cache, batch_ptr, opts, idx, now_time);
    }

    for (cache.shards, 0..) |_, idx| {
        const status = iterShard(cache, batch_ptr, opts, idx, now_time);
        if (status != .Finished) {
            return status;
        }
    }
    return .Finished;
}

fn entryIterImpl(cache: *CacheImpl, time_value: i64, cursor: *u64) ?*entry.Entry {
    const now_time = if (time_value > 0) time_value else now();
    var shard_idx: usize = @as(usize, @truncate(cursor.* >> 32));
    var bucket_iter: usize = @as(usize, @truncate(cursor.* & 0xffffffff));

    if (shard_idx >= cache.nshards) {
        cursor.* = 0;
        return null;
    }

    while (shard_idx < cache.nshards) {
        const shard = &cache.shards[shard_idx];
        shard.lockExclusive(cache.yield, cache.udata);
        defer shard.unlock();

        var i = bucket_iter;
        while (i < shard.map.nbuckets) : (i += 1) {
            const bkt = &shard.map.buckets[i];
            if (bkt.dib == 0) {
                continue;
            }
            const current = bucket.getPtr(entry.Entry, bkt).?;
            if (!entry.isAlive(current, now_time)) {
                const removed = shard.map.deleteBucket(i);
                emitNotify(cache, shard_idx, .Expired, null, removed, now_time);
                entry.release(removed, cache.allocator);
                if (i > 0) i -= 1;
                continue;
            }
            entry.retain(current);
            cursor.* = (@as(u64, shard_idx) << 32) | @as(u64, i + 1);
            return current;
        }

        shard_idx += 1;
        bucket_iter = 0;
    }

    cursor.* = 0;
    return null;
}

fn sweepImpl(cache: *CacheImpl, batch_ptr: ?*BatchImpl, swept: ?*usize, kept: ?*usize, opts: api.SweepOptions) void {
    const now_time = if (opts.time > 0) opts.time else now();

    var swept_count: usize = 0;
    var kept_count: usize = 0;

    if (opts.oneshard) {
        const idx = @as(usize, opts.oneshardidx);
        if (idx < cache.nshards) {
            sweepShard(cache, batch_ptr, idx, now_time, &swept_count, &kept_count);
        }
    } else {
        for (cache.shards, 0..) |_, idx| {
            var swept_local: usize = 0;
            var kept_local: usize = 0;
            sweepShard(cache, batch_ptr, idx, now_time, &swept_local, &kept_local);
            swept_count += swept_local;
            kept_count += kept_local;
        }
    }

    if (swept) |ptr| {
        ptr.* = swept_count;
    }
    if (kept) |ptr| {
        ptr.* = kept_count;
    }
}

fn sweepPollImpl(cache: *CacheImpl, batch_ptr: ?*BatchImpl, opts: api.SweepPollOptions) f64 {
    const now_time = if (opts.time > 0) opts.time else now();
    const pollsize = if (opts.pollsize == 0) 20 else opts.pollsize;

    if (cache.nshards == 0) {
        return 0;
    }

    const shard_idx = @as(usize, hash.mix13(@as(u64, @intCast(now_time))) % cache.nshards);
    const shard = &cache.shards[shard_idx];

    lockShard(cache, batch_ptr, shard);
    defer unlockShard(batch_ptr, shard);

    if (shard.map.nbuckets == 0) {
        return 0;
    }

    const start = @as(usize, hash.mix13(@as(u64, @intCast(now_time + @as(i64, @intCast(shard_idx))))) % shard.map.nbuckets);
    var sampled: usize = 0;
    var dead: usize = 0;

    var i: usize = 0;
    while (i < shard.map.nbuckets and sampled < pollsize) : (i += 1) {
        const idx = (start + i) % shard.map.nbuckets;
        const bkt = &shard.map.buckets[idx];
        if (bkt.dib == 0) {
            continue;
        }
        const current = bucket.getPtr(entry.Entry, bkt).?;
        sampled += 1;
        if (!entry.isAlive(current, now_time)) {
            dead += 1;
        }
    }

    if (sampled == 0) return 0;
    return @as(f64, @floatFromInt(dead)) / @as(f64, @floatFromInt(sampled));
}

fn clearImpl(cache: *CacheImpl, batch_ptr: ?*BatchImpl, opts: api.ClearOptions) void {
    const now_time = if (opts.time > 0) opts.time else now();

    if (opts.oneshard) {
        const idx = @as(usize, opts.oneshardidx);
        if (idx >= cache.nshards) {
            return;
        }
        clearShard(cache, batch_ptr, idx, now_time, opts.deferfree);
        return;
    }

    for (cache.shards, 0..) |*shard, idx| {
        _ = shard;
        clearShard(cache, batch_ptr, idx, now_time, opts.deferfree);
    }
}

fn countImpl(cache: *CacheImpl, batch_ptr: ?*BatchImpl, opts: api.CountOptions) usize {
    if (opts.oneshard) {
        const idx = @as(usize, opts.oneshardidx);
        if (idx >= cache.nshards) {
            return 0;
        }
        const shard = &cache.shards[idx];
        lockShard(cache, batch_ptr, shard);
        defer unlockShard(batch_ptr, shard);
        return shard.map.count;
    }

    var total_count: usize = 0;
    for (cache.shards, 0..) |*shard, idx| {
        _ = idx;
        lockShard(cache, batch_ptr, shard);
        total_count += shard.map.count;
        unlockShard(batch_ptr, shard);
    }
    return total_count;
}

fn totalImpl(cache: *CacheImpl, batch_ptr: ?*BatchImpl, opts: api.TotalOptions) u64 {
    if (opts.oneshard) {
        const idx = @as(usize, opts.oneshardidx);
        if (idx >= cache.nshards) {
            return 0;
        }
        const shard = &cache.shards[idx];
        lockShard(cache, batch_ptr, shard);
        defer unlockShard(batch_ptr, shard);
        return shard.map.total;
    }

    var total_count: u64 = 0;
    for (cache.shards, 0..) |*shard, idx| {
        _ = idx;
        lockShard(cache, batch_ptr, shard);
        total_count += shard.map.total;
        unlockShard(batch_ptr, shard);
    }
    return total_count;
}

fn sizeImpl(cache: *CacheImpl, batch_ptr: ?*BatchImpl, opts: api.SizeOptions) usize {
    if (opts.oneshard) {
        const idx = @as(usize, opts.oneshardidx);
        if (idx >= cache.nshards) {
            return 0;
        }
        const shard = &cache.shards[idx];
        lockShard(cache, batch_ptr, shard);
        defer unlockShard(batch_ptr, shard);
        return shardSize(shard, opts.entriesonly);
    }

    var total_size: usize = 0;
    for (cache.shards, 0..) |*shard, idx| {
        _ = idx;
        lockShard(cache, batch_ptr, shard);
        total_size += shardSize(shard, opts.entriesonly);
        unlockShard(batch_ptr, shard);
    }
    return total_size;
}

fn iterShard(cache: *CacheImpl, batch_ptr: ?*BatchImpl, opts: api.IterOptions, shard_idx: usize, now_time: i64) api.IterResult {
    const shard = &cache.shards[shard_idx];
    lockShard(cache, batch_ptr, shard);
    defer unlockShard(batch_ptr, shard);

    var status: api.IterResult = .Finished;
    var i: usize = 0;
    while (i < shard.map.nbuckets) : (i += 1) {
        const bkt = &shard.map.buckets[i];
        if (bkt.dib == 0) {
            continue;
        }
        const current = bucket.getPtr(entry.Entry, bkt).?;
        if (!entry.isAlive(current, now_time)) {
            const removed = shard.map.deleteBucket(i);
            emitNotify(cache, shard_idx, .Expired, null, removed, now_time);
            entry.release(removed, cache.allocator);
            if (i > 0) i -= 1;
            continue;
        }

        var action: api.IterAction = .Continue;
        if (opts.entry) |entry_cb| {
            var buf: [128]u8 = undefined;
            const key_slice = entry.key(current, cache.usecas, &buf);
            const value_slice = entry.value(current, cache.usecas);
            const expires = entry.expires(current);
            const flags = entry.flags(current);
            const cas_value = entry.cas(current, cache.usecas);
            action = entry_cb(@as(u32, @intCast(shard_idx)), now_time, key_slice, value_slice, expires, flags, cas_value, opts.udata);
        }

        if (action.delete) {
            const removed = shard.map.deleteBucket(i);
            emitNotify(cache, shard_idx, .Deleted, null, removed, now_time);
            entry.release(removed, cache.allocator);
            if (i > 0) i -= 1;
        }
        if (action.stop) {
            status = .Canceled;
            break;
        }
    }

    _ = shard.map.tryShrink() catch {};
    return status;
}

fn sweepShard(cache: *CacheImpl, batch_ptr: ?*BatchImpl, shard_idx: usize, now_time: i64, swept: *usize, kept: *usize) void {
    const shard = &cache.shards[shard_idx];
    lockShard(cache, batch_ptr, shard);
    defer unlockShard(batch_ptr, shard);

    var i: usize = 0;
    while (i < shard.map.nbuckets) : (i += 1) {
        const bkt = &shard.map.buckets[i];
        if (bkt.dib == 0) {
            continue;
        }
        const current = bucket.getPtr(entry.Entry, bkt).?;
        if (entry.isAlive(current, now_time)) {
            kept.* += 1;
            continue;
        }
        const removed = shard.map.deleteBucket(i);
        emitNotify(cache, shard_idx, .Expired, null, removed, now_time);
        entry.release(removed, cache.allocator);
        swept.* += 1;
        if (i > 0) i -= 1;
    }

    _ = shard.map.tryShrink() catch {};
}

fn clearShard(cache: *CacheImpl, batch_ptr: ?*BatchImpl, shard_idx: usize, now_time: i64, deferfree: bool) void {
    const shard = &cache.shards[shard_idx];
    lockShard(cache, batch_ptr, shard);
    const use_defer = deferfree and batch_ptr == null;

    for (shard.map.buckets) |bkt| {
        if (bkt.dib == 0) continue;
        const current = bucket.getPtr(entry.Entry, &bkt).?;
        const kind: NotifyKind = if (entry.isAlive(current, now_time)) .Cleared else .Expired;
        emitNotify(cache, shard_idx, kind, null, current, now_time);
        if (!use_defer) {
            entry.release(current, cache.allocator);
        }
    }

    const old_total = shard.map.total;
    const map_opts = map.Options{
        .load_factor = cache.loadfactor,
        .shrink_factor = cache.shrinkfactor,
        .allow_shrink = cache.allowshrink,
        .usecas = cache.usecas,
    };

    var new_map = map.Map.init(cache.allocator, init_cap, map_opts) catch {
        if (use_defer) {
            for (shard.map.buckets) |bkt| {
                if (bkt.dib == 0) continue;
                if (bucket.getPtr(entry.Entry, &bkt)) |current| {
                    entry.release(current, cache.allocator);
                }
            }
        }
        for (shard.map.buckets) |*bkt| {
            bkt.* = bucket.init();
        }
        shard.map.count = 0;
        shard.map.entsize = 0;
        unlockShard(batch_ptr, shard);
        return;
    };
    new_map.total = old_total;

    if (use_defer) {
        const old_buckets = shard.map.buckets;
        shard.map = new_map;
        unlockShard(batch_ptr, shard);
        for (old_buckets) |bkt| {
            if (bkt.dib == 0) continue;
            if (bucket.getPtr(entry.Entry, &bkt)) |current| {
                entry.release(current, cache.allocator);
            }
        }
        cache.allocator.free(old_buckets);
        return;
    }

    cache.allocator.free(shard.map.buckets);
    shard.map = new_map;
    unlockShard(batch_ptr, shard);
}

fn shardSize(shard: *const shard_mod.Shard, entriesonly: bool) usize {
    var total_size: usize = 0;
    if (!entriesonly) {
        total_size += @sizeOf(shard_mod.Shard);
        total_size += @sizeOf(bucket.Bucket) * shard.map.nbuckets;
    }
    total_size += shard.map.entsize;
    return total_size;
}

fn emitNotify(cache: *CacheImpl, shard_idx: usize, kind: NotifyKind, new_entry: ?*entry.Entry, old_entry: ?*entry.Entry, now_time: i64) void {
    if (cache.notify) |cb| {
        const new_ptr: ?*api.Entry = if (new_entry) |ent| @ptrCast(ent) else null;
        const old_ptr: ?*api.Entry = if (old_entry) |ent| @ptrCast(ent) else null;
        cb(@as(u32, @intCast(shard_idx)), now_time, new_ptr, old_ptr, cache.udata);
    }

    const reason: ?api.EvictReason = switch (kind) {
        .Expired => api.EvictReason.Expired,
        .Cleared => api.EvictReason.Cleared,
        .LowMem => api.EvictReason.LowMem,
        else => null,
    };

    if (reason) |evict_reason| {
        if (cache.evicted) |cb| {
            if (old_entry) |old| {
                var buf: [128]u8 = undefined;
                const key_slice = entry.key(old, cache.usecas, &buf);
                const value_slice = entry.value(old, cache.usecas);
                const expires = entry.expires(old);
                const flags = entry.flags(old);
                const cas_value = entry.cas(old, cache.usecas);
                cb(@as(u32, @intCast(shard_idx)), evict_reason, now_time, key_slice, value_slice, expires, flags, cas_value, cache.udata);
            }
        }
    }
}

fn autoEvictEntry(cache: *CacheImpl, shard: *shard_mod.Shard, shard_idx: usize, hash_value: u32, now_time: i64) void {
    const clipped = bucket.clipHash(hash_value);
    var entries: [2]*entry.Entry = undefined;
    var candidate_count: usize = 0;
    var i: usize = 1;
    while (i < shard.map.nbuckets and candidate_count < 2) : (i += 1) {
        const idx = (i + clipped) & (shard.map.nbuckets - 1);
        const bkt = &shard.map.buckets[idx];
        if (bkt.dib == 0 or bucket.readHash(bkt) == clipped) {
            continue;
        }
        const current = bucket.getPtr(entry.Entry, bkt).?;
        if (!entry.isAlive(current, now_time)) {
            evictEntry(cache, shard, shard_idx, current, now_time, .Expired);
            return;
        }
        entries[candidate_count] = current;
        candidate_count += 1;
    }

    if (candidate_count == 0) return;
    var chosen = entries[0];
    if (candidate_count == 2 and entry.time(entries[1]) < entry.time(entries[0])) {
        chosen = entries[1];
    }
    evictEntry(cache, shard, shard_idx, chosen, now_time, .LowMem);
}

fn evictEntry(cache: *CacheImpl, shard: *shard_mod.Shard, shard_idx: usize, victim: *entry.Entry, now_time: i64, kind: NotifyKind) void {
    var buf: [128]u8 = undefined;
    const key_slice = entry.key(victim, cache.usecas, &buf);
    const fhash = hash.th64(key_slice, cache.seed);
    const map_hash = @as(u32, @truncate(fhash));
    const removed = shard.map.delete(key_slice, map_hash) orelse return;
    emitNotify(cache, shard_idx, kind, null, removed, now_time);
    entry.release(removed, cache.allocator);
}

fn lockShard(cache: *CacheImpl, batch_ptr: ?*BatchImpl, shard: *shard_mod.Shard) void {
    batch.lock(batch_ptr, shard, cache.yield, cache.udata);
}

fn unlockShard(batch_ptr: ?*BatchImpl, shard: *shard_mod.Shard) void {
    if (batch_ptr == null) {
        shard.unlock();
    }
}

fn cacheImpl(cache_ptr: *api.Cache) *CacheImpl {
    return @ptrCast(@alignCast(cache_ptr));
}

fn batchImpl(batch_ptr: *api.Batch) *BatchImpl {
    return @ptrCast(@alignCast(batch_ptr));
}

fn clampLoadFactor(value: u8) u8 {
    if (value == 0) return default_loadfactor;
    if (value < min_loadfactor) return min_loadfactor;
    if (value > max_loadfactor) return max_loadfactor;
    return value;
}

fn addClampI64(a: i64, b: i64) i64 {
    if (!((a ^ b) < 0)) {
        if (a > 0 and b > std.math.maxInt(i64) - a) {
            return std.math.maxInt(i64);
        }
        if (a < 0 and b < std.math.minInt(i64) - a) {
            return std.math.minInt(i64);
        }
    }
    return a + b;
}

fn updateToValue(
    shard: u32,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) ?api.Update {
    _ = shard;
    _ = time;
    _ = key;
    _ = value;
    _ = cas;
    _ = udata;
    return .{
        .value = "v2",
        .flags = flags,
        .expires = expires,
    };
}

const EvictCapture = struct {
    expected_expired: ?[]const u8 = null,
    expected_lowmem: ?[]const u8 = null,
    expected_cleared: ?[]const u8 = null,
    expired: usize = 0,
    lowmem: usize = 0,
    cleared: usize = 0,
    expired_key_match: bool = true,
    lowmem_key_match: bool = true,
    cleared_key_match: bool = true,
};

fn captureEvicted(
    shard: u32,
    reason: api.EvictReason,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) void {
    _ = shard;
    _ = time;
    _ = value;
    _ = expires;
    _ = flags;
    _ = cas;
    const capture = @as(*EvictCapture, @ptrCast(@alignCast(udata.?)));
    switch (reason) {
        .Expired => {
            capture.expired += 1;
            if (capture.expected_expired) |expected| {
                if (!std.mem.eql(u8, key, expected)) {
                    capture.expired_key_match = false;
                }
            }
        },
        .LowMem => {
            capture.lowmem += 1;
            if (capture.expected_lowmem) |expected| {
                if (!std.mem.eql(u8, key, expected)) {
                    capture.lowmem_key_match = false;
                }
            }
        },
        .Cleared => {
            capture.cleared += 1;
            if (capture.expected_cleared) |expected| {
                if (!std.mem.eql(u8, key, expected)) {
                    capture.cleared_key_match = false;
                }
            }
        },
    }
}

fn fillDistinctKeys(seed: u64, bufs: *[3][32]u8, keys: *[3][]const u8, clipped: *[3]u32) void {
    var idx: usize = 0;
    var i: usize = 0;
    while (idx < 3 and i < 10_000) : (i += 1) {
        const key = std.fmt.bufPrint(&bufs[idx], "key-{d}", .{i}) catch unreachable;
        const fhash = hash.th64(key, seed);
        const clip = bucket.clipHash(@as(u32, @truncate(fhash)));
        var distinct = true;
        var j: usize = 0;
        while (j < idx) : (j += 1) {
            if (clipped[j] == clip) {
                distinct = false;
                break;
            }
        }
        if (!distinct) continue;
        keys[idx] = key;
        clipped[idx] = clip;
        idx += 1;
    }
    std.debug.assert(idx == 3);
}

test "store cas and nx/xx behavior" {
    const allocator = std.testing.allocator;
    const cache = try init(.{
        .allocator = allocator,
        .nshards = 1,
        .usecas = true,
    });
    defer deinit(cache);

    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "key", "v1", .{}));
    try std.testing.expectEqual(@as(u64, 1), total(cache, .{}));

    const first_entry = (try load(cache, "key", .{})) orelse {
        try std.testing.expect(false);
        return;
    };
    defer first_entry.release();
    const cas_value = first_entry.cas();
    try std.testing.expect(cas_value != 0);
    try std.testing.expectEqual(@as(i64, 0), first_entry.expires());
    try std.testing.expectEqualStrings("v1", first_entry.value());

    var store_opts = api.StoreOptions{
        .casop = true,
        .cas = cas_value + 1,
    };
    try std.testing.expectEqual(api.StoreResult.Found, try store(cache, "key", "v2", store_opts));
    const entry_after_fail = (try load(cache, "key", .{})) orelse {
        try std.testing.expect(false);
        return;
    };
    defer entry_after_fail.release();
    try std.testing.expectEqualStrings("v1", entry_after_fail.value());

    store_opts.cas = cas_value;
    try std.testing.expectEqual(api.StoreResult.Replaced, try store(cache, "key", "v2", store_opts));
    const entry_after_replace = (try load(cache, "key", .{})) orelse {
        try std.testing.expect(false);
        return;
    };
    defer entry_after_replace.release();
    try std.testing.expectEqualStrings("v2", entry_after_replace.value());

    try std.testing.expectEqual(api.StoreResult.NotFound, try store(cache, "missing", "v", store_opts));
    try std.testing.expectEqual(@as(u64, 1), total(cache, .{}));

    const nx_opts = api.StoreOptions{
        .nx = true,
    };
    try std.testing.expectEqual(api.StoreResult.Found, try store(cache, "key", "v3", nx_opts));
    const entry_after_nx = (try load(cache, "key", .{})) orelse {
        try std.testing.expect(false);
        return;
    };
    defer entry_after_nx.release();
    try std.testing.expectEqualStrings("v2", entry_after_nx.value());

    const xx_opts = api.StoreOptions{
        .xx = true,
    };
    try std.testing.expectEqual(api.StoreResult.NotFound, try store(cache, "missing2", "v", xx_opts));
    try std.testing.expectEqual(@as(u64, 1), total(cache, .{}));
    try std.testing.expectEqual(api.StoreResult.Replaced, try store(cache, "key", "v4", xx_opts));
    const entry_after_xx = (try load(cache, "key", .{})) orelse {
        try std.testing.expect(false);
        return;
    };
    defer entry_after_xx.release();
    try std.testing.expectEqualStrings("v4", entry_after_xx.value());
}

test "total counts only new inserts" {
    const allocator = std.testing.allocator;
    const cache = try init(.{
        .allocator = allocator,
        .nshards = 1,
        .usecas = true,
    });
    defer deinit(cache);

    try std.testing.expectEqual(@as(u64, 0), total(cache, .{}));

    const xx_opts = api.StoreOptions{
        .xx = true,
    };
    try std.testing.expectEqual(api.StoreResult.NotFound, try store(cache, "missing", "v", xx_opts));
    try std.testing.expectEqual(@as(u64, 0), total(cache, .{}));

    var cas_opts = api.StoreOptions{
        .casop = true,
        .cas = 123,
    };
    try std.testing.expectEqual(api.StoreResult.NotFound, try store(cache, "missing2", "v", cas_opts));
    try std.testing.expectEqual(@as(u64, 0), total(cache, .{}));

    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "key", "v1", .{}));
    try std.testing.expectEqual(@as(u64, 1), total(cache, .{}));

    const loaded_entry = (try load(cache, "key", .{})) orelse {
        try std.testing.expect(false);
        return;
    };
    defer loaded_entry.release();
    const cas_value = loaded_entry.cas();

    cas_opts = api.StoreOptions{
        .casop = true,
        .cas = cas_value + 1,
    };
    try std.testing.expectEqual(api.StoreResult.Found, try store(cache, "key", "v2", cas_opts));
    try std.testing.expectEqual(@as(u64, 1), total(cache, .{}));

    const nx_opts = api.StoreOptions{
        .nx = true,
    };
    try std.testing.expectEqual(api.StoreResult.Found, try store(cache, "key", "v3", nx_opts));
    try std.testing.expectEqual(@as(u64, 1), total(cache, .{}));

    try std.testing.expectEqual(api.StoreResult.Replaced, try store(cache, "key", "v4", xx_opts));
    try std.testing.expectEqual(@as(u64, 1), total(cache, .{}));

    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "key2", "v", .{}));
    try std.testing.expectEqual(@as(u64, 2), total(cache, .{}));
}

test "store keepttl preserves expires" {
    const cache = try init(.{
        .allocator = std.testing.allocator,
        .nshards = 1,
    });
    defer deinit(cache);

    var store_opts = api.StoreOptions{
        .time = 10,
        .expires = 50,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "key", "v1", store_opts));

    store_opts = api.StoreOptions{
        .time = 20,
        .expires = 100,
        .keepttl = true,
    };
    try std.testing.expectEqual(api.StoreResult.Replaced, try store(cache, "key", "v2", store_opts));

    const entry_handle = (try load(cache, "key", .{ .time = 20 })) orelse {
        try std.testing.expect(false);
        return;
    };
    defer entry_handle.release();
    try std.testing.expectEqual(@as(i64, 50), entry_handle.expires());
    try std.testing.expectEqualStrings("v2", entry_handle.value());
}

test "load notouch preserves time" {
    const cache = try init(.{
        .allocator = std.testing.allocator,
        .nshards = 1,
    });
    defer deinit(cache);

    const store_opts = api.StoreOptions{
        .time = 100,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "key", "v", store_opts));

    var load_opts = api.LoadOptions{
        .time = 200,
        .notouch = true,
    };
    const found_before_touch = try load(cache, "key", load_opts);
    try std.testing.expect(found_before_touch != null);
    if (found_before_touch) |found_entry| {
        found_entry.release();
    }

    var cursor: u64 = 0;
    const entry_handle = entryIter(cache, 0, &cursor).?;
    defer entry_handle.release();
    try std.testing.expectEqual(@as(i64, 100), entry_handle.time());

    load_opts = api.LoadOptions{
        .time = 300,
        .notouch = false,
    };
    const found_after_touch = try load(cache, "key", load_opts);
    try std.testing.expect(found_after_touch != null);
    if (found_after_touch) |found_entry| {
        found_entry.release();
    }

    cursor = 0;
    const entry_handle2 = entryIter(cache, 0, &cursor).?;
    defer entry_handle2.release();
    try std.testing.expectEqual(@as(i64, 300), entry_handle2.time());
}

test "load update replaces value" {
    const cache = try init(.{
        .allocator = std.testing.allocator,
        .nshards = 1,
        .usecas = true,
    });
    defer deinit(cache);

    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "key", "v1", .{}));

    const updated = try load(cache, "key", .{ .update = updateToValue });
    try std.testing.expect(updated != null);
    if (updated) |entry_handle| {
        defer entry_handle.release();
        try std.testing.expectEqualStrings("v2", entry_handle.value());
    }

    const again = (try load(cache, "key", .{})) orelse {
        try std.testing.expect(false);
        return;
    };
    defer again.release();
    try std.testing.expectEqualStrings("v2", again.value());
}

test "entry helpers and nshards" {
    const cache = try init(.{
        .allocator = std.testing.allocator,
        .nshards = 2,
        .usecas = true,
    });
    defer deinit(cache);

    try std.testing.expectEqual(@as(u32, 2), nshards(cache));
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "alpha", "one", .{}));

    var cursor: u64 = 0;
    const entry_handle = entryIter(cache, 0, &cursor).?;
    defer entry_handle.release();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("alpha", entry_handle.key(&buf));
    try std.testing.expectEqualStrings("one", entry_handle.value());

    entry_handle.retain();
    entry_handle.release();

    const loaded = (try load(cache, "alpha", .{})) orelse {
        try std.testing.expect(false);
        return;
    };
    defer loaded.release();
}

test "expired entries are removed on load" {
    var capture = EvictCapture{
        .expected_expired = "key",
    };
    const cache = try init(.{
        .allocator = std.testing.allocator,
        .nshards = 1,
        .evicted = captureEvicted,
        .udata = &capture,
    });
    defer deinit(cache);

    const store_opts = api.StoreOptions{
        .time = 10,
        .expires = 20,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "key", "v", store_opts));

    const load_opts = api.LoadOptions{
        .time = 30,
    };
    try std.testing.expect((try load(cache, "key", load_opts)) == null);
    try std.testing.expectEqual(@as(usize, 0), count(cache, .{}));
    try std.testing.expectEqual(@as(usize, 1), capture.expired);
    try std.testing.expect(capture.expired_key_match);
}

test "sweep removes expired entries and counts kept" {
    var capture = EvictCapture{
        .expected_expired = "dead",
    };
    const cache = try init(.{
        .allocator = std.testing.allocator,
        .nshards = 1,
        .evicted = captureEvicted,
        .udata = &capture,
    });
    defer deinit(cache);

    var store_opts = api.StoreOptions{
        .time = 10,
        .expires = 15,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "dead", "v1", store_opts));

    store_opts = api.StoreOptions{
        .time = 10,
        .expires = 0,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "live", "v2", store_opts));

    var swept: usize = 0;
    var kept: usize = 0;
    const sweep_opts = api.SweepOptions{
        .time = 20,
    };
    sweep(cache, &swept, &kept, sweep_opts);

    try std.testing.expectEqual(@as(usize, 1), swept);
    try std.testing.expectEqual(@as(usize, 1), kept);
    try std.testing.expectEqual(@as(usize, 1), count(cache, .{}));
    try std.testing.expectEqual(@as(usize, 1), capture.expired);
    try std.testing.expect(capture.expired_key_match);
}

test "clear removes entries with expected reasons" {
    var capture = EvictCapture{
        .expected_expired = "dead",
        .expected_cleared = "live",
    };
    const cache = try init(.{
        .allocator = std.testing.allocator,
        .nshards = 1,
        .evicted = captureEvicted,
        .udata = &capture,
    });
    defer deinit(cache);

    var store_opts = api.StoreOptions{
        .time = 10,
        .expires = 15,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "dead", "v1", store_opts));

    store_opts = api.StoreOptions{
        .time = 10,
        .expires = 0,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, "live", "v2", store_opts));

    const clear_opts = api.ClearOptions{
        .time = 20,
    };
    clear(cache, clear_opts);

    try std.testing.expectEqual(@as(usize, 0), count(cache, .{}));
    try std.testing.expectEqual(@as(usize, 1), capture.expired);
    try std.testing.expectEqual(@as(usize, 1), capture.cleared);
    try std.testing.expect(capture.expired_key_match);
    try std.testing.expect(capture.cleared_key_match);
}

test "eviction prefers expired entry when sampled" {
    var key_bufs: [3][32]u8 = undefined;
    var keys: [3][]const u8 = undefined;
    var clips: [3]u32 = undefined;
    fillDistinctKeys(0, &key_bufs, &keys, &clips);
    try std.testing.expect(clips[0] != clips[1] and clips[0] != clips[2] and clips[1] != clips[2]);

    var capture = EvictCapture{
        .expected_expired = keys[0],
    };
    const cache = try init(.{
        .allocator = std.testing.allocator,
        .nshards = 1,
        .evicted = captureEvicted,
        .udata = &capture,
    });
    defer deinit(cache);

    var store_opts = api.StoreOptions{
        .time = 10,
        .expires = 15,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, keys[0], "v1", store_opts));

    store_opts = api.StoreOptions{
        .time = 12,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, keys[1], "v2", store_opts));

    store_opts = api.StoreOptions{
        .time = 30,
        .lowmem = true,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, keys[2], "v3", store_opts));

    try std.testing.expectEqual(@as(usize, 1), capture.expired);
    try std.testing.expect(capture.expired_key_match);
    try std.testing.expectEqual(@as(usize, 2), count(cache, .{}));
    try std.testing.expect((try load(cache, keys[0], .{})) == null);
    const found_lowmem = try load(cache, keys[1], .{});
    try std.testing.expect(found_lowmem != null);
    if (found_lowmem) |entry_handle| {
        entry_handle.release();
    }
}

test "eviction chooses oldest of two when no expired" {
    var key_bufs: [3][32]u8 = undefined;
    var keys: [3][]const u8 = undefined;
    var clips: [3]u32 = undefined;
    fillDistinctKeys(0, &key_bufs, &keys, &clips);
    try std.testing.expect(clips[0] != clips[1] and clips[0] != clips[2] and clips[1] != clips[2]);

    var capture = EvictCapture{
        .expected_lowmem = keys[0],
    };
    const cache = try init(.{
        .allocator = std.testing.allocator,
        .nshards = 1,
        .evicted = captureEvicted,
        .udata = &capture,
    });
    defer deinit(cache);

    var store_opts = api.StoreOptions{
        .time = 10,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, keys[0], "v1", store_opts));

    store_opts = api.StoreOptions{
        .time = 20,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, keys[1], "v2", store_opts));

    store_opts = api.StoreOptions{
        .time = 30,
        .lowmem = true,
    };
    try std.testing.expectEqual(api.StoreResult.Inserted, try store(cache, keys[2], "v3", store_opts));

    try std.testing.expectEqual(@as(usize, 1), capture.lowmem);
    try std.testing.expect(capture.lowmem_key_match);
    try std.testing.expectEqual(@as(usize, 2), count(cache, .{}));
    try std.testing.expect((try load(cache, keys[0], .{})) == null);
    const found_lowmem2 = try load(cache, keys[1], .{});
    try std.testing.expect(found_lowmem2 != null);
    if (found_lowmem2) |entry_handle| {
        entry_handle.release();
    }
}
