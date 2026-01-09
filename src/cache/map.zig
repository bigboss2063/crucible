const std = @import("std");
const bucket = @import("bucket.zig");
const entry = @import("entry.zig");

pub const MapError = error{
    InvalidCapacity,
    NoMem,
};

pub const Options = struct {
    load_factor: u8 = 75,
    shrink_factor: u8 = 10,
    allow_shrink: bool = false,
    usecas: bool = false,
};

pub const Map = struct {
    allocator: std.mem.Allocator,
    cap: usize,
    nbuckets: usize,
    count: usize,
    mask: usize,
    grow_at: usize,
    shrink_at: usize,
    buckets: []bucket.Bucket,
    total: u64,
    entsize: usize,
    load_factor: f64,
    shrink_factor: f64,
    allow_shrink: bool,
    usecas: bool,

    pub fn init(allocator: std.mem.Allocator, cap: usize, opts: Options) MapError!Map {
        if (cap == 0 or (cap & (cap - 1)) != 0) {
            return MapError.InvalidCapacity;
        }

        var map = Map{
            .allocator = allocator,
            .cap = cap,
            .nbuckets = cap,
            .count = 0,
            .mask = cap - 1,
            .grow_at = 0,
            .shrink_at = 0,
            .buckets = &.{},
            .total = 0,
            .entsize = 0,
            .load_factor = @as(f64, @floatFromInt(opts.load_factor)) / 100.0,
            .shrink_factor = @as(f64, @floatFromInt(opts.shrink_factor)) / 100.0,
            .allow_shrink = opts.allow_shrink,
            .usecas = opts.usecas,
        };

        map.grow_at = @as(usize, @intFromFloat(@as(f64, @floatFromInt(map.nbuckets)) * map.load_factor));
        map.shrink_at = @as(usize, @intFromFloat(@as(f64, @floatFromInt(map.nbuckets)) * map.shrink_factor));

        map.buckets = allocator.alloc(bucket.Bucket, map.nbuckets) catch return MapError.NoMem;
        for (map.buckets) |*bkt| {
            bkt.* = bucket.init();
        }

        return map;
    }

    pub fn deinit(self: *Map) void {
        if (self.buckets.len > 0) {
            self.allocator.free(self.buckets);
            self.buckets = &.{};
        }
    }

    pub fn insert(self: *Map, entry_ptr: *entry.Entry, hash: u32) MapError!?*entry.Entry {
        if (self.count >= self.grow_at) {
            try self.resize(self.nbuckets * 2);
        }

        self.entsize += entry.memSize(entry_ptr);

        var ebkt = bucket.init();
        bucket.setPtr(entry.Entry, &ebkt, entry_ptr);
        bucket.writeHash(&ebkt, hash);
        ebkt.dib = 1;

        var idx = @as(usize, bucket.readHash(&ebkt)) & self.mask;
        while (true) {
            const current = &self.buckets[idx];
            if (current.dib == 0) {
                current.* = ebkt;
                self.count += 1;
                self.total += 1;
                return null;
            }

            if (bucket.readHash(current) == bucket.readHash(&ebkt) and
                entryEqual(entry_ptr, bucket.getPtr(entry.Entry, current).?, self.usecas))
            {
                const old = bucket.getPtr(entry.Entry, current).?;
                self.entsize -= entry.memSize(old);
                bucket.setPtr(entry.Entry, current, entry_ptr);
                return old;
            }

            if (current.dib < ebkt.dib) {
                const tmp = current.*;
                current.* = ebkt;
                ebkt = tmp;
            }

            idx = (idx + 1) & self.mask;
            ebkt.dib +%= 1;
        }
    }

    pub fn lookup(self: *const Map, key: []const u8, hash: u32) ?*entry.Entry {
        const idx = self.findBucket(key, hash) orelse return null;
        return bucket.getPtr(entry.Entry, &self.buckets[idx]).?;
    }

    pub fn delete(self: *Map, key: []const u8, hash: u32) ?*entry.Entry {
        const idx = self.findBucket(key, hash) orelse return null;
        return self.deleteBucket(idx);
    }

    pub fn tryShrink(self: *Map) MapError!void {
        if (!self.allow_shrink or self.nbuckets <= self.cap or self.count > self.shrink_at) {
            return;
        }

        var desired = self.cap;
        var grow_at: usize = @as(usize, @intFromFloat(@as(f64, @floatFromInt(desired)) * self.load_factor));
        while (self.count >= grow_at) {
            desired *= 2;
            grow_at = @as(usize, @intFromFloat(@as(f64, @floatFromInt(desired)) * self.load_factor));
        }

        if (desired < self.nbuckets) {
            try self.resize(desired);
        }
    }

    fn resize(self: *Map, new_cap: usize) MapError!void {
        var new_buckets = self.allocator.alloc(bucket.Bucket, new_cap) catch return MapError.NoMem;
        for (new_buckets) |*bkt| {
            bkt.* = bucket.init();
        }
        const new_mask = new_cap - 1;

        for (self.buckets) |old_bucket| {
            if (old_bucket.dib == 0) continue;
            var ebkt = old_bucket;
            ebkt.dib = 1;
            var idx = @as(usize, bucket.readHash(&ebkt)) & new_mask;
            while (true) {
                if (new_buckets[idx].dib == 0) {
                    new_buckets[idx] = ebkt;
                    break;
                }
                if (new_buckets[idx].dib < ebkt.dib) {
                    const tmp = new_buckets[idx];
                    new_buckets[idx] = ebkt;
                    ebkt = tmp;
                }
                idx = (idx + 1) & new_mask;
                ebkt.dib +%= 1;
            }
        }

        self.allocator.free(self.buckets);
        self.buckets = new_buckets;
        self.nbuckets = new_cap;
        self.mask = new_mask;
        self.grow_at = @as(usize, @intFromFloat(@as(f64, @floatFromInt(self.nbuckets)) * self.load_factor));
        self.shrink_at = @as(usize, @intFromFloat(@as(f64, @floatFromInt(self.nbuckets)) * self.shrink_factor));
    }

    fn findBucket(self: *const Map, key: []const u8, hash: u32) ?usize {
        const clipped = bucket.clipHash(hash);
        var idx = @as(usize, clipped) & self.mask;
        while (true) {
            const current = &self.buckets[idx];
            if (current.dib == 0) return null;
            if (bucket.readHash(current) == clipped and keyMatches(bucket.getPtr(entry.Entry, current).?, key, self.usecas)) {
                return idx;
            }
            idx = (idx + 1) & self.mask;
        }
    }

    pub fn deleteBucket(self: *Map, idx: usize) *entry.Entry {
        const current = &self.buckets[idx];
        std.debug.assert(current.dib != 0);
        const old = bucket.getPtr(entry.Entry, current).?;
        self.entsize -= entry.memSize(old);
        self.shiftDelete(idx);
        return old;
    }

    fn shiftDelete(self: *Map, start_idx: usize) void {
        var idx = start_idx;
        self.buckets[idx].dib = 0;
        while (true) {
            const prev = idx;
            idx = (idx + 1) & self.mask;
            if (self.buckets[idx].dib <= 1) {
                self.buckets[prev].dib = 0;
                break;
            }
            self.buckets[prev] = self.buckets[idx];
            self.buckets[prev].dib -%= 1;
        }
        self.count -= 1;
    }
};

fn keyMatches(ent: *const entry.Entry, key: []const u8, usecas: bool) bool {
    var buf: [128]u8 = undefined;
    const entry_key = entry.key(ent, usecas, &buf);
    return std.mem.eql(u8, key, entry_key);
}

fn entryEqual(a: *const entry.Entry, b: *const entry.Entry, usecas: bool) bool {
    if (entry.hasSixpack(a) == entry.hasSixpack(b)) {
        const akey = entry.rawKey(a, usecas);
        const bkey = entry.rawKey(b, usecas);
        return std.mem.eql(u8, akey, bkey);
    }
    var buf_a: [128]u8 = undefined;
    var buf_b: [128]u8 = undefined;
    const akey = entry.key(a, usecas, &buf_a);
    const bkey = entry.key(b, usecas, &buf_b);
    return std.mem.eql(u8, akey, bkey);
}

test "map insert lookup delete and replace" {
    const allocator = std.testing.allocator;
    var map = try Map.init(allocator, 8, .{ .allow_shrink = true });
    defer map.deinit();

    const e1 = try entry.create(allocator, "alpha", "one", .{});
    const e2 = try entry.create(allocator, "beta", "two", .{});
    const h1 = @as(u32, @truncate(@import("hash.zig").th64("alpha", 0)));
    const h2 = @as(u32, @truncate(@import("hash.zig").th64("beta", 0)));

    try std.testing.expect((try map.insert(e1, h1)) == null);
    try std.testing.expect((try map.insert(e2, h2)) == null);
    try std.testing.expectEqual(@as(usize, 2), map.count);
    try std.testing.expectEqual(@as(u64, 2), map.total);

    const found = map.lookup("alpha", h1).?;
    try std.testing.expectEqual(@intFromPtr(e1), @intFromPtr(found));

    const e1b = try entry.create(allocator, "alpha", "uno", .{});
    const replaced = (try map.insert(e1b, h1)).?;
    defer entry.release(replaced, allocator);
    try std.testing.expectEqual(@as(usize, 2), map.count);
    try std.testing.expectEqual(@as(u64, 2), map.total);

    const deleted = map.delete("alpha", h1).?;
    defer entry.release(deleted, allocator);
    try std.testing.expectEqual(@as(usize, 1), map.count);

    const deleted2 = map.delete("beta", h2).?;
    defer entry.release(deleted2, allocator);
    try std.testing.expectEqual(@as(usize, 0), map.count);
}

test "map resize and shrink" {
    const allocator = std.testing.allocator;
    var map = try Map.init(allocator, 4, .{ .allow_shrink = true });
    defer map.deinit();

    const keys = [_][]const u8{ "a", "b", "c", "d" };
    var entries: [4]*entry.Entry = undefined;
    for (keys, 0..) |key, i| {
        entries[i] = try entry.create(allocator, key, "v", .{});
        const hash = @as(u32, @truncate(@import("hash.zig").th64(key, 0)));
        _ = try map.insert(entries[i], hash);
    }

    try std.testing.expectEqual(@as(usize, 8), map.nbuckets);

    for (keys) |key| {
        const hash = @as(u32, @truncate(@import("hash.zig").th64(key, 0)));
        const removed = map.delete(key, hash).?;
        defer entry.release(removed, allocator);
    }

    try map.tryShrink();
    try std.testing.expectEqual(@as(usize, 4), map.nbuckets);
}

test "map invalid capacity" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(MapError.InvalidCapacity, Map.init(allocator, 0, .{}));
    try std.testing.expectError(MapError.InvalidCapacity, Map.init(allocator, 3, .{}));
}

test "map insert swap and shift delete" {
    const allocator = std.testing.allocator;
    var map = try Map.init(allocator, 8, .{});
    defer map.deinit();

    const e1 = try entry.create(allocator, "alpha", "one", .{});
    const e2 = try entry.create(allocator, "beta", "two", .{});
    const e3 = try entry.create(allocator, "gamma", "three", .{});
    const h0: u32 = 0;
    const h1: u32 = 1;

    try std.testing.expect((try map.insert(e1, h0)) == null);
    try std.testing.expect((try map.insert(e2, h1)) == null);
    try std.testing.expect((try map.insert(e3, h0)) == null);

    const removed1 = map.delete("alpha", h0).?;
    defer entry.release(removed1, allocator);
    const removed2 = map.delete("beta", h1).?;
    defer entry.release(removed2, allocator);
    const removed3 = map.delete("gamma", h0).?;
    defer entry.release(removed3, allocator);
}

test "map tryShrink recalculates desired" {
    const allocator = std.testing.allocator;
    var map = try Map.init(allocator, 4, .{ .allow_shrink = true, .shrink_factor = 100 });
    defer map.deinit();

    const keys = [_][]const u8{ "a", "b", "c", "d" };
    var i: usize = 0;
    while (i < keys.len) : (i += 1) {
        const key = keys[i];
        const ent = try entry.create(allocator, key, "v", .{});
        const hash = @as(u32, @truncate(@import("hash.zig").th64(key, 0)));
        _ = try map.insert(ent, hash);
    }

    try std.testing.expectEqual(@as(usize, 8), map.nbuckets);

    const hash0 = @as(u32, @truncate(@import("hash.zig").th64(keys[0], 0)));
    const removed0 = map.delete(keys[0], hash0).?;
    defer entry.release(removed0, allocator);

    try map.tryShrink();
    try std.testing.expectEqual(@as(usize, 8), map.nbuckets);

    var j: usize = 1;
    while (j < keys.len) : (j += 1) {
        const key = keys[j];
        const hash = @as(u32, @truncate(@import("hash.zig").th64(key, 0)));
        const removed = map.delete(key, hash).?;
        defer entry.release(removed, allocator);
    }
}

test "map resize rehash swap" {
    const allocator = std.testing.allocator;
    var map = try Map.init(allocator, 4, .{});
    defer map.deinit();

    const e1 = try entry.create(allocator, "alpha", "one", .{});
    const e2 = try entry.create(allocator, "beta", "two", .{});
    const e3 = try entry.create(allocator, "gamma", "three", .{});
    defer entry.release(e1, allocator);
    defer entry.release(e2, allocator);
    defer entry.release(e3, allocator);

    map.count = 3;
    map.total = 3;
    map.entsize = entry.memSize(e1) + entry.memSize(e2) + entry.memSize(e3);

    map.buckets[0] = bucket.init();
    bucket.setPtr(entry.Entry, &map.buckets[0], e1);
    bucket.writeHash(&map.buckets[0], 0);
    map.buckets[0].dib = 1;

    map.buckets[1] = bucket.init();
    bucket.setPtr(entry.Entry, &map.buckets[1], e2);
    bucket.writeHash(&map.buckets[1], 1);
    map.buckets[1].dib = 1;

    map.buckets[2] = bucket.init();
    bucket.setPtr(entry.Entry, &map.buckets[2], e3);
    bucket.writeHash(&map.buckets[2], 0);
    map.buckets[2].dib = 1;

    map.buckets[3] = bucket.init();

    try map.resize(8);
    try std.testing.expectEqual(@as(usize, 8), map.nbuckets);
}

test "map entryEqual handles sixpack mismatch" {
    const allocator = std.testing.allocator;
    const packed_entry = try entry.create(allocator, "abcd", "one", .{});
    const raw = try entry.create(allocator, "abcd", "two", .{ .nosixpack = true });
    defer entry.release(packed_entry, allocator);
    defer entry.release(raw, allocator);

    try std.testing.expect(entryEqual(packed_entry, raw, false));
}
