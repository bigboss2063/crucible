const std = @import("std");
const api = @import("api.zig");
const bucket = @import("bucket.zig");
const entry = @import("entry.zig");
const map = @import("map.zig");

const lock_exclusive: usize = std.math.maxInt(usize);

pub const Shard = struct {
    lock: usize,
    cas: u64,
    map: map.Map,
    next: ?*Shard,

    pub fn init(allocator: std.mem.Allocator, cap: usize, opts: map.Options) !Shard {
        return .{
            .lock = 0,
            .cas = 1,
            .map = try map.Map.init(allocator, cap, opts),
            .next = null,
        };
    }

    pub fn deinit(self: *Shard) void {
        if (self.map.buckets.len != 0) {
            for (self.map.buckets) |bkt| {
                if (bkt.dib == 0) continue;
                if (bucket.getPtr(entry.Entry, &bkt)) |ent| {
                    entry.release(ent, self.map.allocator);
                }
            }
        }
        self.map.deinit();
    }

    pub fn nextCas(self: *Shard) u64 {
        self.cas +%= 1;
        return self.cas;
    }

    pub fn lockExclusive(self: *Shard, yield: ?api.YieldFn, udata: ?*anyopaque) void {
        while (true) {
            if (@cmpxchgWeak(usize, &self.lock, 0, lock_exclusive, .acquire, .monotonic) == null) {
                return;
            }
            spin(yield, udata);
        }
    }

    pub fn lockTagged(self: *Shard, tag: usize, yield: ?api.YieldFn, udata: ?*anyopaque) bool {
        while (true) {
            if (@cmpxchgWeak(usize, &self.lock, 0, tag, .acquire, .monotonic) == null) {
                return true;
            }
            if (@atomicLoad(usize, &self.lock, .acquire) == tag) {
                return false;
            }
            spin(yield, udata);
        }
    }

    pub fn unlock(self: *Shard) void {
        @atomicStore(usize, &self.lock, 0, .release);
    }
};

fn spin(yield: ?api.YieldFn, udata: ?*anyopaque) void {
    if (yield) |cb| {
        cb(udata);
    } else {
        std.atomic.spinLoopHint();
    }
}

const LockState = struct {
    shard: *Shard,
    counter: std.atomic.Value(u64),
    in_critical: std.atomic.Value(u8),
    violations: std.atomic.Value(u64),
    iterations: usize,
};

fn lockWorker(state: *LockState) void {
    var i: usize = 0;
    while (i < state.iterations) : (i += 1) {
        state.shard.lockExclusive(null, null);
        if (state.in_critical.swap(1, .acq_rel) != 0) {
            _ = state.violations.fetchAdd(1, .acq_rel);
        }
        _ = state.counter.fetchAdd(1, .acq_rel);
        state.in_critical.store(0, .release);
        state.shard.unlock();
    }
}

test "shard cas increments" {
    var shard = try Shard.init(std.testing.allocator, 8, .{});
    defer shard.deinit();

    try std.testing.expectEqual(@as(u64, 1), shard.cas);
    try std.testing.expectEqual(@as(u64, 2), shard.nextCas());
    try std.testing.expectEqual(@as(u64, 3), shard.nextCas());
}

test "shard lock exclusive and tagged" {
    var shard = try Shard.init(std.testing.allocator, 8, .{});
    defer shard.deinit();

    shard.lockExclusive(null, null);
    try std.testing.expectEqual(lock_exclusive, @atomicLoad(usize, &shard.lock, .acquire));
    shard.unlock();
    try std.testing.expectEqual(@as(usize, 0), @atomicLoad(usize, &shard.lock, .acquire));

    const tag: usize = 0x1234;
    try std.testing.expect(shard.lockTagged(tag, null, null));
    try std.testing.expect(!shard.lockTagged(tag, null, null));
    shard.unlock();
}

test "shard lock excludes concurrent access" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var shard = try Shard.init(std.testing.allocator, 8, .{});
    defer shard.deinit();

    var state = LockState{
        .shard = &shard,
        .counter = std.atomic.Value(u64).init(0),
        .in_critical = std.atomic.Value(u8).init(0),
        .violations = std.atomic.Value(u64).init(0),
        .iterations = 2000,
    };

    var threads: [4]std.Thread = undefined;
    var i: usize = 0;
    while (i < threads.len) : (i += 1) {
        threads[i] = try std.Thread.spawn(.{}, lockWorker, .{&state});
    }
    for (threads) |thread| {
        thread.join();
    }

    try std.testing.expectEqual(@as(u64, 4 * state.iterations), state.counter.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), state.violations.load(.acquire));
}
