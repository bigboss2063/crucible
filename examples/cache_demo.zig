const std = @import("std");
const crucible = @import("crucible");

fn iterEntry(
    shard: u32,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) crucible.IterAction {
    _ = udata;
    std.debug.print(
        "iter shard={d} time={d} key={s} value={s} expires={d} flags={d} cas={d}\n",
        .{ shard, time, key, value, expires, flags, cas },
    );
    return crucible.IterAction.Continue;
}

fn evictedEntry(
    shard: u32,
    reason: crucible.EvictReason,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) void {
    _ = value;
    _ = expires;
    _ = flags;
    _ = cas;
    _ = udata;
    std.debug.print(
        "evicted shard={d} reason={s} time={d} key={s}\n",
        .{ shard, @tagName(reason), time, key },
    );
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const cache = try crucible.init(.{
        .allocator = allocator,
        .nshards = 4,
        .usecas = true,
        .evicted = evictedEntry,
    });
    defer crucible.deinit(cache);
    std.debug.print("nshards={d}\n", .{crucible.nshards(cache)});

    std.debug.print("store alpha -> {s}\n", .{@tagName(try crucible.store(cache, "alpha", "one", .{}))});
    std.debug.print("store beta  -> {s}\n", .{@tagName(try crucible.store(cache, "beta", "two", .{}))});

    const temp_opts = crucible.StoreOptions{
        .time = 100,
        .ttl = 10,
    };
    _ = try crucible.store(cache, "temp", "expire", temp_opts);

    const batch = try crucible.begin(cache);
    _ = try crucible.storeBatch(batch, "gamma", "three", .{});
    _ = try crucible.storeBatch(batch, "delta", "four", .{});
    crucible.end(batch);

    const iter_opts = crucible.IterOptions{
        .entry = iterEntry,
    };
    _ = crucible.iter(cache, iter_opts);

    var cursor: u64 = 0;
    if (crucible.entryIter(cache, 0, &cursor)) |entry_handle| {
        defer entry_handle.release();
        var key_buf: [128]u8 = undefined;
        const key = entry_handle.key(&key_buf);
        const value = entry_handle.value();
        std.debug.print("entry_iter key={s} value={s}\n", .{ key, value });
    }

    const temp_entry = try crucible.load(cache, "temp", .{ .time = 120 });
    if (temp_entry) |entry_handle| {
        defer entry_handle.release();
        std.debug.print("load temp status=Found\n", .{});
    } else {
        std.debug.print("load temp status=NotFound\n", .{});
    }

    var swept: usize = 0;
    var kept: usize = 0;
    const sweep_opts = crucible.SweepOptions{
        .time = 120,
    };
    crucible.sweep(cache, &swept, &kept, sweep_opts);
    std.debug.print("sweep swept={d} kept={d}\n", .{ swept, kept });

    std.debug.print(
        "count={d} total={d} size={d}\n",
        .{ crucible.count(cache, .{}), crucible.total(cache, .{}), crucible.size(cache, .{}) },
    );

    _ = crucible.delete(cache, "beta", .{});
    std.debug.print("after delete count={d}\n", .{crucible.count(cache, .{})});
}
