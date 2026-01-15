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

fn loadUpdate(
    shard: u32,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) ?crucible.Update {
    _ = shard;
    _ = time;
    _ = cas;
    _ = udata;

    if (!std.mem.eql(u8, key, "alpha")) return null;

    return .{
        .value = value,
        .flags = flags | 0x1,
        .expires = expires,
    };
}

const CounterUpdateCtx = struct {
    delta: i64,
    updated: *?i64,
    buf: *[32]u8,
};

fn counterUpdate(
    shard: u32,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) ?crucible.Update {
    _ = shard;
    _ = time;
    _ = key;
    _ = cas;

    const ctx = @as(*CounterUpdateCtx, @ptrCast(@alignCast(udata.?)));
    const current = std.fmt.parseInt(i64, value, 10) catch return null;
    const next = current + ctx.delta;
    const slice = std.fmt.bufPrint(ctx.buf, "{d}", .{next}) catch return null;
    ctx.updated.* = next;
    return .{
        .value = slice,
        .flags = flags,
        .expires = expires,
    };
}

const ExpireUpdateCtx = struct {
    updated: *bool,
    now_time: i64,
    ttl: i64,
};

fn expireUpdate(
    shard: u32,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) ?crucible.Update {
    _ = shard;
    _ = time;
    _ = key;
    _ = expires;
    _ = cas;

    const ctx = @as(*ExpireUpdateCtx, @ptrCast(@alignCast(udata.?)));
    ctx.updated.* = true;
    return .{
        .value = value,
        .flags = flags,
        .expires = ctx.now_time + ctx.ttl,
    };
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
    std.debug.print("store alpha (nx) -> {s}\n", .{@tagName(try crucible.store(cache, "alpha", "one-nx", .{ .nx = true }))});
    std.debug.print("store beta (xx) -> {s}\n", .{@tagName(try crucible.store(cache, "beta", "two", .{ .xx = true }))});
    std.debug.print("store beta -> {s}\n", .{@tagName(try crucible.store(cache, "beta", "two", .{}))});

    const cas_entry = try crucible.load(cache, "alpha", .{});
    if (cas_entry) |entry_handle| {
        const cas_value = entry_handle.cas();
        entry_handle.release();
        std.debug.print(
            "store alpha (cas wrong) -> {s}\n",
            .{@tagName(try crucible.store(cache, "alpha", "one-cas-bad", .{ .casop = true, .cas = cas_value + 1 }))},
        );
        std.debug.print(
            "store alpha (cas ok) -> {s}\n",
            .{@tagName(try crucible.store(cache, "alpha", "one-cas", .{ .casop = true, .cas = cas_value }))},
        );
    }

    const updated_entry = try crucible.load(cache, "alpha", .{ .update = loadUpdate });
    if (updated_entry) |entry_handle| {
        defer entry_handle.release();
        std.debug.print(
            "load update alpha value={s} flags={d}\n",
            .{ entry_handle.value(), entry_handle.flags() },
        );
    }

    _ = try crucible.store(cache, "counter", "10", .{});

    var counter_buf: [32]u8 = undefined;
    var counter_updated: ?i64 = null;
    var counter_ctx = CounterUpdateCtx{
        .delta = 1,
        .updated = &counter_updated,
        .buf = &counter_buf,
    };
    const incr_entry = try crucible.load(cache, "counter", .{ .update = counterUpdate, .udata = &counter_ctx });
    if (incr_entry) |entry_handle| {
        entry_handle.release();
        if (counter_updated) |next| {
            std.debug.print("incr counter -> {d}\n", .{next});
        } else {
            std.debug.print("incr counter -> not an integer\n", .{});
        }
    } else {
        std.debug.print("incr counter -> not found\n", .{});
    }

    counter_updated = null;
    counter_ctx.delta = -2;
    const decr_entry = try crucible.load(cache, "counter", .{ .update = counterUpdate, .udata = &counter_ctx });
    if (decr_entry) |entry_handle| {
        entry_handle.release();
        if (counter_updated) |next| {
            std.debug.print("decr counter -> {d}\n", .{next});
        } else {
            std.debug.print("decr counter -> not an integer\n", .{});
        }
    } else {
        std.debug.print("decr counter -> not found\n", .{});
    }

    _ = try crucible.store(cache, "session", "alive", .{});
    const expire_now = crucible.now();
    const ttl_ns = @as(i64, @intCast(2 * std.time.ns_per_s));
    var expire_updated = false;
    var expire_ctx = ExpireUpdateCtx{
        .updated = &expire_updated,
        .now_time = expire_now,
        .ttl = ttl_ns,
    };
    const expire_entry = try crucible.load(
        cache,
        "session",
        .{ .time = expire_now, .update = expireUpdate, .udata = &expire_ctx },
    );
    if (expire_entry) |entry_handle| {
        entry_handle.release();
    }
    std.debug.print("expire session updated={s}\n", .{if (expire_updated) "true" else "false"});
    const expired_entry = try crucible.load(cache, "session", .{ .time = expire_now + ttl_ns + 1 });
    if (expired_entry) |entry_handle| {
        entry_handle.release();
        std.debug.print("load session after ttl status=Found\n", .{});
    } else {
        std.debug.print("load session after ttl status=NotFound\n", .{});
    }

    const temp_opts = crucible.StoreOptions{
        .time = 100,
        .ttl = 10,
    };
    _ = try crucible.store(cache, "temp", "expire", temp_opts);

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

    // Batch holds shard locks; end it before non-batch ops like count/delete.
    {
        const batch = try crucible.begin(cache);
        defer crucible.end(batch);
        _ = try crucible.storeBatch(batch, "gamma", "three", .{});
        _ = try crucible.storeBatch(batch, "delta", "four", .{});
        if (try crucible.loadBatch(batch, "gamma", .{})) |entry_handle| {
            defer entry_handle.release();
            std.debug.print("load batch gamma value={s}\n", .{entry_handle.value()});
        }
        std.debug.print("delete batch delta -> {s}\n", .{@tagName(crucible.deleteBatch(batch, "delta", .{}))});
        _ = crucible.iterBatch(batch, iter_opts);
        var swept: usize = 0;
        var kept: usize = 0;
        crucible.sweepBatch(batch, &swept, &kept, .{ .time = 120 });
        std.debug.print("sweep batch swept={d} kept={d}\n", .{ swept, kept });
    }

    std.debug.print(
        "count={d} total={d} size={d}\n",
        .{ crucible.count(cache, .{}), crucible.total(cache, .{}), crucible.size(cache, .{}) },
    );

    _ = crucible.delete(cache, "beta", .{});
    std.debug.print("after delete count={d}\n", .{crucible.count(cache, .{})});
}
