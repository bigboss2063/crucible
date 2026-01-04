const std = @import("std");
const cache_mod = @import("../cache/mod.zig");

pub const StatsSnapshot = struct {
    time_unix_ms: u64,
    uptime_ms: u64,
    server: ServerSnapshot,
    errors: ErrorSnapshot,
    cache: CacheSnapshot,
};

pub const ServerSnapshot = struct {
    active_connections: usize,
    total_connections: u64,
    total_requests: u64,
    total_responses: u64,
    bytes_read: u64,
    bytes_written: u64,
};

pub const ErrorSnapshot = struct {
    accept: u64,
    read: u64,
    write: u64,
    parse: u64,
    protocol: u64,
    pool_full: u64,
    buffer_overflow: u64,
    cache: u64,
    timeout: u64,
};

pub const CacheSnapshot = struct {
    items: usize,
    total_items: u64,
    bytes: usize,
    shards: u32,
};

pub fn build(cache: *cache_mod.api.Cache, metrics: anytype, start_time_ms: u64) StatsSnapshot {
    const now_ms = @as(u64, @intCast(std.time.milliTimestamp()));
    const uptime_ms = if (now_ms >= start_time_ms) now_ms - start_time_ms else 0;
    return .{
        .time_unix_ms = now_ms,
        .uptime_ms = uptime_ms,
        .server = .{
            .active_connections = metrics.active_connections,
            .total_connections = metrics.total_connections,
            .total_requests = metrics.total_requests,
            .total_responses = metrics.total_responses,
            .bytes_read = metrics.bytes_read,
            .bytes_written = metrics.bytes_written,
        },
        .errors = .{
            .accept = metrics.errors.accept,
            .read = metrics.errors.read,
            .write = metrics.errors.write,
            .parse = metrics.errors.parse,
            .protocol = metrics.errors.protocol,
            .pool_full = metrics.errors.pool_full,
            .buffer_overflow = metrics.errors.buffer_overflow,
            .cache = metrics.errors.cache,
            .timeout = metrics.errors.timeout,
        },
        .cache = .{
            .items = cache_mod.engine.count(cache, .{}),
            .total_items = cache_mod.engine.total(cache, .{}),
            .bytes = cache_mod.engine.size(cache, .{}),
            .shards = cache_mod.engine.nshards(cache),
        },
    };
}

pub fn formatJson(snapshot: StatsSnapshot, buf: []u8) ![]const u8 {
    const active_connections = @as(u64, @intCast(snapshot.server.active_connections));
    const cache_items = @as(u64, @intCast(snapshot.cache.items));
    const cache_bytes = @as(u64, @intCast(snapshot.cache.bytes));
    const cache_shards = @as(u64, @intCast(snapshot.cache.shards));
    return std.fmt.bufPrint(
        buf,
        "{{\"time_unix_ms\":{d},\"uptime_ms\":{d},\"server\":{{\"active_connections\":{d},\"total_connections\":{d},\"total_requests\":{d},\"total_responses\":{d},\"bytes_read\":{d},\"bytes_written\":{d}}},\"errors\":{{\"accept\":{d},\"read\":{d},\"write\":{d},\"parse\":{d},\"protocol\":{d},\"pool_full\":{d},\"buffer_overflow\":{d},\"cache\":{d},\"timeout\":{d}}},\"cache\":{{\"items\":{d},\"total_items\":{d},\"bytes\":{d},\"shards\":{d}}}}}",
        .{
            snapshot.time_unix_ms,
            snapshot.uptime_ms,
            active_connections,
            snapshot.server.total_connections,
            snapshot.server.total_requests,
            snapshot.server.total_responses,
            snapshot.server.bytes_read,
            snapshot.server.bytes_written,
            snapshot.errors.accept,
            snapshot.errors.read,
            snapshot.errors.write,
            snapshot.errors.parse,
            snapshot.errors.protocol,
            snapshot.errors.pool_full,
            snapshot.errors.buffer_overflow,
            snapshot.errors.cache,
            snapshot.errors.timeout,
            cache_items,
            snapshot.cache.total_items,
            cache_bytes,
            cache_shards,
        },
    );
}

pub fn formatInfo(snapshot: StatsSnapshot, buf: []u8) ![]const u8 {
    const active_connections = @as(u64, @intCast(snapshot.server.active_connections));
    const cache_items = @as(u64, @intCast(snapshot.cache.items));
    const cache_bytes = @as(u64, @intCast(snapshot.cache.bytes));
    const cache_shards = @as(u64, @intCast(snapshot.cache.shards));
    return std.fmt.bufPrint(
        buf,
        "time_unix_ms:{d}\n" ++
            "uptime_ms:{d}\n" ++
            "server.active_connections:{d}\n" ++
            "server.total_connections:{d}\n" ++
            "server.total_requests:{d}\n" ++
            "server.total_responses:{d}\n" ++
            "server.bytes_read:{d}\n" ++
            "server.bytes_written:{d}\n" ++
            "errors.accept:{d}\n" ++
            "errors.read:{d}\n" ++
            "errors.write:{d}\n" ++
            "errors.parse:{d}\n" ++
            "errors.protocol:{d}\n" ++
            "errors.pool_full:{d}\n" ++
            "errors.buffer_overflow:{d}\n" ++
            "errors.cache:{d}\n" ++
            "errors.timeout:{d}\n" ++
            "cache.items:{d}\n" ++
            "cache.total_items:{d}\n" ++
            "cache.bytes:{d}\n" ++
            "cache.shards:{d}",
        .{
            snapshot.time_unix_ms,
            snapshot.uptime_ms,
            active_connections,
            snapshot.server.total_connections,
            snapshot.server.total_requests,
            snapshot.server.total_responses,
            snapshot.server.bytes_read,
            snapshot.server.bytes_written,
            snapshot.errors.accept,
            snapshot.errors.read,
            snapshot.errors.write,
            snapshot.errors.parse,
            snapshot.errors.protocol,
            snapshot.errors.pool_full,
            snapshot.errors.buffer_overflow,
            snapshot.errors.cache,
            snapshot.errors.timeout,
            cache_items,
            snapshot.cache.total_items,
            cache_bytes,
            cache_shards,
        },
    );
}
