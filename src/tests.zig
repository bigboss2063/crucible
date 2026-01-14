comptime {
    _ = @import("cache/batch.zig");
    _ = @import("cache/bucket.zig");
    _ = @import("cache/engine.zig");
    _ = @import("cache/entry.zig");
    _ = @import("cache/hash.zig");
    _ = @import("cache/map.zig");
    _ = @import("cache/shard.zig");
    _ = @import("cache/sixpack.zig");
    _ = @import("cache/varint.zig");

    _ = @import("server/buffer.zig");
    _ = @import("server/connection.zig");
    _ = @import("server/execute.zig");
    _ = @import("server/mod.zig");
    _ = @import("server/network.zig");
    _ = @import("server/aof.zig");
    _ = @import("server/persistence.zig");
    _ = @import("server/resource_controls.zig");
    _ = @import("server/protocol/comptime_parser.zig");
    _ = @import("server/protocol/http.zig");
    _ = @import("server/protocol/resp.zig");
}
