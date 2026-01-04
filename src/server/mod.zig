pub const protocol = @import("protocol.zig");
pub const network = @import("network.zig");
pub const connection = @import("connection.zig");
pub const buffer = @import("buffer.zig");
pub const execute = @import("execute.zig");
pub const persistence = @import("persistence.zig");

test "xev loop init smoke" {
    const xev = @import("xev").Dynamic;
    try xev.detect();
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();
}
