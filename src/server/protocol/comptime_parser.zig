const std = @import("std");

pub const Limits = struct {
    max_key_length: usize = 1024,
    max_value_length: usize = 1024 * 1024,
    max_args: usize = 32,
};

pub const CommonError = error{
    NeedsMore,
    InvalidMethod,
    MalformedRequest,
    KeyTooLarge,
    ValueTooLarge,
    ConnectionClosed,
    InvalidNumber,
    TooManyArgs,
};

/// Protocol interface requirements:
/// - pub const Command: type
/// - pub const State: type
/// - pub const ParseResult: type
/// - pub fn initState() State
/// - pub fn parse(state: *State, buf: []const u8, limits: Limits, eof: bool) ParseResult
pub fn Parser(comptime Protocol: type) type {
    comptime {
        if (!@hasDecl(Protocol, "Command")) @compileError("Protocol must define Command");
        if (!@hasDecl(Protocol, "State")) @compileError("Protocol must define State");
        if (!@hasDecl(Protocol, "ParseResult")) @compileError("Protocol must define ParseResult");
        if (!@hasDecl(Protocol, "initState")) @compileError("Protocol must define initState()");
        if (!@hasDecl(Protocol, "parse")) @compileError("Protocol must define parse()");
    }

    return struct {
        const Self = @This();

        state: Protocol.State,
        limits: Limits,

        pub fn init(limits: Limits) Self {
            return .{
                .state = Protocol.initState(),
                .limits = limits,
            };
        }

        pub fn reset(self: *Self) void {
            self.state = Protocol.initState();
        }

        pub fn parse(self: *Self, buf: []const u8, eof: bool) Protocol.ParseResult {
            return Protocol.parse(&self.state, buf, self.limits, eof);
        }
    };
}

test "comptime parser example compiles and runs" {
    const Example = struct {
        pub const Command = enum { ping };
        pub const State = struct {};
        pub const ParseResult = union(enum) {
            ok: struct { command: Command, consumed: usize },
            needs_more: void,
            err: CommonError,
        };

        pub fn initState() State {
            return .{};
        }

        pub fn parse(_: *State, buf: []const u8, _: Limits, eof: bool) ParseResult {
            if (buf.len == 0) return if (eof) .{ .err = CommonError.ConnectionClosed } else .{ .needs_more = {} };
            if (std.mem.eql(u8, buf, "PING")) {
                return .{ .ok = .{ .command = .ping, .consumed = 4 } };
            }
            return .{ .err = CommonError.MalformedRequest };
        }
    };

    const ExampleParser = Parser(Example);
    var parser = ExampleParser.init(.{});
    const res = parser.parse("PING", false);
    try std.testing.expect(res == .ok);
    try std.testing.expectEqual(Example.Command.ping, res.ok.command);
    try std.testing.expectEqual(@as(usize, 4), res.ok.consumed);
}
