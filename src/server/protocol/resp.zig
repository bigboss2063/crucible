const std = @import("std");
const comptime_parser = @import("comptime_parser.zig");

pub const Limits = comptime_parser.Limits;

pub const Error = error{
    NeedsMore,
    MalformedRequest,
    ValueTooLarge,
    ConnectionClosed,
    InvalidNumber,
    TooManyArgs,
};


pub const KeyCommand = struct {
    key: []const u8,
};

pub const SetOptions = struct {
    nx: bool = false,
    xx: bool = false,
    ttl_ns: i64 = 0,
};

pub const SetCommand = struct {
    key: []const u8,
    value: []const u8,
    options: SetOptions,
};

pub const ExpireCommand = struct {
    key: []const u8,
    ttl_ns: i64,
};

pub const PersistCommand = struct {
    path: ?[]const u8 = null,
    fast: bool = false,
};

pub const Command = union(enum) {
    get: KeyCommand,
    set: SetCommand,
    delete: KeyCommand,
    incr: KeyCommand,
    decr: KeyCommand,
    expire: ExpireCommand,
    ttl: KeyCommand,
    save: PersistCommand,
    load: PersistCommand,
    ping: void,
    info: void,
    stats: void,
};

pub const ParsedCommand = struct {
    command: Command,
    consumed: usize,
};

pub const ParseResult = union(enum) {
    ok: ParsedCommand,
    needs_more: void,
    err: Error,
};

pub const MaxArgs: usize = 32;

pub const State = struct {
    stage: Stage = .start,
    offset: usize = 0,
    array_len: usize = 0,
    arg_index: usize = 0,
    bulk_len: usize = 0,
    args: [MaxArgs][]const u8 = undefined,
};

const Stage = enum {
    start,
    array_len,
    bulk_len,
    bulk_data,
};

pub fn initState() State {
    return .{};
}

pub fn parse(state: *State, buf: []const u8, limits: Limits, eof: bool) ParseResult {
    if (buf.len == 0) {
        return if (eof) .{ .err = Error.ConnectionClosed } else .{ .needs_more = {} };
    }

    var pos = state.offset;

    while (true) {
        switch (state.stage) {
            .start => {
                if (pos >= buf.len) return if (eof) .{ .err = Error.ConnectionClosed } else .{ .needs_more = {} };
                if (buf[pos] != '*') {
                    state.* = initState();
                    return .{ .err = Error.MalformedRequest };
                }
                pos += 1;
                state.stage = .array_len;
                state.offset = pos;
            },
            .array_len => {
                const line_end = findCrlf(buf, pos) orelse {
                    state.offset = pos;
                    return if (eof) .{ .err = Error.ConnectionClosed } else .{ .needs_more = {} };
                };
                const count = parseNumber(buf[pos..line_end]) catch |err| {
                    state.* = initState();
                    return .{ .err = err };
                };
                if (count < 0) {
                    state.* = initState();
                    return .{ .err = Error.MalformedRequest };
                }
                const usize_count = @as(usize, @intCast(count));
                if (usize_count > limits.max_args or usize_count > MaxArgs) {
                    state.* = initState();
                    return .{ .err = Error.TooManyArgs };
                }
                state.array_len = usize_count;
                state.arg_index = 0;
                state.stage = .bulk_len;
                pos = line_end + 2;
                state.offset = pos;
            },
            .bulk_len => {
                if (state.arg_index >= state.array_len) {
                    const cmd = buildCommand(state, limits) catch |err| {
                        state.* = initState();
                        return .{ .err = err };
                    };
                    const consumed = pos;
                    state.* = initState();
                    return .{ .ok = .{ .command = cmd, .consumed = consumed } };
                }
                if (pos >= buf.len) {
                    state.offset = pos;
                    return if (eof) .{ .err = Error.ConnectionClosed } else .{ .needs_more = {} };
                }
                if (buf[pos] != '$') {
                    state.* = initState();
                    return .{ .err = Error.MalformedRequest };
                }
                const line_start = pos + 1;
                const line_end = findCrlf(buf, line_start) orelse {
                    state.offset = pos;
                    return if (eof) .{ .err = Error.ConnectionClosed } else .{ .needs_more = {} };
                };
                const len = parseNumber(buf[line_start..line_end]) catch |err| {
                    state.* = initState();
                    return .{ .err = err };
                };
                if (len < 0) {
                    state.* = initState();
                    return .{ .err = Error.MalformedRequest };
                }
                const usize_len = @as(usize, @intCast(len));
                if (usize_len > limits.max_value_length) {
                    state.* = initState();
                    return .{ .err = Error.ValueTooLarge };
                }
                state.bulk_len = usize_len;
                state.stage = .bulk_data;
                pos = line_end + 2;
                state.offset = pos;
            },
            .bulk_data => {
                const needed = pos + state.bulk_len + 2;
                if (buf.len < needed) {
                    state.offset = pos;
                    return if (eof) .{ .err = Error.ConnectionClosed } else .{ .needs_more = {} };
                }
                if (buf[pos + state.bulk_len] != '\r' or buf[pos + state.bulk_len + 1] != '\n') {
                    state.* = initState();
                    return .{ .err = Error.MalformedRequest };
                }
                state.args[state.arg_index] = buf[pos .. pos + state.bulk_len];
                state.arg_index += 1;
                pos = needed;
                state.stage = .bulk_len;
                state.offset = pos;
            },
        }
    }
}

pub const Parser = comptime_parser.Parser(@This());

fn parseNumber(slice: []const u8) Error!i64 {
    return std.fmt.parseInt(i64, slice, 10) catch Error.InvalidNumber;
}

fn buildCommand(state: *const State, limits: Limits) Error!Command {
    if (state.array_len == 0) return Error.MalformedRequest;
    const args = state.args[0..state.array_len];
    const cmd = args[0];
    if (std.ascii.eqlIgnoreCase(cmd, "PING")) {
        if (args.len != 1) return Error.MalformedRequest;
        return .{ .ping = {} };
    }
    if (std.ascii.eqlIgnoreCase(cmd, "INFO")) {
        if (args.len != 1) return Error.MalformedRequest;
        return .{ .info = {} };
    }
    if (std.ascii.eqlIgnoreCase(cmd, "STATS")) {
        if (args.len != 1) return Error.MalformedRequest;
        return .{ .stats = {} };
    }
    if (std.ascii.eqlIgnoreCase(cmd, "GET")) {
        if (args.len != 2) return Error.MalformedRequest;
        if (args[1].len > limits.max_key_length) return Error.ValueTooLarge;
        return .{ .get = .{ .key = args[1] } };
    }
    if (std.ascii.eqlIgnoreCase(cmd, "SET")) {
        if (args.len < 3) return Error.MalformedRequest;
        if (args[1].len > limits.max_key_length) return Error.ValueTooLarge;
        var options: SetOptions = .{};
        var i: usize = 3;
        while (i < args.len) {
            if (std.ascii.eqlIgnoreCase(args[i], "NX")) {
                options.nx = true;
                i += 1;
                continue;
            }
            if (std.ascii.eqlIgnoreCase(args[i], "XX")) {
                options.xx = true;
                i += 1;
                continue;
            }
            if (std.ascii.eqlIgnoreCase(args[i], "EX") or std.ascii.eqlIgnoreCase(args[i], "PX")) {
                if (i + 1 >= args.len) return Error.MalformedRequest;
                const ttl_raw = std.fmt.parseInt(i64, args[i + 1], 10) catch return Error.InvalidNumber;
                const mult: i64 = if (std.ascii.eqlIgnoreCase(args[i], "EX"))
                    @as(i64, @intCast(std.time.ns_per_s))
                else
                    @as(i64, @intCast(std.time.ns_per_ms));
                const ttl_ns = std.math.mul(i64, ttl_raw, mult) catch return Error.InvalidNumber;
                options.ttl_ns = ttl_ns;
                i += 2;
                continue;
            }
            return Error.MalformedRequest;
        }
        if (options.nx and options.xx) return Error.MalformedRequest;
        return .{ .set = .{ .key = args[1], .value = args[2], .options = options } };
    }
    if (std.ascii.eqlIgnoreCase(cmd, "DEL")) {
        if (args.len != 2) return Error.MalformedRequest;
        if (args[1].len > limits.max_key_length) return Error.ValueTooLarge;
        return .{ .delete = .{ .key = args[1] } };
    }
    if (std.ascii.eqlIgnoreCase(cmd, "INCR")) {
        if (args.len != 2) return Error.MalformedRequest;
        if (args[1].len > limits.max_key_length) return Error.ValueTooLarge;
        return .{ .incr = .{ .key = args[1] } };
    }
    if (std.ascii.eqlIgnoreCase(cmd, "DECR")) {
        if (args.len != 2) return Error.MalformedRequest;
        if (args[1].len > limits.max_key_length) return Error.ValueTooLarge;
        return .{ .decr = .{ .key = args[1] } };
    }
    if (std.ascii.eqlIgnoreCase(cmd, "EXPIRE")) {
        if (args.len != 3) return Error.MalformedRequest;
        if (args[1].len > limits.max_key_length) return Error.ValueTooLarge;
        const ttl_raw = std.fmt.parseInt(i64, args[2], 10) catch return Error.InvalidNumber;
        const ttl_ns = std.math.mul(i64, ttl_raw, @as(i64, @intCast(std.time.ns_per_s))) catch return Error.InvalidNumber;
        return .{ .expire = .{ .key = args[1], .ttl_ns = ttl_ns } };
    }
    if (std.ascii.eqlIgnoreCase(cmd, "TTL")) {
        if (args.len != 2) return Error.MalformedRequest;
        if (args[1].len > limits.max_key_length) return Error.ValueTooLarge;
        return .{ .ttl = .{ .key = args[1] } };
    }
    if (std.ascii.eqlIgnoreCase(cmd, "SAVE") or std.ascii.eqlIgnoreCase(cmd, "LOAD")) {
        const is_save = std.ascii.eqlIgnoreCase(cmd, "SAVE");
        var persist_cmd = PersistCommand{};
        var i: usize = 1;
        while (i < args.len) {
            if (std.ascii.eqlIgnoreCase(args[i], "FAST")) {
                persist_cmd.fast = true;
                i += 1;
                continue;
            }
            const marker = if (is_save) "TO" else "FROM";
            if (std.ascii.eqlIgnoreCase(args[i], marker)) {
                if (i + 1 >= args.len) return Error.MalformedRequest;
                if (persist_cmd.path != null) return Error.MalformedRequest;
                persist_cmd.path = args[i + 1];
                i += 2;
                continue;
            }
            return Error.MalformedRequest;
        }
        return if (is_save) .{ .save = persist_cmd } else .{ .load = persist_cmd };
    }
    return Error.MalformedRequest;
}

fn findCrlf(buf: []const u8, start: usize) ?usize {
    return std.mem.indexOfPos(u8, buf, start, "\r\n");
}

test "resp parser handles GET command" {
    var parser = Parser.init(.{});
    const buf = "*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expectEqualStrings("mykey", res.ok.command.get.key);
}

test "resp parser handles SET command" {
    var parser = Parser.init(.{});
    const buf = "*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$5\r\nvalue\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expectEqualStrings("value", res.ok.command.set.value);
}

test "resp parser handles SET with EX" {
    var parser = Parser.init(.{});
    const buf = "*5\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$5\r\nvalue\r\n$2\r\nEX\r\n$2\r\n10\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expectEqual(@as(i64, 10) * @as(i64, @intCast(std.time.ns_per_s)), res.ok.command.set.options.ttl_ns);
}

test "resp parser handles DEL command" {
    var parser = Parser.init(.{});
    const buf = "*2\r\n$3\r\nDEL\r\n$5\r\nmykey\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expectEqualStrings("mykey", res.ok.command.delete.key);
}

test "resp parser handles INCR command" {
    var parser = Parser.init(.{});
    const buf = "*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expectEqualStrings("counter", res.ok.command.incr.key);
}

test "resp parser handles PING command" {
    var parser = Parser.init(.{});
    const buf = "*1\r\n$4\r\nPING\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command == .ping);
}

test "resp parser handles INFO command" {
    var parser = Parser.init(.{});
    const buf = "*1\r\n$4\r\nINFO\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command == .info);
}

test "resp parser handles STATS command" {
    var parser = Parser.init(.{});
    const buf = "*1\r\n$5\r\nSTATS\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command == .stats);
}

test "resp parser supports pipeline" {
    var parser = Parser.init(.{});
    const buf = "*2\r\n$3\r\nGET\r\n$1\r\na\r\n*2\r\n$3\r\nGET\r\n$1\r\nb\r\n";
    var out: [2]Command = undefined;
    var pos: usize = 0;
    var count: usize = 0;
    while (pos < buf.len and count < out.len) {
        const res = parser.parse(buf[pos..], false);
        try std.testing.expect(res == .ok);
        out[count] = res.ok.command;
        pos += res.ok.consumed;
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("a", out[0].get.key);
    try std.testing.expectEqualStrings("b", out[1].get.key);
}

test "resp parser detects malformed bulk length" {
    var parser = Parser.init(.{});
    const buf = "*2\r\n$3\r\nGET\r\n$4\r\nshort\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .err);
    try std.testing.expectEqual(Error.MalformedRequest, res.err);
}

test "resp parser needs more for partial bulk and resumes" {
    var parser = Parser.init(.{});
    const part = "*2\r\n$3\r\nGET\r\n$5\r\nmy";
    const res1 = parser.parse(part, false);
    try std.testing.expect(res1 == .needs_more);
    const full = "*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
    const res2 = parser.parse(full, false);
    try std.testing.expect(res2 == .ok);
    try std.testing.expectEqualStrings("mykey", res2.ok.command.get.key);
}

test "resp parser reports connection closed on EOF" {
    var parser = Parser.init(.{});
    const res = parser.parse("*2\r\n$3\r\nGET\r\n", true);
    try std.testing.expect(res == .err);
    try std.testing.expectEqual(Error.ConnectionClosed, res.err);
}

test "resp parser enforces value length" {
    var parser = Parser.init(.{ .max_value_length = 3 });
    const buf = "*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .err);
    try std.testing.expectEqual(Error.ValueTooLarge, res.err);
}

test "resp parser handles SAVE and LOAD" {
    var parser = Parser.init(.{});
    const save_buf = "*1\r\n$4\r\nSAVE\r\n";
    var res = parser.parse(save_buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command == .save);
    try std.testing.expect(res.ok.command.save.path == null);
    try std.testing.expect(!res.ok.command.save.fast);

    const load_buf = "*4\r\n$4\r\nLOAD\r\n$4\r\nFROM\r\n$9\r\nsnap.cruc\r\n$4\r\nFAST\r\n";
    res = parser.parse(load_buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command == .load);
    try std.testing.expectEqualStrings("snap.cruc", res.ok.command.load.path.?);
    try std.testing.expect(res.ok.command.load.fast);
}
