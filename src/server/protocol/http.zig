const std = @import("std");
const comptime_parser = @import("comptime_parser.zig");

pub const Limits = comptime_parser.Limits;

pub const Error = error{
    NeedsMore,
    InvalidMethod,
    MalformedRequest,
    KeyTooLarge,
    ValueTooLarge,
    ConnectionClosed,
};

pub const Method = enum {
    get,
    post,
    put,
    delete,
};

pub const KeyCommand = struct {
    key: []const u8,
};

pub const SetCommand = struct {
    key: []const u8,
    value: []const u8,
    xx: bool,
};

pub const PersistCommand = struct {
    path: ?[]const u8 = null,
    fast: bool = false,
};

pub const Command = union(enum) {
    get: KeyCommand,
    set: SetCommand,
    delete: KeyCommand,
    save: PersistCommand,
    load: PersistCommand,
    health: void,
    stats: void,
    ops_not_found: void,
};

pub const ParsedCommand = struct {
    command: Command,
    consumed: usize,
    keepalive: bool,
};

pub const ParseResult = union(enum) {
    ok: ParsedCommand,
    needs_more: void,
    err: Error,
};

pub const State = struct {
    stage: Stage = .start,
    scan: usize = 0,
    header_end: usize = 0,
    content_length: usize = 0,
    keepalive: bool = false,
    method: Method = .get,
    key_start: usize = 0,
    key_end: usize = 0,
};

const Stage = enum { start, body };

pub fn initState() State {
    return .{};
}

pub fn parse(state: *State, buf: []const u8, limits: Limits, eof: bool) ParseResult {
    if (buf.len == 0) {
        return if (eof) .{ .err = Error.ConnectionClosed } else .{ .needs_more = {} };
    }

    if (state.stage == .body) {
        const needed = state.header_end + state.content_length;
        if (buf.len < needed) {
            return if (eof) .{ .err = Error.ConnectionClosed } else .{ .needs_more = {} };
        }
        const cmd = buildCommand(state, buf) catch |err| {
            state.* = initState();
            return .{ .err = err };
        };
        state.* = initState();
        return .{ .ok = cmd };
    }

    const header_pos = findHeaderEnd(buf, state.scan);
    if (header_pos == null) {
        state.scan = if (buf.len > 3) buf.len - 3 else 0;
        return if (eof) .{ .err = Error.ConnectionClosed } else .{ .needs_more = {} };
    }

    const header_end = header_pos.? + 4;
    state.header_end = header_end;
    state.scan = 0;

    const parse_res = parseHeaders(state, buf, limits) catch |err| {
        state.* = initState();
        return .{ .err = err };
    };
    _ = parse_res;

    if (state.content_length == 0 or state.method == .get or state.method == .delete) {
        if ((state.method == .get or state.method == .delete) and state.content_length != 0) {
            state.* = initState();
            return .{ .err = Error.MalformedRequest };
        }
        const cmd = buildCommand(state, buf) catch |err| {
            state.* = initState();
            return .{ .err = err };
        };
        state.* = initState();
        return .{ .ok = cmd };
    }

    const needed = header_end + state.content_length;
    if (buf.len < needed) {
        state.stage = .body;
        return if (eof) .{ .err = Error.ConnectionClosed } else .{ .needs_more = {} };
    }

    const cmd = buildCommand(state, buf) catch |err| {
        state.* = initState();
        return .{ .err = err };
    };
    state.* = initState();
    return .{ .ok = cmd };
}

fn findHeaderEnd(buf: []const u8, start: usize) ?usize {
    return std.mem.indexOfPos(u8, buf, start, "\r\n\r\n");
}

fn parseHeaders(state: *State, buf: []const u8, limits: Limits) Error!void {
    const line_end = std.mem.indexOf(u8, buf, "\r\n") orelse return Error.MalformedRequest;
    const line = buf[0..line_end];

    const method_end = std.mem.indexOfScalar(u8, line, ' ') orelse return Error.MalformedRequest;
    const method = parseMethod(line[0..method_end]) orelse return Error.InvalidMethod;

    const path_start = method_end + 1;
    const path_end = std.mem.indexOfScalarPos(u8, line, path_start, ' ') orelse return Error.MalformedRequest;
    if (path_end <= path_start) return Error.MalformedRequest;

    const version_start = path_end + 1;
    if (version_start >= line.len) return Error.MalformedRequest;
    if (!std.mem.eql(u8, line[version_start..], "HTTP/1.1")) return Error.MalformedRequest;

    const path = line[path_start..path_end];
    if (path.len == 0 or path[0] != '/') return Error.MalformedRequest;
    const key = path[1..];
    if (key.len == 0) return Error.MalformedRequest;
    if (key.len > limits.max_key_length) return Error.KeyTooLarge;

    state.method = method;
    state.key_start = path_start + 1;
    state.key_end = path_end;
    state.keepalive = true;
    state.content_length = 0;

    var idx = line_end + 2;
    while (idx + 1 < state.header_end) {
        const hdr_end = std.mem.indexOfPos(u8, buf, idx, "\r\n") orelse break;
        if (hdr_end == idx) break;
        const header_line = buf[idx..hdr_end];
        parseHeaderLine(state, header_line, limits) catch |err| return err;
        idx = hdr_end + 2;
    }

    if ((method == .post or method == .put) and state.content_length == 0) {
        const persist_key = buf[state.key_start..state.key_end];
        const split = splitQuery(persist_key);
        if (!(method == .post and isPersistOp(split.base))) {
            return Error.MalformedRequest;
        }
    }
}

fn parseHeaderLine(state: *State, line: []const u8, limits: Limits) Error!void {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return;
    const name = std.mem.trim(u8, line[0..colon], " \t");
    const value = std.mem.trim(u8, line[colon + 1 ..], " \t");

    if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
        const len = std.fmt.parseInt(usize, value, 10) catch return Error.MalformedRequest;
        if (len > limits.max_value_length) return Error.ValueTooLarge;
        state.content_length = len;
        return;
    }

    if (std.ascii.eqlIgnoreCase(name, "Connection")) {
        if (containsIgnoreCase(value, "close")) {
            state.keepalive = false;
        } else if (containsIgnoreCase(value, "keep-alive")) {
            state.keepalive = true;
        }
    }
}

fn parseMethod(slice: []const u8) ?Method {
    if (std.mem.eql(u8, slice, "GET")) return .get;
    if (std.mem.eql(u8, slice, "POST")) return .post;
    if (std.mem.eql(u8, slice, "PUT")) return .put;
    if (std.mem.eql(u8, slice, "DELETE")) return .delete;
    return null;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn buildCommand(state: *const State, buf: []const u8) Error!ParsedCommand {
    const key = buf[state.key_start..state.key_end];
    if (key.len > 0 and key[0] == '@') {
        const split = splitQuery(key);
        if (state.method == .post and std.mem.eql(u8, split.base, "@save")) {
            const cmd = parsePersistQuery(split.query);
            const consumed = state.header_end + state.content_length;
            return .{
                .command = .{ .save = cmd },
                .consumed = consumed,
                .keepalive = state.keepalive,
            };
        }
        if (state.method == .post and std.mem.eql(u8, split.base, "@load")) {
            const cmd = parsePersistQuery(split.query);
            const consumed = state.header_end + state.content_length;
            return .{
                .command = .{ .load = cmd },
                .consumed = consumed,
                .keepalive = state.keepalive,
            };
        }
        if (state.method == .get) {
            if (std.mem.eql(u8, key, "@health")) {
                return .{
                    .command = .{ .health = {} },
                    .consumed = state.header_end,
                    .keepalive = state.keepalive,
                };
            }
            if (std.mem.eql(u8, key, "@stats")) {
                return .{
                    .command = .{ .stats = {} },
                    .consumed = state.header_end,
                    .keepalive = state.keepalive,
                };
            }
        }
        const consumed = if (state.method == .post or state.method == .put)
            state.header_end + state.content_length
        else
            state.header_end;
        return .{
            .command = .{ .ops_not_found = {} },
            .consumed = consumed,
            .keepalive = state.keepalive,
        };
    }
    return switch (state.method) {
        .get => .{
            .command = .{ .get = .{ .key = key } },
            .consumed = state.header_end,
            .keepalive = state.keepalive,
        },
        .delete => .{
            .command = .{ .delete = .{ .key = key } },
            .consumed = state.header_end,
            .keepalive = state.keepalive,
        },
        .post => .{
            .command = .{ .set = .{ .key = key, .value = buf[state.header_end .. state.header_end + state.content_length], .xx = false } },
            .consumed = state.header_end + state.content_length,
            .keepalive = state.keepalive,
        },
        .put => .{
            .command = .{ .set = .{ .key = key, .value = buf[state.header_end .. state.header_end + state.content_length], .xx = true } },
            .consumed = state.header_end + state.content_length,
            .keepalive = state.keepalive,
        },
    };
}

fn splitQuery(key: []const u8) struct { base: []const u8, query: ?[]const u8 } {
    if (std.mem.indexOfScalar(u8, key, '?')) |idx| {
        return .{ .base = key[0..idx], .query = key[idx + 1 ..] };
    }
    return .{ .base = key, .query = null };
}

fn isPersistOp(base: []const u8) bool {
    return std.mem.eql(u8, base, "@save") or std.mem.eql(u8, base, "@load");
}

fn parsePersistQuery(query: ?[]const u8) PersistCommand {
    var cmd = PersistCommand{};
    const q = query orelse return cmd;
    var it = std.mem.splitScalar(u8, q, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const name = pair[0..eq];
        const value = pair[eq + 1 ..];
        if (std.mem.eql(u8, name, "path")) {
            if (value.len > 0) cmd.path = value;
            continue;
        }
        if (std.mem.eql(u8, name, "fast")) {
            if (std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "true")) {
                cmd.fast = true;
            }
            continue;
        }
    }
    return cmd;
}

pub const Parser = comptime_parser.Parser(@This());

test "http parser handles GET" {
    var parser = Parser.init(.{});
    const res = parser.parse("GET /mykey HTTP/1.1\r\n\r\n", false);
    try std.testing.expect(res == .ok);
    try std.testing.expectEqualStrings("mykey", res.ok.command.get.key);
    try std.testing.expectEqual(@as(usize, "GET /mykey HTTP/1.1\r\n\r\n".len), res.ok.consumed);
    try std.testing.expect(res.ok.keepalive);
}

test "http parser handles POST" {
    var parser = Parser.init(.{});
    const buf = "POST /mykey HTTP/1.1\r\nContent-Length: 5\r\n\r\nvalue";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expectEqualStrings("mykey", res.ok.command.set.key);
    try std.testing.expectEqualStrings("value", res.ok.command.set.value);
    try std.testing.expect(!res.ok.command.set.xx);
}

test "http parser handles PUT" {
    var parser = Parser.init(.{});
    const buf = "PUT /mykey HTTP/1.1\r\nContent-Length: 5\r\n\r\nvalue";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command.set.xx);
}

test "http parser handles DELETE" {
    var parser = Parser.init(.{});
    const res = parser.parse("DELETE /mykey HTTP/1.1\r\n\r\n", false);
    try std.testing.expect(res == .ok);
    try std.testing.expectEqualStrings("mykey", res.ok.command.delete.key);
}

test "http parser handles ops health" {
    var parser = Parser.init(.{});
    const res = parser.parse("GET /@health HTTP/1.1\r\n\r\n", false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command == .health);
}

test "http parser handles ops stats" {
    var parser = Parser.init(.{});
    const res = parser.parse("GET /@stats HTTP/1.1\r\n\r\n", false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command == .stats);
}

test "http parser marks unknown ops" {
    var parser = Parser.init(.{});
    const res = parser.parse("GET /@whoami HTTP/1.1\r\n\r\n", false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command == .ops_not_found);
}

test "http parser detects keepalive" {
    var parser = Parser.init(.{});
    const buf = "GET /k HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.keepalive);
}

test "http parser honors close" {
    var parser = Parser.init(.{});
    const buf = "GET /k HTTP/1.1\r\nConnection: close\r\n\r\n";
    const res = parser.parse(buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(!res.ok.keepalive);
}

test "http parser rejects invalid method" {
    var parser = Parser.init(.{});
    const res = parser.parse("TRACE /k HTTP/1.1\r\n\r\n", false);
    try std.testing.expect(res == .err);
    try std.testing.expectEqual(Error.InvalidMethod, res.err);
}

test "http parser enforces key length" {
    var parser = Parser.init(.{ .max_key_length = 3 });
    const res = parser.parse("GET /abcd HTTP/1.1\r\n\r\n", false);
    try std.testing.expect(res == .err);
    try std.testing.expectEqual(Error.KeyTooLarge, res.err);
}

test "http parser enforces value length" {
    var parser = Parser.init(.{ .max_value_length = 3 });
    const res = parser.parse("POST /k HTTP/1.1\r\nContent-Length: 4\r\n\r\nvalue", false);
    try std.testing.expect(res == .err);
    try std.testing.expectEqual(Error.ValueTooLarge, res.err);
}

test "http parser needs more for partial headers" {
    var parser = Parser.init(.{});
    const res = parser.parse("GET /k HTTP/1.1\r\n", false);
    try std.testing.expect(res == .needs_more);
}

test "http parser needs more for partial body and resumes" {
    var parser = Parser.init(.{});
    const part = "POST /k HTTP/1.1\r\nContent-Length: 5\r\n\r\nva";
    const res1 = parser.parse(part, false);
    try std.testing.expect(res1 == .needs_more);
    const full = "POST /k HTTP/1.1\r\nContent-Length: 5\r\n\r\nvalue";
    const res2 = parser.parse(full, false);
    try std.testing.expect(res2 == .ok);
    try std.testing.expectEqualStrings("value", res2.ok.command.set.value);
}

test "http parser rejects missing content length" {
    var parser = Parser.init(.{});
    const res = parser.parse("POST /k HTTP/1.1\r\n\r\nvalue", false);
    try std.testing.expect(res == .err);
    try std.testing.expectEqual(Error.MalformedRequest, res.err);
}

test "http parser reports connection closed on EOF" {
    var parser = Parser.init(.{});
    const res = parser.parse("GET /k HTTP/1.1\r\n", true);
    try std.testing.expect(res == .err);
    try std.testing.expectEqual(Error.ConnectionClosed, res.err);
}

test "http parser handles save/load ops" {
    var parser = Parser.init(.{});
    const save_buf = "POST /@save?path=/tmp/snap&fast=1 HTTP/1.1\r\n\r\n";
    var res = parser.parse(save_buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command == .save);
    try std.testing.expectEqualStrings("/tmp/snap", res.ok.command.save.path.?);
    try std.testing.expect(res.ok.command.save.fast);

    const load_buf = "POST /@load HTTP/1.1\r\n\r\n";
    res = parser.parse(load_buf, false);
    try std.testing.expect(res == .ok);
    try std.testing.expect(res.ok.command == .load);
    try std.testing.expect(res.ok.command.load.path == null);
    try std.testing.expect(!res.ok.command.load.fast);
}
