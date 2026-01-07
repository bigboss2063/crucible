const std = @import("std");
const cache_mod = @import("../cache/mod.zig");
const buffer = @import("buffer.zig");
const http = @import("protocol/http.zig");
const resp = @import("protocol/resp.zig");
const stats = @import("stats.zig");
const resource_controls = @import("resource_controls.zig");

pub const ExecuteError = error{
    BufferOverflow,
    AsyncRequired,
};

pub const ExecResult = struct {
    close: bool,
    cache_error: bool = false,
};

pub fn executeHttp(
    cache: *cache_mod.api.Cache,
    cmd: http.Command,
    resource: ?*const resource_controls.ResourceControls,
    keepalive: bool,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
    stats_snapshot: ?stats.StatsSnapshot,
) ExecuteError!ExecResult {
    return switch (cmd) {
        .get => |get_cmd| handleHttpGet(cache, get_cmd, keepalive, out, allow_resize),
        .set => |set_cmd| handleHttpSet(cache, set_cmd, resource, keepalive, out, allow_resize),
        .delete => |del_cmd| handleHttpDelete(cache, del_cmd, keepalive, out, allow_resize),
        .save, .load => error.AsyncRequired,
        .health => handleHttpHealth(keepalive, out, allow_resize),
        .stats => handleHttpStats(keepalive, out, allow_resize, stats_snapshot),
        .ops_not_found => handleHttpOpsNotFound(keepalive, out, allow_resize),
    };
}

pub fn executeResp(
    cache: *cache_mod.api.Cache,
    cmd: resp.Command,
    resource: ?*const resource_controls.ResourceControls,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
    stats_snapshot: ?stats.StatsSnapshot,
) ExecuteError!ExecResult {
    return switch (cmd) {
        .get => |get_cmd| handleRespGet(cache, get_cmd, out, allow_resize),
        .set => |set_cmd| handleRespSet(cache, set_cmd, resource, out, allow_resize),
        .delete => |del_cmd| handleRespDelete(cache, del_cmd, out, allow_resize),
        .incr => |incr_cmd| handleRespIncrDecr(cache, incr_cmd.key, 1, resource, out, allow_resize),
        .decr => |decr_cmd| handleRespIncrDecr(cache, decr_cmd.key, -1, resource, out, allow_resize),
        .expire => |expire_cmd| handleRespExpire(cache, expire_cmd, out, allow_resize),
        .ttl => |ttl_cmd| handleRespTtl(cache, ttl_cmd, out, allow_resize),
        .save, .load => error.AsyncRequired,
        .ping => handleRespPing(out, allow_resize),
        .info => handleRespInfo(out, allow_resize, stats_snapshot),
        .stats => handleRespInfo(out, allow_resize, stats_snapshot),
    };
}

fn handleHttpGet(
    cache: *cache_mod.api.Cache,
    cmd: http.KeyCommand,
    keepalive: bool,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
) ExecuteError!ExecResult {
    const entry = cache_mod.engine.load(cache, cmd.key, .{}) catch {
        try writeHttpError(out, allow_resize, 500, "Internal Server Error", keepalive);
        return .{ .close = !keepalive, .cache_error = true };
    };
    if (entry) |handle| {
        defer handle.release();
        const value = handle.value();
        try writeHttpResponse(out, allow_resize, 200, "OK", value, keepalive);
    } else {
        try writeHttpResponse(out, allow_resize, 404, "Not Found", "", keepalive);
    }
    return .{ .close = !keepalive };
}

fn handleHttpSet(
    cache: *cache_mod.api.Cache,
    cmd: http.SetCommand,
    resource: ?*const resource_controls.ResourceControls,
    keepalive: bool,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
) ExecuteError!ExecResult {
    const lowmem = if (resource) |controls| controls.lowmem.load(.acquire) else false;
    if (resource) |controls| {
        if (lowmem and !controls.evict) {
            try writeHttpResponse(out, allow_resize, 500, "Internal Server Error", "ERR out of memory\r\n", keepalive);
            return .{ .close = !keepalive, .cache_error = true };
        }
    }
    const result = cache_mod.engine.store(cache, cmd.key, cmd.value, .{
        .xx = cmd.xx,
        .lowmem = lowmem,
    }) catch |err| {
        if (err == error.OutOfMemory) {
            try writeHttpResponse(out, allow_resize, 500, "Internal Server Error", "ERR out of memory\r\n", keepalive);
        } else {
            try writeHttpError(out, allow_resize, 500, "Internal Server Error", keepalive);
        }
        return .{ .close = !keepalive, .cache_error = true };
    };
    switch (result) {
        .Inserted => try writeHttpResponse(out, allow_resize, 201, "Created", "", keepalive),
        .Replaced => try writeHttpResponse(out, allow_resize, 200, "OK", "", keepalive),
        .NotFound => try writeHttpResponse(out, allow_resize, 404, "Not Found", "", keepalive),
        .Found, .Canceled => try writeHttpResponse(out, allow_resize, 409, "Conflict", "", keepalive),
    }
    return .{ .close = !keepalive };
}

fn handleHttpDelete(
    cache: *cache_mod.api.Cache,
    cmd: http.KeyCommand,
    keepalive: bool,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
) ExecuteError!ExecResult {
    const result = cache_mod.engine.delete(cache, cmd.key, .{});
    switch (result) {
        .Deleted => try writeHttpResponse(out, allow_resize, 200, "OK", "", keepalive),
        .NotFound => try writeHttpResponse(out, allow_resize, 404, "Not Found", "", keepalive),
        .Canceled => try writeHttpResponse(out, allow_resize, 409, "Conflict", "", keepalive),
    }
    return .{ .close = !keepalive };
}


fn handleHttpHealth(keepalive: bool, out: *buffer.LinearBuffer, allow_resize: bool) ExecuteError!ExecResult {
    try writeHttpResponse(out, allow_resize, 200, "OK", "OK", keepalive);
    return .{ .close = !keepalive };
}

fn handleHttpStats(
    keepalive: bool,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
    snapshot: ?stats.StatsSnapshot,
) ExecuteError!ExecResult {
    const payload = snapshot orelse {
        try writeHttpError(out, allow_resize, 500, "Internal Server Error", keepalive);
        return .{ .close = !keepalive };
    };
    var body_buf: [1024]u8 = undefined;
    const body = stats.formatJson(payload, &body_buf) catch {
        try writeHttpError(out, allow_resize, 500, "Internal Server Error", keepalive);
        return .{ .close = !keepalive };
    };

    var header_buf: [256]u8 = undefined;
    const header = buildHttpHeader(&header_buf, 200, "OK", body.len, keepalive, "application/json") catch {
        try writeHttpError(out, allow_resize, 500, "Internal Server Error", keepalive);
        return .{ .close = !keepalive };
    };

    try ensureWritable(out, allow_resize, header.len + body.len);
    try writeAll(out, allow_resize, header);
    try writeAll(out, allow_resize, body);
    return .{ .close = !keepalive };
}

fn handleHttpOpsNotFound(keepalive: bool, out: *buffer.LinearBuffer, allow_resize: bool) ExecuteError!ExecResult {
    try writeHttpResponse(out, allow_resize, 404, "Not Found", "", keepalive);
    return .{ .close = !keepalive };
}

fn handleRespGet(
    cache: *cache_mod.api.Cache,
    cmd: resp.KeyCommand,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
) ExecuteError!ExecResult {
    const entry = cache_mod.engine.load(cache, cmd.key, .{}) catch {
        try writeRespError(out, allow_resize, "ERR internal error");
        return .{ .close = false, .cache_error = true };
    };
    if (entry) |handle| {
        defer handle.release();
        const value = handle.value();
        try writeRespBulk(out, allow_resize, value);
    } else {
        try writeRespNullBulk(out, allow_resize);
    }
    return .{ .close = false };
}

fn handleRespSet(
    cache: *cache_mod.api.Cache,
    cmd: resp.SetCommand,
    resource: ?*const resource_controls.ResourceControls,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
) ExecuteError!ExecResult {
    const lowmem = if (resource) |controls| controls.lowmem.load(.acquire) else false;
    if (resource) |controls| {
        if (lowmem and !controls.evict) {
            try writeRespError(out, allow_resize, "ERR out of memory");
            return .{ .close = false, .cache_error = true };
        }
    }
    const result = cache_mod.engine.store(cache, cmd.key, cmd.value, .{
        .nx = cmd.options.nx,
        .xx = cmd.options.xx,
        .ttl = cmd.options.ttl_ns,
        .lowmem = lowmem,
    }) catch |err| {
        if (err == error.OutOfMemory) {
            try writeRespError(out, allow_resize, "ERR out of memory");
        } else {
            try writeRespError(out, allow_resize, "ERR internal error");
        }
        return .{ .close = false, .cache_error = true };
    };
    switch (result) {
        .Inserted, .Replaced => try writeRespSimple(out, allow_resize, "OK"),
        .Found, .NotFound, .Canceled => try writeRespNullBulk(out, allow_resize),
    }
    return .{ .close = false };
}


fn handleRespDelete(
    cache: *cache_mod.api.Cache,
    cmd: resp.KeyCommand,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
) ExecuteError!ExecResult {
    const result = cache_mod.engine.delete(cache, cmd.key, .{});
    const val: i64 = if (result == .Deleted) 1 else 0;
    try writeRespInt(out, allow_resize, val);
    return .{ .close = false };
}

fn handleRespIncrDecr(
    cache: *cache_mod.api.Cache,
    key: []const u8,
    delta: i64,
    resource: ?*const resource_controls.ResourceControls,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
) ExecuteError!ExecResult {
    var cache_error = false;
    const updated = try updateCounter(cache, key, delta, resource, out, allow_resize, &cache_error);
    if (updated) |val| {
        try writeRespInt(out, allow_resize, val);
    }
    return .{ .close = false, .cache_error = cache_error };
}

fn updateCounter(
    cache: *cache_mod.api.Cache,
    key: []const u8,
    delta: i64,
    resource: ?*const resource_controls.ResourceControls,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
    cache_error: *bool,
) ExecuteError!?i64 {
    var buf: [32]u8 = undefined;
    while (true) {
        var updated: ?i64 = null;
        var ctx = struct {
            delta: i64,
            updated: *?i64,
            buf: *[32]u8,
        }{
            .delta = delta,
            .updated = &updated,
            .buf = &buf,
        };
        const entry = cache_mod.engine.load(cache, key, .{
            .update = (struct {
                fn apply(
                    _: u32,
                    _: i64,
                    _: []const u8,
                    value: []const u8,
                    expires: i64,
                    flags: u32,
                    _: u64,
                    udata: ?*anyopaque,
                ) ?cache_mod.api.Update {
                    const ctx_ptr = @as(*struct {
                        delta: i64,
                        updated: *?i64,
                        buf: *[32]u8,
                    }, @ptrCast(@alignCast(udata.?)));
                    const current = std.fmt.parseInt(i64, value, 10) catch return null;
                    const next = current + ctx_ptr.delta;
                    const slice = std.fmt.bufPrint(ctx_ptr.buf, "{d}", .{next}) catch return null;
                    ctx_ptr.updated.* = next;
                    return .{
                        .value = slice,
                        .flags = flags,
                        .expires = expires,
                    };
                }
            }).apply,
            .udata = &ctx,
        }) catch {
            try writeRespError(out, allow_resize, "ERR internal error");
            cache_error.* = true;
            return null;
        };

        if (entry) |handle| {
            handle.release();
            if (updated == null) {
                try writeRespError(out, allow_resize, "ERR value is not an integer");
                return null;
            }
            return updated;
        }

        const slice = std.fmt.bufPrint(&buf, "{d}", .{delta}) catch return ExecuteError.BufferOverflow;
        const lowmem = if (resource) |controls| controls.lowmem.load(.acquire) else false;
        if (resource) |controls| {
            if (lowmem and !controls.evict) {
                try writeRespError(out, allow_resize, "ERR out of memory");
                cache_error.* = true;
                return null;
            }
        }
        const store_res = cache_mod.engine.store(cache, key, slice, .{ .nx = true, .lowmem = lowmem }) catch |err| {
            if (err == error.OutOfMemory) {
                try writeRespError(out, allow_resize, "ERR out of memory");
            } else {
                try writeRespError(out, allow_resize, "ERR internal error");
            }
            cache_error.* = true;
            return null;
        };
        if (store_res == .Inserted) {
            return delta;
        }
        if (store_res == .Found) {
            continue;
        }
        if (store_res == .NotFound) {
            continue;
        }
        try writeRespError(out, allow_resize, "ERR update failed");
        return null;
    }
}

fn handleRespExpire(
    cache: *cache_mod.api.Cache,
    cmd: resp.ExpireCommand,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
) ExecuteError!ExecResult {
    var updated: bool = false;
    const now_time = cache_mod.engine.now();
    var ctx = struct {
        updated: *bool,
        now_time: i64,
        ttl: i64,
    }{
        .updated = &updated,
        .now_time = now_time,
        .ttl = cmd.ttl_ns,
    };
    const res = cache_mod.engine.load(cache, cmd.key, .{
        .update = (struct {
            fn apply(
                _: u32,
                _: i64,
                _: []const u8,
                value: []const u8,
                _: i64,
                flags: u32,
                _: u64,
                    udata: ?*anyopaque,
                ) ?cache_mod.api.Update {
                const ctx_ptr = @as(*struct {
                    updated: *bool,
                    now_time: i64,
                    ttl: i64,
                }, @ptrCast(@alignCast(udata.?)));
                ctx_ptr.updated.* = true;
                return .{
                    .value = value,
                    .flags = flags,
                    .expires = ctx_ptr.now_time + ctx_ptr.ttl,
                };
            }
        }).apply,
        .udata = &ctx,
    }) catch {
        try writeRespError(out, allow_resize, "ERR internal error");
        return .{ .close = false, .cache_error = true };
    };
    if (res) |handle| {
        handle.release();
    }
    try writeRespInt(out, allow_resize, if (updated) 1 else 0);
    return .{ .close = false };
}

fn handleRespTtl(
    cache: *cache_mod.api.Cache,
    cmd: resp.KeyCommand,
    out: *buffer.LinearBuffer,
    allow_resize: bool,
) ExecuteError!ExecResult {
    const entry = cache_mod.engine.load(cache, cmd.key, .{}) catch {
        try writeRespError(out, allow_resize, "ERR internal error");
        return .{ .close = false, .cache_error = true };
    };
    if (entry) |handle| {
        defer handle.release();
        const expires = handle.expires();
        if (expires == 0) {
            try writeRespInt(out, allow_resize, -1);
        } else {
            const now_time = cache_mod.engine.now();
            if (expires <= now_time) {
                try writeRespInt(out, allow_resize, -2);
            } else {
                const remaining = @divTrunc(expires - now_time, @as(i64, @intCast(std.time.ns_per_s)));
                try writeRespInt(out, allow_resize, remaining);
            }
        }
    } else {
        try writeRespInt(out, allow_resize, -2);
    }
    return .{ .close = false };
}

fn handleRespPing(out: *buffer.LinearBuffer, allow_resize: bool) ExecuteError!ExecResult {
    try writeRespSimple(out, allow_resize, "PONG");
    return .{ .close = false };
}

fn handleRespInfo(out: *buffer.LinearBuffer, allow_resize: bool, snapshot: ?stats.StatsSnapshot) ExecuteError!ExecResult {
    const payload = snapshot orelse {
        try writeRespError(out, allow_resize, "ERR internal error");
        return .{ .close = false };
    };
    var body_buf: [1024]u8 = undefined;
    const body = stats.formatInfo(payload, &body_buf) catch {
        try writeRespError(out, allow_resize, "ERR internal error");
        return .{ .close = false };
    };

    var len_buf: [32]u8 = undefined;
    const len_slice = std.fmt.bufPrint(&len_buf, "{d}", .{@as(i64, @intCast(body.len))}) catch {
        try writeRespError(out, allow_resize, "ERR internal error");
        return .{ .close = false };
    };
    const needed = 1 + len_slice.len + 2 + body.len + 2;
    ensureWritable(out, allow_resize, needed) catch {
        try writeRespError(out, allow_resize, "ERR internal error");
        return .{ .close = false };
    };

    try writeAll(out, allow_resize, "$");
    try writeAll(out, allow_resize, len_slice);
    try writeAll(out, allow_resize, "\r\n");
    try writeAll(out, allow_resize, body);
    try writeAll(out, allow_resize, "\r\n");
    return .{ .close = false };
}

fn buildHttpHeader(
    buf: []u8,
    code: u16,
    reason: []const u8,
    body_len: usize,
    keepalive: bool,
    content_type: ?[]const u8,
) ExecuteError![]const u8 {
    const conn = if (keepalive) "keep-alive" else "close";
    if (content_type) |ct| {
        return std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: {s}\r\nContent-Type: {s}\r\n\r\n", .{
            code,
            reason,
            body_len,
            conn,
            ct,
        }) catch return ExecuteError.BufferOverflow;
    }
    return std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: {s}\r\n\r\n", .{
        code,
        reason,
        body_len,
        conn,
    }) catch return ExecuteError.BufferOverflow;
}

fn writeHttpResponseWithType(
    out: *buffer.LinearBuffer,
    allow_resize: bool,
    code: u16,
    reason: []const u8,
    body: []const u8,
    keepalive: bool,
    content_type: ?[]const u8,
) ExecuteError!void {
    var header_buf: [256]u8 = undefined;
    const header = try buildHttpHeader(&header_buf, code, reason, body.len, keepalive, content_type);
    try ensureWritable(out, allow_resize, header.len + body.len);
    appendUnchecked(out, header);
    appendUnchecked(out, body);
}

fn writeHttpResponse(
    out: *buffer.LinearBuffer,
    allow_resize: bool,
    code: u16,
    reason: []const u8,
    body: []const u8,
    keepalive: bool,
) ExecuteError!void {
    try writeHttpResponseWithType(out, allow_resize, code, reason, body, keepalive, null);
}

fn writeHttpError(
    out: *buffer.LinearBuffer,
    allow_resize: bool,
    code: u16,
    reason: []const u8,
    keepalive: bool,
) ExecuteError!void {
    try writeHttpResponse(out, allow_resize, code, reason, "", keepalive);
}

fn writeRespSimple(out: *buffer.LinearBuffer, allow_resize: bool, msg: []const u8) ExecuteError!void {
    try ensureWritable(out, allow_resize, 1 + msg.len + 2);
    appendUnchecked(out, "+");
    appendUnchecked(out, msg);
    appendUnchecked(out, "\r\n");
}

fn writeRespError(out: *buffer.LinearBuffer, allow_resize: bool, msg: []const u8) ExecuteError!void {
    try ensureWritable(out, allow_resize, 1 + msg.len + 2);
    appendUnchecked(out, "-");
    appendUnchecked(out, msg);
    appendUnchecked(out, "\r\n");
}

fn writeRespInt(out: *buffer.LinearBuffer, allow_resize: bool, value: i64) ExecuteError!void {
    var buf: [32]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return ExecuteError.BufferOverflow;
    try ensureWritable(out, allow_resize, 1 + slice.len + 2);
    appendUnchecked(out, ":");
    appendUnchecked(out, slice);
    appendUnchecked(out, "\r\n");
}

fn writeRespNullBulk(out: *buffer.LinearBuffer, allow_resize: bool) ExecuteError!void {
    try ensureWritable(out, allow_resize, 5);
    appendUnchecked(out, "$-1\r\n");
}

fn writeRespBulk(out: *buffer.LinearBuffer, allow_resize: bool, value: []const u8) ExecuteError!void {
    var len_buf: [32]u8 = undefined;
    const slice = std.fmt.bufPrint(&len_buf, "{d}", .{@as(i64, @intCast(value.len))}) catch return ExecuteError.BufferOverflow;
    try ensureWritable(out, allow_resize, 1 + slice.len + 2 + value.len + 2);
    appendUnchecked(out, "$");
    appendUnchecked(out, slice);
    appendUnchecked(out, "\r\n");
    appendUnchecked(out, value);
    appendUnchecked(out, "\r\n");
}

fn ensureWritable(out: *buffer.LinearBuffer, allow_resize: bool, len: usize) ExecuteError!void {
    if (len == 0) return;
    if (allow_resize) {
        if (!out.reserve(len)) return ExecuteError.BufferOverflow;
    } else {
        if (out.availableTail() < len) return ExecuteError.BufferOverflow;
    }
}

fn appendUnchecked(out: *buffer.LinearBuffer, data: []const u8) void {
    if (data.len == 0) return;
    std.debug.assert(out.availableTail() >= data.len);
    std.mem.copyForwards(u8, out.tailSlice()[0..data.len], data);
    out.commitWrite(data.len);
}

fn writeAll(out: *buffer.LinearBuffer, allow_resize: bool, data: []const u8) ExecuteError!void {
    if (data.len == 0) return;
    try ensureWritable(out, allow_resize, data.len);
    appendUnchecked(out, data);
}

test "http execution stores and loads" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var rb = try buffer.LinearBuffer.init(allocator, 512, 512);
    defer rb.deinit();

    _ = try executeHttp(cache_instance, .{ .set = .{ .key = "k", .value = "v", .xx = false } }, null, false, &rb, true, null);
    const res = rb.readable();
    try std.testing.expect(std.mem.indexOf(u8, res, "201") != null);

    rb.clear();
    _ = try executeHttp(cache_instance, .{ .get = .{ .key = "k" } }, null, false, &rb, true, null);
    try std.testing.expect(std.mem.indexOf(u8, rb.readable(), "200") != null);
}

test "http execution put missing returns 404" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var rb = try buffer.LinearBuffer.init(allocator, 256, 256);
    defer rb.deinit();

    _ = try executeHttp(cache_instance, .{ .set = .{ .key = "missing", .value = "v", .xx = true } }, null, false, &rb, true, null);
    try std.testing.expect(std.mem.indexOf(u8, rb.readable(), "404") != null);
}

test "resp execution set/get" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var rb = try buffer.LinearBuffer.init(allocator, 256, 256);
    defer rb.deinit();

    _ = try executeResp(cache_instance, .{ .set = .{ .key = "k", .value = "v", .options = .{} } }, null, &rb, true, null);
    try std.testing.expectEqualStrings("+OK\r\n", rb.readable());

    rb.clear();
    _ = try executeResp(cache_instance, .{ .get = .{ .key = "k" } }, null, &rb, true, null);
    try std.testing.expect(std.mem.indexOf(u8, rb.readable(), "$1\r\nv\r\n") != null);
}

test "resp execution honors nx/xx options" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var rb = try buffer.LinearBuffer.init(allocator, 256, 256);
    defer rb.deinit();

    _ = try executeResp(cache_instance, .{ .set = .{ .key = "k", .value = "v", .options = .{} } }, null, &rb, true, null);
    rb.clear();

    _ = try executeResp(cache_instance, .{ .set = .{ .key = "k", .value = "v2", .options = .{ .nx = true } } }, null, &rb, true, null);
    try std.testing.expectEqualStrings("$-1\r\n", rb.readable());

    rb.clear();
    _ = try executeResp(cache_instance, .{ .set = .{ .key = "missing", .value = "v", .options = .{ .xx = true } } }, null, &rb, true, null);
    try std.testing.expectEqualStrings("$-1\r\n", rb.readable());
}

test "resp execution incr rejects non-integer" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var rb = try buffer.LinearBuffer.init(allocator, 256, 256);
    defer rb.deinit();

    _ = try executeResp(cache_instance, .{ .set = .{ .key = "k", .value = "abc", .options = .{} } }, null, &rb, true, null);
    rb.clear();

    _ = try executeResp(cache_instance, .{ .incr = .{ .key = "k" } }, null, &rb, true, null);
    try std.testing.expect(std.mem.indexOf(u8, rb.readable(), "ERR value is not an integer") != null);
}

test "resp execution ttl missing returns -2" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var rb = try buffer.LinearBuffer.init(allocator, 256, 256);
    defer rb.deinit();

    _ = try executeResp(cache_instance, .{ .ttl = .{ .key = "missing" } }, null, &rb, true, null);
    try std.testing.expectEqualStrings(":-2\r\n", rb.readable());
}

test "resp execution rejects writes when lowmem and eviction disabled" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var controls = resource_controls.ResourceControls.init(null, false, false);
    controls.lowmem.store(true, .release);

    var rb = try buffer.LinearBuffer.init(allocator, 128, 128);
    defer rb.deinit();

    _ = try executeResp(
        cache_instance,
        .{ .set = .{ .key = "k", .value = "v", .options = .{} } },
        &controls,
        &rb,
        true,
        null,
    );
    try std.testing.expectEqualStrings("-ERR out of memory\r\n", rb.readable());
}
