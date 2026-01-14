const std = @import("std");
const cache_mod = @import("../cache/mod.zig");
const http = @import("protocol/http.zig");
const resp = @import("protocol/resp.zig");
const stats = @import("stats.zig");
const resource_controls = @import("resource_controls.zig");
const aof = @import("aof.zig");

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
    writer: anytype,
    aof_mgr: ?*aof.Manager,
    stats_snapshot: ?stats.StatsSnapshot,
) ExecuteError!ExecResult {
    return switch (cmd) {
        .get => |get_cmd| handleHttpGet(cache, get_cmd, keepalive, writer),
        .set => |set_cmd| handleHttpSet(cache, set_cmd, resource, keepalive, writer, aof_mgr),
        .delete => |del_cmd| handleHttpDelete(cache, del_cmd, keepalive, writer, aof_mgr),
        .save, .load => error.AsyncRequired,
        .health => handleHttpHealth(keepalive, writer),
        .stats => handleHttpStats(keepalive, writer, stats_snapshot),
        .ops_not_found => handleHttpOpsNotFound(keepalive, writer),
    };
}

pub fn executeResp(
    cache: *cache_mod.api.Cache,
    cmd: resp.Command,
    resource: ?*const resource_controls.ResourceControls,
    writer: anytype,
    aof_mgr: ?*aof.Manager,
    stats_snapshot: ?stats.StatsSnapshot,
) ExecuteError!ExecResult {
    return switch (cmd) {
        .get => |get_cmd| handleRespGet(cache, get_cmd, writer),
        .set => |set_cmd| handleRespSet(cache, set_cmd, resource, writer, aof_mgr),
        .delete => |del_cmd| handleRespDelete(cache, del_cmd, writer, aof_mgr),
        .incr => |incr_cmd| handleRespIncrDecr(cache, incr_cmd.key, 1, resource, writer, aof_mgr),
        .decr => |decr_cmd| handleRespIncrDecr(cache, decr_cmd.key, -1, resource, writer, aof_mgr),
        .expire => |expire_cmd| handleRespExpire(cache, expire_cmd, writer, aof_mgr),
        .ttl => |ttl_cmd| handleRespTtl(cache, ttl_cmd, writer),
        .save, .load => error.AsyncRequired,
        .ping => handleRespPing(writer),
        .info => handleRespInfo(writer, stats_snapshot),
        .stats => handleRespInfo(writer, stats_snapshot),
        .monitor => error.AsyncRequired,
        .bgrewriteaof => error.AsyncRequired,
    };
}

fn handleHttpGet(
    cache: *cache_mod.api.Cache,
    cmd: http.KeyCommand,
    keepalive: bool,
    writer: anytype,
) ExecuteError!ExecResult {
    const entry = cache_mod.engine.load(cache, cmd.key, .{}) catch {
        try writeHttpError(writer, 500, "Internal Server Error", keepalive);
        return .{ .close = !keepalive, .cache_error = true };
    };
    if (entry) |handle| {
        defer handle.release();
        const value = handle.value();
        try writeHttpResponse(writer, 200, "OK", value, keepalive);
    } else {
        try writeHttpResponse(writer, 404, "Not Found", "", keepalive);
    }
    return .{ .close = !keepalive };
}

fn handleHttpSet(
    cache: *cache_mod.api.Cache,
    cmd: http.SetCommand,
    resource: ?*const resource_controls.ResourceControls,
    keepalive: bool,
    writer: anytype,
    aof_mgr: ?*aof.Manager,
) ExecuteError!ExecResult {
    const lowmem = if (resource) |controls| controls.lowmem.load(.acquire) else false;
    if (resource) |controls| {
        if (lowmem and !controls.evict) {
            try writeHttpResponse(writer, 500, "Internal Server Error", "ERR out of memory\r\n", keepalive);
            return .{ .close = !keepalive, .cache_error = true };
        }
    }
    const result = cache_mod.engine.store(cache, cmd.key, cmd.value, .{
        .xx = cmd.xx,
        .lowmem = lowmem,
    }) catch |err| {
        if (err == error.OutOfMemory) {
            try writeHttpResponse(writer, 500, "Internal Server Error", "ERR out of memory\r\n", keepalive);
        } else {
            try writeHttpError(writer, 500, "Internal Server Error", keepalive);
        }
        return .{ .close = !keepalive, .cache_error = true };
    };
    if (result == .Inserted or result == .Replaced) {
        if (aof_mgr) |mgr| {
            if (mgr.enabled()) {
                appendAofSet(cache, mgr, cmd.key) catch {
                    try writeHttpError(writer, 500, "Internal Server Error", keepalive);
                    return .{ .close = !keepalive, .cache_error = true };
                };
            }
        }
    }
    switch (result) {
        .Inserted => try writeHttpResponse(writer, 201, "Created", "", keepalive),
        .Replaced => try writeHttpResponse(writer, 200, "OK", "", keepalive),
        .NotFound => try writeHttpResponse(writer, 404, "Not Found", "", keepalive),
        .Found, .Canceled => try writeHttpResponse(writer, 409, "Conflict", "", keepalive),
    }
    return .{ .close = !keepalive };
}

fn handleHttpDelete(
    cache: *cache_mod.api.Cache,
    cmd: http.KeyCommand,
    keepalive: bool,
    writer: anytype,
    aof_mgr: ?*aof.Manager,
) ExecuteError!ExecResult {
    const result = cache_mod.engine.delete(cache, cmd.key, .{});
    if (aof_mgr) |mgr| {
        if (mgr.enabled()) {
            mgr.appendDel(cmd.key) catch {
                try writeHttpError(writer, 500, "Internal Server Error", keepalive);
                return .{ .close = !keepalive, .cache_error = true };
            };
        }
    }
    switch (result) {
        .Deleted => try writeHttpResponse(writer, 200, "OK", "", keepalive),
        .NotFound => try writeHttpResponse(writer, 404, "Not Found", "", keepalive),
        .Canceled => try writeHttpResponse(writer, 409, "Conflict", "", keepalive),
    }
    return .{ .close = !keepalive };
}


fn handleHttpHealth(keepalive: bool, writer: anytype) ExecuteError!ExecResult {
    try writeHttpResponse(writer, 200, "OK", "OK", keepalive);
    return .{ .close = !keepalive };
}

fn handleHttpStats(
    keepalive: bool,
    writer: anytype,
    snapshot: ?stats.StatsSnapshot,
) ExecuteError!ExecResult {
    const payload = snapshot orelse {
        try writeHttpError(writer, 500, "Internal Server Error", keepalive);
        return .{ .close = !keepalive };
    };
    var body_buf: [1024]u8 = undefined;
    const body = stats.formatJson(payload, &body_buf) catch {
        try writeHttpError(writer, 500, "Internal Server Error", keepalive);
        return .{ .close = !keepalive };
    };

    var header_buf: [256]u8 = undefined;
    const header = buildHttpHeader(&header_buf, 200, "OK", body.len, keepalive, "application/json") catch {
        try writeHttpError(writer, 500, "Internal Server Error", keepalive);
        return .{ .close = !keepalive };
    };

    try writeAll(writer, header);
    try writeAll(writer, body);
    return .{ .close = !keepalive };
}

fn handleHttpOpsNotFound(keepalive: bool, writer: anytype) ExecuteError!ExecResult {
    try writeHttpResponse(writer, 404, "Not Found", "", keepalive);
    return .{ .close = !keepalive };
}

fn handleRespGet(
    cache: *cache_mod.api.Cache,
    cmd: resp.KeyCommand,
    writer: anytype,
) ExecuteError!ExecResult {
    const entry = cache_mod.engine.load(cache, cmd.key, .{}) catch {
        try writeRespError(writer, "ERR internal error");
        return .{ .close = false, .cache_error = true };
    };
    if (entry) |handle| {
        defer handle.release();
        const value = handle.value();
        try writeRespBulk(writer, value);
    } else {
        try writeRespNullBulk(writer);
    }
    return .{ .close = false };
}

fn handleRespSet(
    cache: *cache_mod.api.Cache,
    cmd: resp.SetCommand,
    resource: ?*const resource_controls.ResourceControls,
    writer: anytype,
    aof_mgr: ?*aof.Manager,
) ExecuteError!ExecResult {
    const lowmem = if (resource) |controls| controls.lowmem.load(.acquire) else false;
    if (resource) |controls| {
        if (lowmem and !controls.evict) {
            try writeRespError(writer, "ERR out of memory");
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
            try writeRespError(writer, "ERR out of memory");
        } else {
            try writeRespError(writer, "ERR internal error");
        }
        return .{ .close = false, .cache_error = true };
    };
    if (result == .Inserted or result == .Replaced) {
        if (aof_mgr) |mgr| {
            if (mgr.enabled()) {
                appendAofSet(cache, mgr, cmd.key) catch {
                    try writeRespError(writer, "ERR persistence failed");
                    return .{ .close = false, .cache_error = true };
                };
            }
        }
    }
    switch (result) {
        .Inserted, .Replaced => try writeRespSimple(writer, "OK"),
        .Found, .NotFound, .Canceled => try writeRespNullBulk(writer),
    }
    return .{ .close = false };
}


fn handleRespDelete(
    cache: *cache_mod.api.Cache,
    cmd: resp.KeyCommand,
    writer: anytype,
    aof_mgr: ?*aof.Manager,
) ExecuteError!ExecResult {
    const result = cache_mod.engine.delete(cache, cmd.key, .{});
    if (aof_mgr) |mgr| {
        if (mgr.enabled()) {
            mgr.appendDel(cmd.key) catch {
                try writeRespError(writer, "ERR persistence failed");
                return .{ .close = false, .cache_error = true };
            };
        }
    }
    const val: i64 = if (result == .Deleted) 1 else 0;
    try writeRespInt(writer, val);
    return .{ .close = false };
}

fn handleRespIncrDecr(
    cache: *cache_mod.api.Cache,
    key: []const u8,
    delta: i64,
    resource: ?*const resource_controls.ResourceControls,
    writer: anytype,
    aof_mgr: ?*aof.Manager,
) ExecuteError!ExecResult {
    var cache_error = false;
    const updated = try updateCounter(cache, key, delta, resource, writer, &cache_error);
    if (updated) |val| {
        if (aof_mgr) |mgr| {
            if (mgr.enabled()) {
                appendAofSet(cache, mgr, key) catch {
                    try writeRespError(writer, "ERR persistence failed");
                    return .{ .close = false, .cache_error = true };
                };
            }
        }
        try writeRespInt(writer, val);
    }
    return .{ .close = false, .cache_error = cache_error };
}

fn updateCounter(
    cache: *cache_mod.api.Cache,
    key: []const u8,
    delta: i64,
    resource: ?*const resource_controls.ResourceControls,
    writer: anytype,
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
            try writeRespError(writer, "ERR internal error");
            cache_error.* = true;
            return null;
        };

        if (entry) |handle| {
            handle.release();
            if (updated == null) {
                try writeRespError(writer, "ERR value is not an integer");
                return null;
            }
            return updated;
        }

        const slice = std.fmt.bufPrint(&buf, "{d}", .{delta}) catch return ExecuteError.BufferOverflow;
        const lowmem = if (resource) |controls| controls.lowmem.load(.acquire) else false;
        if (resource) |controls| {
            if (lowmem and !controls.evict) {
                try writeRespError(writer, "ERR out of memory");
                cache_error.* = true;
                return null;
            }
        }
        const store_res = cache_mod.engine.store(cache, key, slice, .{ .nx = true, .lowmem = lowmem }) catch |err| {
            if (err == error.OutOfMemory) {
                try writeRespError(writer, "ERR out of memory");
            } else {
                try writeRespError(writer, "ERR internal error");
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
        try writeRespError(writer, "ERR update failed");
        return null;
    }
}

fn handleRespExpire(
    cache: *cache_mod.api.Cache,
    cmd: resp.ExpireCommand,
    writer: anytype,
    aof_mgr: ?*aof.Manager,
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
        try writeRespError(writer, "ERR internal error");
        return .{ .close = false, .cache_error = true };
    };
    if (res) |handle| {
        handle.release();
    }
    if (updated) {
        if (aof_mgr) |mgr| {
            if (mgr.enabled()) {
                const expire_unix_ns = @as(u64, @intCast(now_time + cmd.ttl_ns));
                mgr.appendExpire(cmd.key, expire_unix_ns) catch {
                    try writeRespError(writer, "ERR persistence failed");
                    return .{ .close = false, .cache_error = true };
                };
            }
        }
    }
    try writeRespInt(writer, if (updated) 1 else 0);
    return .{ .close = false };
}

fn handleRespTtl(
    cache: *cache_mod.api.Cache,
    cmd: resp.KeyCommand,
    writer: anytype,
) ExecuteError!ExecResult {
    const entry = cache_mod.engine.load(cache, cmd.key, .{}) catch {
        try writeRespError(writer, "ERR internal error");
        return .{ .close = false, .cache_error = true };
    };
    if (entry) |handle| {
        defer handle.release();
        const expires = handle.expires();
        if (expires == 0) {
            try writeRespInt(writer, -1);
        } else {
            const now_time = cache_mod.engine.now();
            if (expires <= now_time) {
                try writeRespInt(writer, -2);
            } else {
                const remaining = @divTrunc(expires - now_time, @as(i64, @intCast(std.time.ns_per_s)));
                try writeRespInt(writer, remaining);
            }
        }
    } else {
        try writeRespInt(writer, -2);
    }
    return .{ .close = false };
}

fn handleRespPing(writer: anytype) ExecuteError!ExecResult {
    try writeRespSimple(writer, "PONG");
    return .{ .close = false };
}

fn handleRespInfo(writer: anytype, snapshot: ?stats.StatsSnapshot) ExecuteError!ExecResult {
    const payload = snapshot orelse {
        try writeRespError(writer, "ERR internal error");
        return .{ .close = false };
    };
    var body_buf: [1024]u8 = undefined;
    const body = stats.formatInfo(payload, &body_buf) catch {
        try writeRespError(writer, "ERR internal error");
        return .{ .close = false };
    };

    var len_buf: [32]u8 = undefined;
    const len_slice = std.fmt.bufPrint(&len_buf, "{d}", .{@as(i64, @intCast(body.len))}) catch {
        try writeRespError(writer, "ERR internal error");
        return .{ .close = false };
    };
    try writeAll(writer, "$");
    try writeAll(writer, len_slice);
    try writeAll(writer, "\r\n");
    try writeAll(writer, body);
    try writeAll(writer, "\r\n");
    return .{ .close = false };
}

fn appendAofSet(cache: *cache_mod.api.Cache, mgr: *aof.Manager, key: []const u8) !void {
    const entry = cache_mod.engine.load(cache, key, .{ .notouch = true }) catch return error.PersistenceFailed;
    const handle = entry orelse return error.PersistenceFailed;
    defer handle.release();
    const value = handle.value();
    const flags = handle.flags();
    const cas = handle.cas();
    const expires = handle.expires();
    const expire_unix_ns: u64 = if (expires > 0) @as(u64, @intCast(expires)) else 0;
    try mgr.appendSet(key, value, flags, cas, expire_unix_ns);
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
    writer: anytype,
    code: u16,
    reason: []const u8,
    body: []const u8,
    keepalive: bool,
    content_type: ?[]const u8,
) ExecuteError!void {
    var header_buf: [256]u8 = undefined;
    const header = try buildHttpHeader(&header_buf, code, reason, body.len, keepalive, content_type);
    try writeAll(writer, header);
    try writeAll(writer, body);
}

fn writeHttpResponse(
    writer: anytype,
    code: u16,
    reason: []const u8,
    body: []const u8,
    keepalive: bool,
) ExecuteError!void {
    try writeHttpResponseWithType(writer, code, reason, body, keepalive, null);
}

fn writeHttpError(
    writer: anytype,
    code: u16,
    reason: []const u8,
    keepalive: bool,
) ExecuteError!void {
    try writeHttpResponse(writer, code, reason, "", keepalive);
}

fn writeRespSimple(writer: anytype, msg: []const u8) ExecuteError!void {
    try writeAll(writer, "+");
    try writeAll(writer, msg);
    try writeAll(writer, "\r\n");
}

fn writeRespError(writer: anytype, msg: []const u8) ExecuteError!void {
    try writeAll(writer, "-");
    try writeAll(writer, msg);
    try writeAll(writer, "\r\n");
}

fn writeRespInt(writer: anytype, value: i64) ExecuteError!void {
    var buf: [32]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return ExecuteError.BufferOverflow;
    try writeAll(writer, ":");
    try writeAll(writer, slice);
    try writeAll(writer, "\r\n");
}

fn writeRespNullBulk(writer: anytype) ExecuteError!void {
    try writeAll(writer, "$-1\r\n");
}

fn writeRespBulk(writer: anytype, value: []const u8) ExecuteError!void {
    var len_buf: [32]u8 = undefined;
    const slice = std.fmt.bufPrint(&len_buf, "{d}", .{@as(i64, @intCast(value.len))}) catch return ExecuteError.BufferOverflow;
    try writeAll(writer, "$");
    try writeAll(writer, slice);
    try writeAll(writer, "\r\n");
    try writeAll(writer, value);
    try writeAll(writer, "\r\n");
}

fn writeAll(writer: anytype, data: []const u8) ExecuteError!void {
    if (data.len == 0) return;
    writer.writeAll(data) catch return ExecuteError.BufferOverflow;
}

test "http execution stores and loads" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    var writer = out.writer(allocator);
    _ = try executeHttp(cache_instance, .{ .set = .{ .key = "k", .value = "v", .xx = false } }, null, false, writer, null, null);
    const res = out.items;
    try std.testing.expect(std.mem.indexOf(u8, res, "201") != null);

    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeHttp(cache_instance, .{ .get = .{ .key = "k" } }, null, false, writer, null, null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "200") != null);
}

test "http execution put missing returns 404" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    const writer = out.writer(allocator);
    _ = try executeHttp(cache_instance, .{ .set = .{ .key = "missing", .value = "v", .xx = true } }, null, false, writer, null, null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "404") != null);
}

test "resp execution set/get" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    var writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .set = .{ .key = "k", .value = "v", .options = .{} } }, null, writer, null, null);
    try std.testing.expectEqualStrings("+OK\r\n", out.items);

    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .get = .{ .key = "k" } }, null, writer, null, null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "$1\r\nv\r\n") != null);
}

test "resp execution honors nx/xx options" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    var writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .set = .{ .key = "k", .value = "v", .options = .{} } }, null, writer, null, null);
    out.clearRetainingCapacity();

    writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .set = .{ .key = "k", .value = "v2", .options = .{ .nx = true } } }, null, writer, null, null);
    try std.testing.expectEqualStrings("$-1\r\n", out.items);

    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .set = .{ .key = "missing", .value = "v", .options = .{ .xx = true } } }, null, writer, null, null);
    try std.testing.expectEqualStrings("$-1\r\n", out.items);
}

test "resp execution incr rejects non-integer" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    var writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .set = .{ .key = "k", .value = "abc", .options = .{} } }, null, writer, null, null);
    out.clearRetainingCapacity();

    writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .incr = .{ .key = "k" } }, null, writer, null, null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "ERR value is not an integer") != null);
}

test "resp execution ttl missing returns -2" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    const writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .ttl = .{ .key = "missing" } }, null, writer, null, null);
    try std.testing.expectEqualStrings(":-2\r\n", out.items);
}

test "resp execution rejects writes when lowmem and eviction disabled" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var controls = resource_controls.ResourceControls.init(null, false, false);
    controls.lowmem.store(true, .release);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    const writer = out.writer(allocator);
    _ = try executeResp(
        cache_instance,
        .{ .set = .{ .key = "k", .value = "v", .options = .{} } },
        &controls,
        writer,
        null,
        null,
    );
    try std.testing.expectEqualStrings("-ERR out of memory\r\n", out.items);
}

test "http execution delete ops not found and stats" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    _ = try cache_mod.engine.store(cache_instance, "k", "v", .{});
    var writer = out.writer(allocator);
    _ = try executeHttp(cache_instance, .{ .delete = .{ .key = "k" } }, null, false, writer, null, null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "200") != null);

    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeHttp(cache_instance, .{ .ops_not_found = {} }, null, false, writer, null, null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "404") != null);

    out.clearRetainingCapacity();
    const snapshot = stats.StatsSnapshot{
        .time_unix_ms = 1,
        .uptime_ms = 1,
        .server = .{
            .active_connections = 0,
            .total_connections = 1,
            .total_requests = 2,
            .total_responses = 3,
            .bytes_read = 4,
            .bytes_written = 5,
        },
        .errors = .{
            .accept = 0,
            .read = 0,
            .write = 0,
            .parse = 0,
            .protocol = 0,
            .pool_full = 0,
            .buffer_overflow = 0,
            .cache = 0,
            .timeout = 0,
        },
        .cache = .{
            .items = 0,
            .total_items = 0,
            .bytes = 0,
            .shards = 1,
        },
    };
    writer = out.writer(allocator);
    _ = try executeHttp(cache_instance, .{ .stats = {} }, null, false, writer, null, snapshot);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "200") != null);

    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeHttp(cache_instance, .{ .stats = {} }, null, false, writer, null, null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "500") != null);
}

test "http execution rejects lowmem writes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var controls = resource_controls.ResourceControls.init(null, false, false);
    controls.lowmem.store(true, .release);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    const writer = out.writer(allocator);
    _ = try executeHttp(
        cache_instance,
        .{ .set = .{ .key = "k", .value = "v", .xx = false } },
        &controls,
        false,
        writer,
        null,
        null,
    );
    try std.testing.expect(std.mem.indexOf(u8, out.items, "ERR out of memory") != null);
}

test "resp execution delete decr expire ttl branches" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    _ = try cache_mod.engine.store(cache_instance, "k", "v", .{});
    var writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .delete = .{ .key = "k" } }, null, writer, null, null);
    try std.testing.expectEqualStrings(":1\r\n", out.items);

    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .decr = .{ .key = "counter" } }, null, writer, null, null);
    try std.testing.expectEqualStrings(":-1\r\n", out.items);

    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeResp(
        cache_instance,
        .{ .expire = .{ .key = "missing", .ttl_ns = @as(i64, @intCast(5 * std.time.ns_per_s)) } },
        null,
        writer,
        null,
        null,
    );
    try std.testing.expectEqualStrings(":0\r\n", out.items);

    _ = try cache_mod.engine.store(cache_instance, "expire", "v", .{});
    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeResp(
        cache_instance,
        .{ .expire = .{ .key = "expire", .ttl_ns = @as(i64, @intCast(5 * std.time.ns_per_s)) } },
        null,
        writer,
        null,
        null,
    );
    try std.testing.expectEqualStrings(":1\r\n", out.items);

    _ = try cache_mod.engine.store(cache_instance, "ttl", "v", .{});
    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .ttl = .{ .key = "ttl" } }, null, writer, null, null);
    try std.testing.expectEqualStrings(":-1\r\n", out.items);

    const now_time = cache_mod.engine.now();
    _ = try cache_mod.engine.store(cache_instance, "expired", "v", .{ .expires = now_time - 1 });
    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .ttl = .{ .key = "expired" } }, null, writer, null, null);
    try std.testing.expectEqualStrings(":-2\r\n", out.items);

    _ = try cache_mod.engine.store(
        cache_instance,
        "live",
        "v",
        .{ .expires = now_time + @as(i64, @intCast(5 * std.time.ns_per_s)) },
    );
    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .ttl = .{ .key = "live" } }, null, writer, null, null);
    const ttl_out = out.items;
    try std.testing.expect(ttl_out.len >= 3);
    try std.testing.expect(ttl_out[0] == ':');
    try std.testing.expect(ttl_out[ttl_out.len - 2] == '\r' and ttl_out[ttl_out.len - 1] == '\n');
    const ttl_val = try std.fmt.parseInt(i64, ttl_out[1 .. ttl_out.len - 2], 10);
    try std.testing.expect(ttl_val >= 0);
}

test "resp execution info missing snapshot and lowmem incr" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    var writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .info = {} }, null, writer, null, null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "ERR internal error") != null);

    out.clearRetainingCapacity();
    var controls = resource_controls.ResourceControls.init(null, false, false);
    controls.lowmem.store(true, .release);
    writer = out.writer(allocator);
    const res = try executeResp(cache_instance, .{ .incr = .{ .key = "counter" } }, &controls, writer, null, null);
    try std.testing.expect(res.cache_error);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "ERR out of memory") != null);
}

test "resp execution incr updates existing value" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    _ = try cache_mod.engine.store(cache_instance, "counter", "10", .{});

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    var writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .incr = .{ .key = "counter" } }, null, writer, null, null);
    try std.testing.expectEqualStrings(":11\r\n", out.items);

    out.clearRetainingCapacity();
    writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .decr = .{ .key = "counter" } }, null, writer, null, null);
    try std.testing.expectEqualStrings(":10\r\n", out.items);

    const entry_handle = (try cache_mod.engine.load(cache_instance, "counter", .{})) orelse {
        try std.testing.expect(false);
        return;
    };
    defer entry_handle.release();
    try std.testing.expectEqualStrings("10", entry_handle.value());
}

test "resp execution info returns snapshot" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    const snapshot = stats.StatsSnapshot{
        .time_unix_ms = 1,
        .uptime_ms = 2,
        .server = .{
            .active_connections = 3,
            .total_connections = 4,
            .total_requests = 5,
            .total_responses = 6,
            .bytes_read = 7,
            .bytes_written = 8,
        },
        .errors = .{
            .accept = 0,
            .read = 0,
            .write = 0,
            .parse = 0,
            .protocol = 0,
            .pool_full = 0,
            .buffer_overflow = 0,
            .cache = 0,
            .timeout = 0,
        },
        .cache = .{
            .items = 1,
            .total_items = 2,
            .bytes = 3,
            .shards = 4,
        },
    };

    const writer = out.writer(allocator);
    _ = try executeResp(cache_instance, .{ .info = {} }, null, writer, null, snapshot);
    const data = out.items;
    try std.testing.expect(std.mem.indexOf(u8, data, "server.total_connections:4") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "cache.items:1") != null);
}

test "resp execution reports aof failures" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache_instance = try cache_mod.engine.init(.{ .allocator = allocator, .nshards = 4 });
    defer cache_mod.engine.deinit(cache_instance);

    var mgr = aof.Manager.init(allocator, cache_instance, .{
        .path = "dummy.aof",
        .enabled = true,
    });
    mgr.failed.store(true, .release);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    const writer = out.writer(allocator);
    const res = try executeResp(
        cache_instance,
        .{ .set = .{ .key = "k", .value = "v", .options = .{} } },
        null,
        writer,
        &mgr,
        null,
    );
    try std.testing.expect(res.cache_error);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "ERR persistence failed") != null);
}
