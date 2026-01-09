const std = @import("std");
const sixpack = @import("sixpack.zig");
const varint = @import("varint.zig");

pub const Entry = extern struct {
    time: i64,
    rc: i32,
    meta: u8,
    _pad: [3]u8,
};

pub const EntryOptions = struct {
    expires: i64 = 0,
    flags: u32 = 0,
    cas: u64 = 0,
    usecas: bool = false,
    nosixpack: bool = false,
};

const meta_memsz_mask: u8 = 0b0000_0011;
const meta_has_expires: u8 = 0b0000_0100;
const meta_has_flags: u8 = 0b0000_1000;
const meta_has_sixpack: u8 = 0b0001_0000;

comptime {
    if (@sizeOf(Entry) != 16) {
        @compileError("Entry header must be 16 bytes");
    }
    if (@alignOf(Entry) != 8) {
        @compileError("Entry alignment must be 8 bytes");
    }
}

pub fn create(allocator: std.mem.Allocator, key_input: []const u8, value_input: []const u8, opts: EntryOptions) !*Entry {
    var key_bytes = key_input;
    var has_sixpack = false;
    var packed_buf: [128]u8 = undefined;
    if (!opts.nosixpack and key_input.len <= 128) {
        const needed = sixpack.packedLen(key_input.len);
        const packed_len = sixpack.pack(packed_buf[0..needed], key_input);
        if (packed_len > 0) {
            key_bytes = packed_buf[0..packed_len];
            has_sixpack = true;
        }
    }

    var keylen_buf: [varint.max_len]u8 = undefined;
    const keylen_len = varint.writeU64(&keylen_buf, key_bytes.len);

    var prefix_len: usize = 0;
    if (opts.expires > 0) prefix_len += 8;
    if (opts.flags > 0) prefix_len += 4;
    if (opts.usecas) prefix_len += 8;

    var size: usize = @sizeOf(Entry) + prefix_len + keylen_len + key_bytes.len + value_input.len;
    var memszsz: u8 = 0;
    if (size <= 0xFF - 1) {
        memszsz = 0;
        size += 1;
    } else if (size <= 0xFFFF - 2) {
        memszsz = 1;
        size += 2;
    } else if (size <= 0xFFFFFFFF - 4) {
        memszsz = 2;
        size += 4;
    } else {
        memszsz = 3;
        size += 8;
    }

    const mem = try allocator.alignedAlloc(u8, std.mem.Alignment.of(Entry), size);
    const entry: *Entry = @ptrCast(mem.ptr);
    entry.time = 0;
    entry.rc = 1;
    entry.meta = memszsz;
    if (opts.expires > 0) entry.meta |= meta_has_expires;
    if (opts.flags > 0) entry.meta |= meta_has_flags;
    if (has_sixpack) entry.meta |= meta_has_sixpack;
    entry._pad = .{ 0, 0, 0 };

    var p = dataPtrMut(entry);
    switch (memszsz) {
        0 => {
            p[0] = @as(u8, @intCast(size));
            p += 1;
        },
        1 => {
            std.mem.writeInt(u16, p[0..2], @as(u16, @intCast(size)), .little);
            p += 2;
        },
        2 => {
            std.mem.writeInt(u32, p[0..4], @as(u32, @intCast(size)), .little);
            p += 4;
        },
        else => {
            std.mem.writeInt(u64, p[0..8], @as(u64, @intCast(size)), .little);
            p += 8;
        },
    }

    if (opts.expires > 0) {
        std.mem.writeInt(i64, p[0..8], opts.expires, .little);
        p += 8;
    }
    if (opts.flags > 0) {
        std.mem.writeInt(u32, p[0..4], opts.flags, .little);
        p += 4;
    }
    if (opts.usecas) {
        std.mem.writeInt(u64, p[0..8], opts.cas, .little);
        p += 8;
    }
    std.mem.copyForwards(u8, p[0..keylen_len], keylen_buf[0..keylen_len]);
    p += keylen_len;
    std.mem.copyForwards(u8, p[0..key_bytes.len], key_bytes);
    p += key_bytes.len;
    std.mem.copyForwards(u8, p[0..value_input.len], value_input);

    return entry;
}

pub fn retain(entry: *Entry) void {
    _ = @atomicRmw(i32, &entry.rc, .Add, 1, .monotonic);
}

pub fn release(entry: *Entry, allocator: std.mem.Allocator) void {
    const prev = @atomicRmw(i32, &entry.rc, .Sub, 1, .acq_rel);
    if (prev == 1) {
        const size = memSize(entry);
        const bytes = @as([*]align(@alignOf(Entry)) u8, @ptrCast(entry))[0..size];
        allocator.free(bytes);
    }
}

pub fn setTime(entry: *Entry, timestamp: i64) void {
    entry.time = timestamp;
}

pub fn time(entry: *const Entry) i64 {
    return entry.time;
}

pub fn isAlive(entry: *const Entry, now: i64) bool {
    return isAliveExpires(expires(entry), now);
}

pub fn isAliveExpires(expires_value: i64, now: i64) bool {
    return expires_value == 0 or expires_value > now;
}

pub fn memSize(entry: *const Entry) usize {
    const len = memSizeFieldLen(entry);
    const bytes = dataPtr(entry)[0..len];
    return switch (len) {
        1 => bytes[0],
        2 => std.mem.readInt(u16, @as(*const [2]u8, @ptrCast(bytes.ptr)), .little),
        4 => std.mem.readInt(u32, @as(*const [4]u8, @ptrCast(bytes.ptr)), .little),
        8 => @as(usize, @intCast(std.mem.readInt(u64, @as(*const [8]u8, @ptrCast(bytes.ptr)), .little))),
        else => unreachable,
    };
}

pub fn memSizeFieldLen(entry: *const Entry) usize {
    const memsz = entry.meta & meta_memsz_mask;
    const shift: u6 = @intCast(memsz);
    return @as(usize, 1) << shift;
}

pub fn hasSixpack(entry: *const Entry) bool {
    return (entry.meta & meta_has_sixpack) != 0;
}

pub fn expires(entry: *const Entry) i64 {
    if ((entry.meta & meta_has_expires) == 0) return 0;
    const offset = memSizeFieldLen(entry);
    const bytes = dataPtr(entry)[offset .. offset + 8];
    return std.mem.readInt(i64, @as(*const [8]u8, @ptrCast(bytes.ptr)), .little);
}

pub fn flags(entry: *const Entry) u32 {
    if ((entry.meta & meta_has_flags) == 0) return 0;
    var offset = memSizeFieldLen(entry);
    if ((entry.meta & meta_has_expires) != 0) {
        offset += 8;
    }
    const bytes = dataPtr(entry)[offset .. offset + 4];
    return std.mem.readInt(u32, @as(*const [4]u8, @ptrCast(bytes.ptr)), .little);
}

pub fn cas(entry: *const Entry, usecas: bool) u64 {
    if (!usecas) return 0;
    var offset = memSizeFieldLen(entry);
    if ((entry.meta & meta_has_expires) != 0) offset += 8;
    if ((entry.meta & meta_has_flags) != 0) offset += 4;
    const bytes = dataPtr(entry)[offset .. offset + 8];
    return std.mem.readInt(u64, @as(*const [8]u8, @ptrCast(bytes.ptr)), .little);
}

pub fn rawKey(entry: *const Entry, usecas: bool) []const u8 {
    const payload = payloadSlice(entry);
    const offset = prefixOffset(entry, usecas);
    const res = varint.readU64(payload[offset..]) catch unreachable;
    const key_len = @as(usize, @intCast(res.value));
    const start = offset + res.len;
    return payload[start .. start + key_len];
}

pub fn key(entry: *const Entry, usecas: bool, buf: *[128]u8) []const u8 {
    const raw = rawKey(entry, usecas);
    if (!hasSixpack(entry)) return raw;
    const len = sixpack.unpack(buf, raw);
    return buf[0..len];
}

pub fn value(entry: *const Entry, usecas: bool) []const u8 {
    const payload = payloadSlice(entry);
    var offset = prefixOffset(entry, usecas);
    const res = varint.readU64(payload[offset..]) catch unreachable;
    const key_len = @as(usize, @intCast(res.value));
    offset += res.len + key_len;
    return payload[offset..payload.len];
}

fn prefixOffset(entry: *const Entry, usecas: bool) usize {
    var offset = memSizeFieldLen(entry);
    if ((entry.meta & meta_has_expires) != 0) offset += 8;
    if ((entry.meta & meta_has_flags) != 0) offset += 4;
    if (usecas) offset += 8;
    return offset;
}

fn payloadSlice(entry: *const Entry) []const u8 {
    const total = memSize(entry);
    const payload_len = total - @sizeOf(Entry);
    return dataPtr(entry)[0..payload_len];
}

fn dataPtr(entry: *const Entry) [*]const u8 {
    return @as([*]const u8, @ptrCast(entry)) + @sizeOf(Entry);
}

fn dataPtrMut(entry: *Entry) [*]u8 {
    return @as([*]u8, @ptrCast(entry)) + @sizeOf(Entry);
}

test "entry create and decode" {
    const allocator = std.testing.allocator;
    const opts = EntryOptions{
        .expires = 1234,
        .flags = 0xdeadbeef,
        .cas = 42,
        .usecas = true,
    };

    const entry = try create(allocator, "user:42", "value", opts);
    defer release(entry, allocator);

    try std.testing.expectEqual(@as(i64, 1234), expires(entry));
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), flags(entry));
    try std.testing.expectEqual(@as(u64, 42), cas(entry, true));
    try std.testing.expectEqual(@as(usize, 1), memSizeFieldLen(entry));
    try std.testing.expect(hasSixpack(entry));

    var buf: [128]u8 = undefined;
    const decoded_key = key(entry, true, &buf);
    try std.testing.expectEqualStrings("user:42", decoded_key);
    try std.testing.expectEqualStrings("value", value(entry, true));
}

test "entry raw key without sixpack" {
    const allocator = std.testing.allocator;
    const entry = try create(allocator, "hello!", "ok", .{ .usecas = false });
    defer release(entry, allocator);

    try std.testing.expect(!hasSixpack(entry));
    const raw = rawKey(entry, false);
    try std.testing.expectEqualStrings("hello!", raw);
    try std.testing.expectEqualStrings("ok", value(entry, false));
}

test "entry large payload uses u32 size field" {
    const allocator = std.testing.allocator;
    const value_len: usize = 70_000;
    const value_buf = try allocator.alloc(u8, value_len);
    defer allocator.free(value_buf);
    @memset(value_buf, 'a');

    const entry_ptr = try create(allocator, "bigkey", value_buf, .{});
    defer release(entry_ptr, allocator);

    try std.testing.expectEqual(@as(usize, 4), memSizeFieldLen(entry_ptr));
    try std.testing.expect(memSize(entry_ptr) >= @sizeOf(Entry));
}
