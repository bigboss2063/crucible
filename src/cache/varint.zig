const std = @import("std");

pub const max_len: usize = 10;

pub const ReadError = error{
    Incomplete,
    Overflow,
};

pub const ReadResult = struct {
    value: u64,
    len: usize,
};

pub fn encodedLenU64(value: u64) usize {
    var x = value;
    var n: usize = 1;
    while (x >= 128) : (n += 1) {
        x >>= 7;
    }
    return n;
}

pub fn writeU64(dest: []u8, value: u64) usize {
    const needed = encodedLenU64(value);
    std.debug.assert(dest.len >= needed);

    var x = value;
    var i: usize = 0;
    while (x >= 128) : (i += 1) {
        dest[i] = @as(u8, @truncate(x)) | 0x80;
        x >>= 7;
    }
    dest[i] = @as(u8, @truncate(x));
    return i + 1;
}

pub fn readU64(src: []const u8) ReadError!ReadResult {
    if (src.len == 0) return ReadError.Incomplete;
    if (src[0] < 128) {
        return .{ .value = src[0], .len = 1 };
    }

    var value: u64 = 0;
    var i: usize = 0;
    while (i < src.len and i < max_len) : (i += 1) {
        const b = src[i];
        const shift: u6 = @as(u6, @truncate(7 * i));
        value |= (@as(u64, b & 0x7f)) << shift;
        if (b < 128) {
            return .{ .value = value, .len = i + 1 };
        }
    }

    return if (i == max_len) ReadError.Overflow else ReadError.Incomplete;
}

pub fn encodedLenI64(value: i64) usize {
    return encodedLenU64(zigzagEncode(value));
}

pub fn writeI64(dest: []u8, value: i64) usize {
    return writeU64(dest, zigzagEncode(value));
}

pub fn readI64(src: []const u8) ReadError!struct { value: i64, len: usize } {
    const res = try readU64(src);
    var value = @as(i64, @intCast(res.value >> 1));
    if ((res.value & 1) == 1) {
        value = ~value;
    }
    return .{ .value = value, .len = res.len };
}

fn zigzagEncode(value: i64) u64 {
    var ux = @as(u64, @bitCast(value)) << 1;
    if (value < 0) {
        ux = ~ux;
    }
    return ux;
}

test "varint u64 golden vectors" {
    const Case = struct {
        value: u64,
        bytes: []const u8,
    };

    const cases = [_]Case{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = 1, .bytes = &.{0x01} },
        .{ .value = 127, .bytes = &.{0x7f} },
        .{ .value = 128, .bytes = &.{0x80, 0x01} },
        .{ .value = 300, .bytes = &.{0xac, 0x02} },
        .{ .value = 16384, .bytes = &.{0x80, 0x80, 0x01} },
        .{ .value = 0x1122334455667788, .bytes = &.{0x88, 0xef, 0x99, 0xab, 0xc5, 0xe8, 0x8c, 0x91, 0x11} },
        .{ .value = 0xffffffffffffffff, .bytes = &.{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01} },
    };

    for (cases) |case| {
        var buf: [max_len]u8 = undefined;
        const n = writeU64(&buf, case.value);
        try std.testing.expectEqual(case.bytes.len, n);
        try std.testing.expectEqualSlices(u8, case.bytes, buf[0..n]);

        const res = try readU64(buf[0..n]);
        try std.testing.expectEqual(case.value, res.value);
        try std.testing.expectEqual(n, res.len);
    }
}

test "varint i64 golden vectors" {
    const Case = struct {
        value: i64,
        bytes: []const u8,
    };

    const cases = [_]Case{
        .{ .value = 0, .bytes = &.{0x00} },
        .{ .value = 1, .bytes = &.{0x02} },
        .{ .value = -1, .bytes = &.{0x01} },
        .{ .value = -2, .bytes = &.{0x03} },
        .{ .value = 63, .bytes = &.{0x7e} },
        .{ .value = -64, .bytes = &.{0x7f} },
        .{ .value = 9223372036854775807, .bytes = &.{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01} },
        .{ .value = @as(i64, @bitCast(@as(u64, 0x8000000000000000))), .bytes = &.{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01} },
    };

    for (cases) |case| {
        var buf: [max_len]u8 = undefined;
        const n = writeI64(&buf, case.value);
        try std.testing.expectEqual(case.bytes.len, n);
        try std.testing.expectEqualSlices(u8, case.bytes, buf[0..n]);

        const res = try readI64(buf[0..n]);
        try std.testing.expectEqual(case.value, res.value);
        try std.testing.expectEqual(n, res.len);
    }
}
