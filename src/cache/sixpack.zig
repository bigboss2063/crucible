const std = @import("std");

pub const from_six: [64]u8 = .{
    0, '-', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', '_', 'a', 'b', 'c',
    'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
    'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
};

pub const to_six: [256]u8 = blk: {
    var table = std.mem.zeroes([256]u8);
    for (from_six, 0..) |ch, idx| {
        if (ch != 0) {
            table[ch] = @as(u8, @intCast(idx));
        }
    }
    break :blk table;
};

pub fn packedLen(src_len: usize) usize {
    return (src_len * 6 + 7) / 8;
}

pub fn pack(dst: []u8, src: []const u8) usize {
    if (src.len == 0) return 0;
    std.debug.assert(dst.len >= packedLen(src.len));

    var j: usize = 0;
    for (src, 0..) |byte, i| {
        const k6v = to_six[byte];
        if (k6v == 0) {
            return 0;
        }
        switch (i & 3) {
            0 => {
                dst[j] = k6v << 2;
                j += 1;
            },
            1 => {
                dst[j - 1] |= k6v >> 4;
                dst[j] = k6v << 4;
                j += 1;
            },
            2 => {
                dst[j - 1] |= k6v >> 2;
                dst[j] = k6v << 6;
                j += 1;
            },
            else => {
                dst[j - 1] |= k6v;
            },
        }
    }

    return j;
}

pub fn unpack(dst: []u8, src: []const u8) usize {
    if (src.len == 0) return 0;

    const max_out = (src.len / 3) * 4 + (src.len % 3);
    std.debug.assert(dst.len >= max_out);

    var j: usize = 0;
    var k: u8 = 0;
    for (src, 0..) |byte, i| {
        if (k == 0) {
            dst[j] = from_six[byte >> 2];
            j += 1;
            k = 1;
        } else if (k == 1) {
            const prev = src[i - 1];
            const idx = ((@as(u16, prev) << 4) | (@as(u16, byte) >> 4)) & 0x3f;
            dst[j] = from_six[@as(usize, idx)];
            j += 1;
            k = 2;
        } else {
            const prev = src[i - 1];
            const idx0 = ((@as(u16, prev) << 2) | (@as(u16, byte) >> 6)) & 0x3f;
            dst[j] = from_six[@as(usize, idx0)];
            dst[j + 1] = from_six[byte & 0x3f];
            j += 2;
            k = 0;
        }
    }

    if (j > 0 and dst[j - 1] == 0) {
        j -= 1;
    }

    return j;
}

test "sixpack golden vectors" {
    const Case = struct {
        input: []const u8,
        encoded: []const u8,
    };

    const cases = [_]Case{
        .{ .input = "hello", .encoded = &.{0xba, 0xbc, 0xb2, 0xd4} },
        .{ .input = "user:42", .encoded = &.{0xef, 0x9a, 0xf8, 0x34, 0x71, 0x40} },
        .{ .input = "abcd", .encoded = &.{0x9e, 0x8a, 0x6a} },
        .{ .input = "abc", .encoded = &.{0x9e, 0x8a, 0x40} },
        .{ .input = "A-._", .encoded = &.{0x38, 0x10, 0xa6} },
    };

    for (cases) |case| {
        var buf: [32]u8 = undefined;
        const n = pack(&buf, case.input);
        try std.testing.expectEqual(case.encoded.len, n);
        try std.testing.expectEqualSlices(u8, case.encoded, buf[0..n]);

        var out: [64]u8 = undefined;
        const m = unpack(&out, buf[0..n]);
        try std.testing.expectEqual(case.input.len, m);
        try std.testing.expectEqualSlices(u8, case.input, out[0..m]);
    }
}

test "sixpack rejects invalid characters" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), pack(&buf, "z"));
    try std.testing.expectEqual(@as(usize, 0), pack(&buf, "Q"));
    try std.testing.expectEqual(@as(usize, 0), pack(&buf, "!"));
}
