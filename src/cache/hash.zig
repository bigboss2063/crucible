const std = @import("std");

pub fn th64(data: []const u8, seed: u64) u64 {
    const r: u64 = 0x14020a57acced8b7;
    var h: u64 = seed;
    var i: usize = 0;

    while (i + 8 <= data.len) : (i += 8) {
        var x = std.mem.readInt(u64, data[i..][0..8], .little);
        x = x *% r;
        x = std.math.rotl(u64, x, 31);
        h = h *% r ^ x;
        h = std.math.rotl(u64, h, 31);
    }

    while (i < data.len) : (i += 1) {
        h = h *% r ^ @as(u64, data[i]);
    }

    h = h *% r +% @as(u64, data.len);
    h ^= h >> 31;
    h = h *% r;
    h ^= h >> 31;
    h = h *% r;
    h ^= h >> 31;
    h = h *% r;
    return h;
}

pub fn mix13(key: u64) u64 {
    var x = key;
    x ^= x >> 30;
    x = x *% 0xbf58476d1ce4e5b9;
    x ^= x >> 27;
    x = x *% 0x94d049bb133111eb;
    x ^= x >> 31;
    return x;
}

test "th64 golden vectors" {
    const Case = struct {
        data: []const u8,
        seed: u64,
        expect: u64,
    };

    const cases = [_]Case{
        .{ .data = "", .seed = 0, .expect = 0x0000000000000000 },
        .{ .data = "a", .seed = 0, .expect = 0xbc02fc57c97c3a15 },
        .{ .data = "hello", .seed = 1, .expect = 0xc36fd6f18d578b3d },
        .{ .data = "The quick brown fox", .seed = 12345, .expect = 0x83f420005430684e },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.expect, th64(case.data, case.seed));
    }
}

test "mix13 golden vectors" {
    const Case = struct {
        value: u64,
        expect: u64,
    };

    const cases = [_]Case{
        .{ .value = 0x0000000000000000, .expect = 0x0000000000000000 },
        .{ .value = 0x0000000000000001, .expect = 0x5692161d100b05e5 },
        .{ .value = 0xdeadbeefdeadbeef, .expect = 0x64c2df93e2e8338c },
        .{ .value = 0x0123456789abcdef, .expect = 0xb2c058e4ebb5112c },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.expect, mix13(case.value));
    }
}
