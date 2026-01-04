const std = @import("std");

pub const ptr_bytes: usize = 6;
pub const hash_bytes: usize = 3;

pub const Bucket = extern struct {
    entry: [ptr_bytes]u8,
    hash: [hash_bytes]u8,
    dib: u8,
};

comptime {
    if (@sizeOf(usize) != 8) {
        @compileError("Bucket pointer packing requires 64-bit targets");
    }
    if (@sizeOf(Bucket) != ptr_bytes + hash_bytes + 1) {
        @compileError("Bucket size must be 10 bytes");
    }
}

pub fn init() Bucket {
    return .{
        .entry = .{0} ** ptr_bytes,
        .hash = .{0} ** hash_bytes,
        .dib = 0,
    };
}

pub fn setPtr(comptime T: type, bucket: *Bucket, ptr: ?*T) void {
    const raw: usize = if (ptr) |p| @intFromPtr(p) else 0;
    writePtr(&bucket.entry, raw);
}

pub fn getPtr(comptime T: type, bucket: *const Bucket) ?*T {
    const raw = readPtr(&bucket.entry);
    if (raw == 0) return null;
    return @ptrFromInt(raw);
}

pub fn writeHash(bucket: *Bucket, hash: u32) void {
    const clipped = clipHash(hash);
    bucket.hash[0] = @as(u8, @truncate(clipped));
    bucket.hash[1] = @as(u8, @truncate(clipped >> 8));
    bucket.hash[2] = @as(u8, @truncate(clipped >> 16));
}

pub fn readHash(bucket: *const Bucket) u32 {
    return @as(u32, bucket.hash[0]) |
        (@as(u32, bucket.hash[1]) << 8) |
        (@as(u32, bucket.hash[2]) << 16);
}

pub fn clipHash(hash: u32) u32 {
    return hash & 0x00ff_ffff;
}

fn writePtr(buf: *[ptr_bytes]u8, value: usize) void {
    if (value == 0) {
        buf.* = .{0} ** ptr_bytes;
        return;
    }
    std.debug.assert((value >> 48) == 0);
    var i: usize = 0;
    while (i < ptr_bytes) : (i += 1) {
        buf[i] = @as(u8, @truncate(value >> @intCast(8 * i)));
    }
}

fn readPtr(buf: *const [ptr_bytes]u8) usize {
    var value: usize = 0;
    var i: usize = 0;
    while (i < ptr_bytes) : (i += 1) {
        value |= @as(usize, buf[i]) << @intCast(8 * i);
    }
    return value;
}

test "bucket layout size" {
    try std.testing.expectEqual(@as(usize, 10), @sizeOf(Bucket));
}

test "bucket pointer packing" {
    var bucket = init();
    var value: u32 = 7;
    setPtr(u32, &bucket, &value);
    const out = getPtr(u32, &bucket).?;
    try std.testing.expectEqual(@intFromPtr(&value), @intFromPtr(out));

    setPtr(u32, &bucket, null);
    try std.testing.expect(getPtr(u32, &bucket) == null);
}

test "bucket hash packing" {
    var bucket = init();
    writeHash(&bucket, 0x11223344);
    try std.testing.expectEqual(@as(u32, 0x223344), readHash(&bucket));
}
