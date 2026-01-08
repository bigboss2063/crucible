const std = @import("std");

pub const LinearBuffer = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    start: usize,
    len: usize,
    init_cap: usize,

    fn assertInvariants(self: *const LinearBuffer) void {
        std.debug.assert(self.start + self.len <= self.storage.len);
        std.debug.assert(self.storage.len >= self.init_cap);
    }

    pub fn init(allocator: std.mem.Allocator, init_cap: usize) !LinearBuffer {
        if (init_cap == 0) return error.InvalidCapacity;
        const storage = try allocator.alloc(u8, init_cap);
        return .{
            .allocator = allocator,
            .storage = storage,
            .start = 0,
            .len = 0,
            .init_cap = init_cap,
        };
    }

    pub fn deinit(self: *LinearBuffer) void {
        self.assertInvariants();
        self.allocator.free(self.storage);
        self.storage = &.{};
        self.start = 0;
        self.len = 0;
    }

    pub fn clear(self: *LinearBuffer) void {
        self.assertInvariants();
        self.start = 0;
        self.len = 0;
    }

    pub fn readable(self: *const LinearBuffer) []const u8 {
        self.assertInvariants();
        return self.storage[self.start .. self.start + self.len];
    }

    pub fn availableTail(self: *const LinearBuffer) usize {
        self.assertInvariants();
        return self.storage.len - (self.start + self.len);
    }

    pub fn tailSlice(self: *LinearBuffer) []u8 {
        self.assertInvariants();
        return self.storage[self.start + self.len .. self.storage.len];
    }

    pub fn reserve(self: *LinearBuffer, min_free: usize) bool {
        self.assertInvariants();
        if (min_free == 0) return true;
        const needed = std.math.add(usize, self.len, min_free) catch return false;
        self.compactIfNeeded(min_free);
        if (self.availableTail() >= min_free) return true;
        if (!self.grow(needed)) return false;
        return self.availableTail() >= min_free;
    }

    pub fn commitWrite(self: *LinearBuffer, n: usize) void {
        self.assertInvariants();
        if (n == 0) return;
        std.debug.assert(n <= self.availableTail());
        self.len += n;
    }

    pub fn write(self: *LinearBuffer, data: []const u8) bool {
        self.assertInvariants();
        if (data.len == 0) return true;
        if (!self.reserve(data.len)) return false;
        std.mem.copyForwards(u8, self.tailSlice()[0..data.len], data);
        self.commitWrite(data.len);
        return true;
    }

    pub fn consume(self: *LinearBuffer, n: usize) void {
        self.assertInvariants();
        if (self.len == 0 or n == 0) return;
        const take = @min(n, self.len);
        self.start += take;
        self.len -= take;
        if (self.len == 0) {
            self.start = 0;
        }
    }

    pub fn shrinkToInit(self: *LinearBuffer) void {
        self.assertInvariants();
        if (self.storage.len <= self.init_cap) return;
        if (self.len != 0) return;
        const resized = self.allocator.realloc(self.storage, self.init_cap) catch return;
        self.storage = resized;
        self.start = 0;
    }

    fn compactIfNeeded(self: *LinearBuffer, min_free: usize) void {
        self.assertInvariants();
        if (self.start == 0) return;
        const cap = self.storage.len;
        const available = cap - (self.start + self.len);
        const threshold = cap / 2;
        if (available >= min_free and self.start < threshold) return;
        if (self.len > 0) {
            std.mem.copyForwards(u8, self.storage[0..self.len], self.storage[self.start .. self.start + self.len]);
        }
        self.start = 0;
    }

    fn grow(self: *LinearBuffer, needed: usize) bool {
        self.assertInvariants();
        var new_cap = self.storage.len;
        while (new_cap < needed) {
            const next = std.math.mul(usize, new_cap, 2) catch return false;
            if (next <= new_cap) return false;
            new_cap = next;
        }
        if (new_cap == self.storage.len) return true;
        const resized = self.allocator.realloc(self.storage, new_cap) catch return false;
        self.storage = resized;
        return true;
    }
};

test "linear buffer basic write/read/consume" {
    var storage = try LinearBuffer.init(std.testing.allocator, 8);
    defer storage.deinit();

    try std.testing.expect(storage.write("abcd"));
    try std.testing.expectEqualSlices(u8, "abcd", storage.readable());

    storage.consume(2);
    try std.testing.expectEqualSlices(u8, "cd", storage.readable());
}

test "linear buffer compacts on demand" {
    var buf = try LinearBuffer.init(std.testing.allocator, 8);
    defer buf.deinit();

    try std.testing.expect(buf.write("abcdef"));
    buf.consume(4);
    try std.testing.expectEqualSlices(u8, "ef", buf.readable());

    try std.testing.expect(buf.reserve(6));
    try std.testing.expectEqual(@as(usize, 0), buf.start);
    try std.testing.expectEqualSlices(u8, "ef", buf.readable());
    try std.testing.expect(buf.write("ghij"));
    try std.testing.expectEqualSlices(u8, "efghij", buf.readable());
}

test "linear buffer grows on demand" {
    var buf = try LinearBuffer.init(std.testing.allocator, 4);
    defer buf.deinit();

    try std.testing.expect(buf.write("abcd"));
    try std.testing.expect(buf.reserve(6));
    try std.testing.expect(buf.storage.len >= 10);
    try std.testing.expect(buf.write("efghij"));
    try std.testing.expectEqualSlices(u8, "abcdefghij", buf.readable());
}
