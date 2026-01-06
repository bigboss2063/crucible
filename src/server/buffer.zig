const std = @import("std");

pub const RingBuffer = struct {
    buf: []u8,
    head: usize,
    tail: usize,
    len: usize,

    pub fn init(buf: []u8) RingBuffer {
        std.debug.assert(buf.len > 0);
        return .{
            .buf = buf,
            .head = 0,
            .tail = 0,
            .len = 0,
        };
    }

    pub fn availableSpace(self: *const RingBuffer) usize {
        return self.buf.len - self.len;
    }

    pub fn read(self: *const RingBuffer) []const u8 {
        if (self.len == 0) return self.buf[0..0];
        const end = if (self.tail > self.head and self.len < self.buf.len) self.tail else self.buf.len;
        return self.buf[self.head..end];
    }

    pub fn writeSlice(self: *RingBuffer) []u8 {
        if (self.len == self.buf.len) return self.buf[0..0];
        if (self.tail >= self.head and self.len < self.buf.len) {
            return self.buf[self.tail..self.buf.len];
        }
        return self.buf[self.tail..self.head];
    }

    pub fn commitWrite(self: *RingBuffer, n: usize) void {
        if (n == 0) return;
        const space = self.availableSpace();
        std.debug.assert(n <= space);
        self.tail = (self.tail + n) % self.buf.len;
        self.len += n;
    }

    pub fn write(self: *RingBuffer, data: []const u8) usize {
        if (data.len == 0) return 0;
        const space = self.availableSpace();
        if (space == 0) return 0;

        const to_write = @min(space, data.len);
        const first = @min(to_write, self.buf.len - self.tail);
        std.mem.copyForwards(u8, self.buf[self.tail .. self.tail + first], data[0..first]);

        const remaining = to_write - first;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.buf[0..remaining], data[first .. first + remaining]);
        }

        self.tail = (self.tail + to_write) % self.buf.len;
        self.len += to_write;
        return to_write;
    }

    pub fn consume(self: *RingBuffer, n: usize) void {
        if (self.len == 0 or n == 0) return;
        const take = @min(n, self.len);
        self.head = (self.head + take) % self.buf.len;
        self.len -= take;

        if (self.len == 0) {
            self.head = 0;
            self.tail = 0;
        }
    }

    pub fn clear(self: *RingBuffer) void {
        self.head = 0;
        self.tail = 0;
        self.len = 0;
    }

    pub fn linearize(self: *RingBuffer, scratch: []u8) void {
        if (self.len == 0) return;
        if (self.head < self.tail) return;
        if (self.head == self.tail and self.len < self.buf.len) return;
        if (self.head == 0) return;
        const first_len = self.buf.len - self.head;
        std.debug.assert(scratch.len >= first_len);
        std.mem.copyForwards(u8, scratch[0..first_len], self.buf[self.head .. self.head + first_len]);
        std.mem.copyBackwards(u8, self.buf[first_len .. first_len + self.tail], self.buf[0..self.tail]);
        std.mem.copyForwards(u8, self.buf[0..first_len], scratch[0..first_len]);
        self.head = 0;
        self.tail = if (self.len == self.buf.len) 0 else self.len;
    }
};

test "ring buffer basic write/read/consume" {
    var storage: [8]u8 = undefined;
    var rb = RingBuffer.init(&storage);

    try std.testing.expectEqual(@as(usize, 8), rb.availableSpace());
    const n1 = rb.write("abcd");
    try std.testing.expectEqual(@as(usize, 4), n1);
    try std.testing.expectEqualSlices(u8, "abcd", rb.read());

    rb.consume(2);
    try std.testing.expectEqualSlices(u8, "cd", rb.read());
    try std.testing.expectEqual(@as(usize, 6), rb.availableSpace());
}

test "ring buffer wrap around" {
    var storage: [8]u8 = undefined;
    var rb = RingBuffer.init(&storage);

    _ = rb.write("abcdef");
    rb.consume(4);
    _ = rb.write("wxyz");

    try std.testing.expectEqualSlices(u8, "efwx", rb.read());
    rb.consume(4);
    try std.testing.expectEqualSlices(u8, "yz", rb.read());
}

test "ring buffer partial write" {
    var storage: [4]u8 = undefined;
    var rb = RingBuffer.init(&storage);

    const n1 = rb.write("abc");
    try std.testing.expectEqual(@as(usize, 3), n1);
    const n2 = rb.write("def");
    try std.testing.expectEqual(@as(usize, 1), n2);
    try std.testing.expectEqualSlices(u8, "abcd", rb.read());

    rb.consume(4);
    try std.testing.expectEqual(@as(usize, 4), rb.availableSpace());
}

test "ring buffer write slice and commit" {
    var storage: [6]u8 = undefined;
    var rb = RingBuffer.init(&storage);

    var slice = rb.writeSlice();
    try std.testing.expectEqual(@as(usize, 6), slice.len);
    std.mem.copyForwards(u8, slice[0..3], "abc");
    rb.commitWrite(3);
    try std.testing.expectEqualSlices(u8, "abc", rb.read());

    rb.consume(2);
    slice = rb.writeSlice();
    std.mem.copyForwards(u8, slice[0..3], "def");
    rb.commitWrite(3);
    var scratch: [6]u8 = undefined;
    rb.linearize(&scratch);
    try std.testing.expectEqualSlices(u8, "cdef", rb.read());
}

test "ring buffer linearize full wrap" {
    var storage: [6]u8 = undefined;
    var rb = RingBuffer.init(&storage);

    _ = rb.write("abcdef");
    rb.consume(2);
    _ = rb.write("gh");

    var scratch: [6]u8 = undefined;
    rb.linearize(&scratch);
    try std.testing.expectEqualSlices(u8, "cdefgh", rb.read());
}
