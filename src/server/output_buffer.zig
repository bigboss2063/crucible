const std = @import("std");

pub const OutputLimit = struct {
    hard_bytes: usize = 0,
    soft_bytes: usize = 0,
    soft_seconds: u32 = 0,
};

pub const OutputError = error{OutOfMemory, OutputLimitExceeded, InvalidCapacity};

pub const default_inline_bytes: usize = 16 * 1024;
pub const default_chunk_bytes: usize = 16 * 1024;

const max_free_chunks: usize = 8;

pub const WriteSource = enum {
    inline_buf,
    chunk,
};

pub const WriteSlice = struct {
    source: WriteSource,
    slice: []const u8,
};

const ReplyChunk = struct {
    next: ?*ReplyChunk = null,
    data: []u8,
    len: usize = 0,
    sent: usize = 0,
};

pub const OutputBuffer = struct {
    allocator: std.mem.Allocator,
    inline_buf: []u8,
    inline_start: usize = 0,
    inline_len: usize = 0,
    head: ?*ReplyChunk = null,
    tail: ?*ReplyChunk = null,
    queued_bytes: usize = 0,
    soft_since: ?std.time.Instant = null,
    limits: OutputLimit,
    chunk_bytes: usize,
    free_head: ?*ReplyChunk = null,
    free_len: usize = 0,
    limit_exceeded: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        inline_bytes: usize,
        chunk_bytes: usize,
        limits: OutputLimit,
    ) OutputError!OutputBuffer {
        if (inline_bytes == 0 or chunk_bytes == 0) return error.InvalidCapacity;
        const inline_buf = try allocator.alloc(u8, inline_bytes);
        return .{
            .allocator = allocator,
            .inline_buf = inline_buf,
            .limits = limits,
            .chunk_bytes = chunk_bytes,
        };
    }

    pub fn deinit(self: *OutputBuffer) void {
        self.clearQueued(true);
        self.allocator.free(self.inline_buf);
        self.inline_buf = &.{};
    }

    pub fn reset(self: *OutputBuffer, limits: OutputLimit) void {
        self.clearQueued(false);
        self.limits = limits;
        self.limit_exceeded = false;
    }

    pub fn shrinkToInit(self: *OutputBuffer) void {
        self.clearQueued(true);
        self.limit_exceeded = false;
    }

    pub fn writer(self: *OutputBuffer) std.io.GenericWriter(*OutputBuffer, OutputError, write) {
        return .{ .context = self };
    }

    pub fn write(self: *OutputBuffer, data: []const u8) OutputError!usize {
        try self.append(data);
        return data.len;
    }

    pub fn writeAll(self: *OutputBuffer, data: []const u8) OutputError!void {
        if (data.len == 0) return;
        try self.append(data);
    }

    pub fn append(self: *OutputBuffer, data: []const u8) OutputError!void {
        if (data.len == 0) return;
        if (self.limit_exceeded) return error.OutputLimitExceeded;
        if (self.head == null and self.canAppendInline(data.len)) {
            self.appendInline(data);
        } else {
            try self.appendChunks(data);
        }
        self.queued_bytes += data.len;
        try self.checkLimits();
    }

    pub fn hasPending(self: *const OutputBuffer) bool {
        return self.inline_len != 0 or self.head != null;
    }

    pub fn nextWriteSlice(self: *const OutputBuffer) ?WriteSlice {
        if (self.inline_len != 0) {
            const slice = self.inline_buf[self.inline_start .. self.inline_start + self.inline_len];
            return .{ .source = .inline_buf, .slice = slice };
        }
        if (self.head) |chunk| {
            const slice = chunk.data[chunk.sent..chunk.len];
            return .{ .source = .chunk, .slice = slice };
        }
        return null;
    }

    pub fn consumeWrite(self: *OutputBuffer, source: WriteSource, written: usize) void {
        if (written == 0) return;
        switch (source) {
            .inline_buf => self.consumeInline(written),
            .chunk => self.consumeChunk(written),
        }
        self.updateSoftState();
    }

    pub fn dropQueued(self: *OutputBuffer) void {
        self.clearQueued(false);
    }

    fn clearQueued(self: *OutputBuffer, release_free: bool) void {
        self.inline_start = 0;
        self.inline_len = 0;
        self.queued_bytes = 0;
        self.soft_since = null;
        var node = self.head;
        self.head = null;
        self.tail = null;
        while (node) |chunk| {
            const next = chunk.next;
            if (release_free) {
                self.freeChunk(chunk);
            } else {
                self.recycleChunk(chunk);
            }
            node = next;
        }
        if (release_free) {
            var free_node = self.free_head;
            self.free_head = null;
            self.free_len = 0;
            while (free_node) |chunk| {
                const next = chunk.next;
                self.freeChunk(chunk);
                free_node = next;
            }
        }
    }

    fn canAppendInline(self: *const OutputBuffer, len: usize) bool {
        if (len > self.inline_buf.len) return false;
        const end = self.inline_start + self.inline_len;
        return end + len <= self.inline_buf.len;
    }

    fn appendInline(self: *OutputBuffer, data: []const u8) void {
        const start = self.inline_start + self.inline_len;
        std.debug.assert(start + data.len <= self.inline_buf.len);
        std.mem.copyForwards(u8, self.inline_buf[start .. start + data.len], data);
        self.inline_len += data.len;
    }

    fn appendChunks(self: *OutputBuffer, data: []const u8) OutputError!void {
        var remaining = data;
        if (self.tail) |tail| {
            const avail = tail.data.len - tail.len;
            if (avail != 0) {
                const take = @min(avail, remaining.len);
                std.mem.copyForwards(u8, tail.data[tail.len .. tail.len + take], remaining[0..take]);
                tail.len += take;
                remaining = remaining[take..];
            }
        }
        while (remaining.len != 0) {
            const cap = if (remaining.len > self.chunk_bytes) remaining.len else self.chunk_bytes;
            const chunk = try self.allocChunk(cap);
            const take = @min(remaining.len, chunk.data.len);
            std.mem.copyForwards(u8, chunk.data[0..take], remaining[0..take]);
            chunk.len = take;
            chunk.sent = 0;
            chunk.next = null;
            if (self.tail) |tail| {
                tail.next = chunk;
            } else {
                self.head = chunk;
            }
            self.tail = chunk;
            remaining = remaining[take..];
        }
    }

    fn consumeInline(self: *OutputBuffer, written: usize) void {
        std.debug.assert(self.inline_len >= written);
        self.inline_start += written;
        self.inline_len -= written;
        if (self.queued_bytes >= written) {
            self.queued_bytes -= written;
        } else {
            self.queued_bytes = 0;
        }
        if (self.inline_len == 0) {
            self.inline_start = 0;
        }
    }

    fn consumeChunk(self: *OutputBuffer, written: usize) void {
        const chunk = self.head orelse return;
        std.debug.assert(chunk.len - chunk.sent >= written);
        chunk.sent += written;
        if (self.queued_bytes >= written) {
            self.queued_bytes -= written;
        } else {
            self.queued_bytes = 0;
        }
        if (chunk.sent == chunk.len) {
            self.head = chunk.next;
            if (self.head == null) {
                self.tail = null;
            }
            self.recycleChunk(chunk);
        }
    }

    fn allocChunk(self: *OutputBuffer, capacity: usize) OutputError!*ReplyChunk {
        var prev: ?*ReplyChunk = null;
        var node = self.free_head;
        while (node) |chunk| {
            if (chunk.data.len >= capacity) {
                if (prev) |p| {
                    p.next = chunk.next;
                } else {
                    self.free_head = chunk.next;
                }
                self.free_len -= 1;
                chunk.next = null;
                chunk.len = 0;
                chunk.sent = 0;
                return chunk;
            }
            prev = node;
            node = chunk.next;
        }

        const chunk = try self.allocator.create(ReplyChunk);
        errdefer self.allocator.destroy(chunk);
        const data = try self.allocator.alloc(u8, capacity);
        chunk.* = .{ .data = data };
        return chunk;
    }

    fn recycleChunk(self: *OutputBuffer, chunk: *ReplyChunk) void {
        if (chunk.data.len <= self.chunk_bytes and self.free_len < max_free_chunks) {
            chunk.len = 0;
            chunk.sent = 0;
            chunk.next = self.free_head;
            self.free_head = chunk;
            self.free_len += 1;
            return;
        }
        self.freeChunk(chunk);
    }

    fn freeChunk(self: *OutputBuffer, chunk: *ReplyChunk) void {
        self.allocator.free(chunk.data);
        self.allocator.destroy(chunk);
    }

    fn checkLimits(self: *OutputBuffer) OutputError!void {
        if (self.limits.hard_bytes != 0 and self.queued_bytes > self.limits.hard_bytes) {
            self.limit_exceeded = true;
            return error.OutputLimitExceeded;
        }

        if (self.limits.soft_bytes == 0 or self.limits.soft_seconds == 0) {
            self.soft_since = null;
            return;
        }

        if (self.queued_bytes <= self.limits.soft_bytes) {
            self.soft_since = null;
            return;
        }

        if (self.soft_since == null) {
            const now = std.time.Instant.now() catch return;
            self.soft_since = now;
            return;
        }

        const now = std.time.Instant.now() catch return;
        const elapsed_ns = now.since(self.soft_since.?);
        const threshold = @as(u64, self.limits.soft_seconds) * std.time.ns_per_s;
        if (elapsed_ns >= threshold) {
            self.limit_exceeded = true;
            return error.OutputLimitExceeded;
        }
    }

    fn updateSoftState(self: *OutputBuffer) void {
        if (self.limits.soft_bytes == 0 or self.limits.soft_seconds == 0) {
            self.soft_since = null;
            return;
        }
        if (self.queued_bytes <= self.limits.soft_bytes) {
            self.soft_since = null;
        }
    }
};

test "output buffer inline and chunk ordering" {
    var buf = try OutputBuffer.init(std.testing.allocator, 8, 8, .{});
    defer buf.deinit();

    try buf.append("abc");
    try buf.append("defghijkl");

    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);

    while (buf.nextWriteSlice()) |slice| {
        try out.appendSlice(std.testing.allocator, slice.slice);
        buf.consumeWrite(slice.source, slice.slice.len);
    }

    try std.testing.expectEqualSlices(u8, "abcdefghijkl", out.items);
}

test "output buffer partial inline write advances" {
    var buf = try OutputBuffer.init(std.testing.allocator, 8, 8, .{});
    defer buf.deinit();

    try buf.append("hello");
    const first = buf.nextWriteSlice().?;
    try std.testing.expectEqualSlices(u8, "hello", first.slice);
    buf.consumeWrite(first.source, 2);

    const second = buf.nextWriteSlice().?;
    try std.testing.expectEqualSlices(u8, "llo", second.slice);
    buf.consumeWrite(second.source, second.slice.len);
    try std.testing.expect(!buf.hasPending());
}

test "output buffer hard limit closes" {
    var buf = try OutputBuffer.init(std.testing.allocator, 8, 8, .{ .hard_bytes = 4 });
    defer buf.deinit();

    try buf.append("abcd");
    try std.testing.expect(buf.queued_bytes == 4);
    try std.testing.expectError(error.OutputLimitExceeded, buf.append("e"));
    try std.testing.expect(buf.limit_exceeded);
}

test "output buffer soft limit clears on drain" {
    var buf = try OutputBuffer.init(std.testing.allocator, 8, 8, .{ .soft_bytes = 4, .soft_seconds = 1 });
    defer buf.deinit();

    try buf.append("hello");
    try std.testing.expect(buf.queued_bytes == 5);
    const slice = buf.nextWriteSlice().?;
    buf.consumeWrite(slice.source, slice.slice.len);
    try std.testing.expect(buf.queued_bytes == 0);
    try std.testing.expect(buf.soft_since == null);
}
