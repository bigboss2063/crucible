const std = @import("std");
const builtin = @import("builtin");
const cache_mod = @import("../cache/mod.zig");

pub const ResourceControls = struct {
    maxmemory_bytes: ?u64,
    evict: bool,
    autosweep: bool,
    lowmem: std.atomic.Value(bool) = .init(false),
    stop_flag: std.atomic.Value(bool) = .init(false),
    mem_thread: ?std.Thread = null,
    sweep_thread: ?std.Thread = null,
    mem_ctx: ?MemContext = null,
    sweep_ctx: ?SweepContext = null,

    pub fn init(maxmemory_bytes: ?u64, evict: bool, autosweep: bool) ResourceControls {
        return .{
            .maxmemory_bytes = maxmemory_bytes,
            .evict = evict,
            .autosweep = autosweep,
        };
    }

    pub fn start(self: *ResourceControls, cache: *cache_mod.api.Cache) !void {
        if (self.mem_thread != null or self.sweep_thread != null) return;
        self.stop_flag.store(false, .release);
        self.lowmem.store(false, .release);

        if (self.maxmemory_bytes) |limit| {
            self.mem_ctx = MemContext{
                .controls = self,
                .limit_bytes = limit,
                .page_size = std.heap.pageSize(),
            };
            const ctx_ptr = &self.mem_ctx.?;
            self.mem_thread = try std.Thread.spawn(.{}, memMonitorMain, .{ctx_ptr});
        }

        if (self.autosweep) {
            self.sweep_ctx = SweepContext{
                .controls = self,
                .cache = cache,
            };
            const ctx_ptr = &self.sweep_ctx.?;
            self.sweep_thread = std.Thread.spawn(.{}, autosweepMain, .{ctx_ptr}) catch |err| {
                self.stop();
                return err;
            };
        }
    }

    pub fn stop(self: *ResourceControls) void {
        self.stop_flag.store(true, .release);
        if (self.mem_thread) |thread| {
            thread.join();
            self.mem_thread = null;
        }
        if (self.sweep_thread) |thread| {
            thread.join();
            self.sweep_thread = null;
        }
        self.mem_ctx = null;
        self.sweep_ctx = null;
    }
};

const MemContext = struct {
    controls: *ResourceControls,
    limit_bytes: u64,
    page_size: usize,
};

const SweepContext = struct {
    controls: *ResourceControls,
    cache: *cache_mod.api.Cache,
};

fn memMonitorMain(ctx: *MemContext) void {
    while (!ctx.controls.stop_flag.load(.acquire)) {
        const rss = processRssBytes(ctx.page_size) catch {
            std.Thread.sleep(std.time.ns_per_s);
            continue;
        };
        ctx.controls.lowmem.store(rss >= ctx.limit_bytes, .release);
        std.Thread.sleep(std.time.ns_per_s);
    }
}

fn autosweepMain(ctx: *SweepContext) void {
    while (!ctx.controls.stop_flag.load(.acquire)) {
        autosweepTick(ctx.cache);
        std.Thread.sleep(std.time.ns_per_s);
    }
}

fn autosweepTick(cache: *cache_mod.api.Cache) void {
    const now_time = cache_mod.engine.now();
    const ratio = cache_mod.engine.sweepPoll(cache, .{ .time = now_time });
    if (ratio > 0.10) {
        var swept: usize = 0;
        var kept: usize = 0;
        cache_mod.engine.sweep(cache, &swept, &kept, .{ .time = now_time });
    }
}

const RssError = error{
    Unsupported,
    ParseFailed,
    ReadFailed,
};

fn processRssBytes(page_size: usize) RssError!u64 {
    return switch (builtin.os.tag) {
        .linux => processRssLinux(page_size),
        .macos => processRssDarwin(),
        else => error.Unsupported,
    };
}

fn processRssLinux(page_size: usize) RssError!u64 {
    var file = std.fs.cwd().openFile("/proc/self/statm", .{}) catch return error.ReadFailed;
    defer file.close();
    var buf: [128]u8 = undefined;
    const len = file.readAll(&buf) catch return error.ReadFailed;
    const content = std.mem.trim(u8, buf[0..len], " \n\r\t");
    var it = std.mem.tokenizeAny(u8, content, " \t");
    _ = it.next() orelse return error.ParseFailed;
    const resident = it.next() orelse return error.ParseFailed;
    const pages = std.fmt.parseInt(u64, resident, 10) catch return error.ParseFailed;
    return pages * @as(u64, @intCast(page_size));
}

fn processRssDarwin() RssError!u64 {
    const task = std.c.mach_task_self();
    if (task == std.c.TASK_NULL) return error.ReadFailed;
    var info: std.c.mach_task_basic_info = undefined;
    var count: std.c.mach_msg_type_number_t = std.c.MACH_TASK_BASIC_INFO_COUNT;
    const result = std.c.task_info(
        task,
        std.c.MACH_TASK_BASIC_INFO,
        @as(std.c.task_info_t, @ptrCast(&info)),
        &count,
    );
    if (result != 0) return error.ReadFailed;
    return @as(u64, @intCast(info.resident_size));
}

test "autosweep removes expired entries" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const cache = try cache_mod.engine.init(.{
        .allocator = allocator,
        .nshards = 1,
    });
    defer cache_mod.engine.deinit(cache);

    const now_time = cache_mod.engine.now();
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const key = std.fmt.allocPrint(allocator, "k{d}", .{i}) catch unreachable;
        defer allocator.free(key);
        const expires = if (i < 5) now_time - 1 else now_time + @as(i64, @intCast(10 * std.time.ns_per_s));
        _ = try cache_mod.engine.store(cache, key, "v", .{ .expires = expires });
    }

    try std.testing.expectEqual(@as(usize, 10), cache_mod.engine.count(cache, .{}));
    autosweepTick(cache);
    try std.testing.expectEqual(@as(usize, 5), cache_mod.engine.count(cache, .{}));
}
