const std = @import("std");
const entry = @import("entry.zig");

pub const Cache = opaque {};
pub const Batch = opaque {};

pub const StoreResult = enum {
    Inserted,
    Replaced,
    Found,
    NotFound,
    Canceled,
};

pub const DeleteResult = enum {
    Deleted,
    NotFound,
    Canceled,
};

pub const IterResult = enum {
    Finished,
    Canceled,
};

pub const EvictReason = enum(u8) {
    Expired = 1,
    LowMem = 2,
    Cleared = 3,
};

pub const IterAction = packed struct(u8) {
    stop: bool = false,
    delete: bool = false,
    _reserved: u6 = 0,

    pub const Continue: IterAction = .{};
    pub const Stop: IterAction = .{ .stop = true };
    pub const Delete: IterAction = .{ .delete = true };
    pub const StopDelete: IterAction = .{ .stop = true, .delete = true };
};

pub const Update = struct {
    value: []const u8 = &.{},
    flags: u32 = 0,
    expires: i64 = 0,
};

pub const Entry = struct {
    _ptr: *anyopaque,
    _allocator: std.mem.Allocator,
    _usecas: bool,

    pub fn retain(self: Entry) void {
        const ptr = @as(*entry.Entry, @ptrCast(@alignCast(self._ptr)));
        entry.retain(ptr);
    }

    pub fn release(self: Entry) void {
        const ptr = @as(*entry.Entry, @ptrCast(@alignCast(self._ptr)));
        entry.release(ptr, self._allocator);
    }

    pub fn key(self: Entry, buf: *[128]u8) []const u8 {
        const ptr = @as(*entry.Entry, @ptrCast(@alignCast(self._ptr)));
        return entry.key(ptr, self._usecas, buf);
    }

    pub fn value(self: Entry) []const u8 {
        const ptr = @as(*entry.Entry, @ptrCast(@alignCast(self._ptr)));
        return entry.value(ptr, self._usecas);
    }

    pub fn flags(self: Entry) u32 {
        const ptr = @as(*entry.Entry, @ptrCast(@alignCast(self._ptr)));
        return entry.flags(ptr);
    }

    pub fn expires(self: Entry) i64 {
        const ptr = @as(*entry.Entry, @ptrCast(@alignCast(self._ptr)));
        return entry.expires(ptr);
    }

    pub fn cas(self: Entry) u64 {
        const ptr = @as(*entry.Entry, @ptrCast(@alignCast(self._ptr)));
        return entry.cas(ptr, self._usecas);
    }

    pub fn time(self: Entry) i64 {
        const ptr = @as(*entry.Entry, @ptrCast(@alignCast(self._ptr)));
        return entry.time(ptr);
    }
};

pub const YieldFn = *const fn (udata: ?*anyopaque) void;
pub const EvictedFn = *const fn (
    shard: u32,
    reason: EvictReason,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) void;
pub const NotifyFn = *const fn (
    shard: u32,
    time: i64,
    new_entry: ?*Entry,
    old_entry: ?*Entry,
    udata: ?*anyopaque,
) void;

pub const StoreEntryFn = *const fn (
    shard: u32,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) bool;
pub const LoadUpdateFn = *const fn (
    shard: u32,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) ?Update;
pub const DeleteEntryFn = *const fn (
    shard: u32,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) bool;
pub const IterEntryFn = *const fn (
    shard: u32,
    time: i64,
    key: []const u8,
    value: []const u8,
    expires: i64,
    flags: u32,
    cas: u64,
    udata: ?*anyopaque,
) IterAction;

pub const Options = struct {
    allocator: ?std.mem.Allocator = null,
    yield: ?YieldFn = null,
    evicted: ?EvictedFn = null,
    notify: ?NotifyFn = null,
    udata: ?*anyopaque = null,
    usecas: bool = false,
    nosixpack: bool = false,
    noevict: bool = false,
    allowshrink: bool = false,
    usethreadbatch: bool = false,
    nshards: u32 = 0,
    loadfactor: u8 = 0,
    seed: u64 = 0,
};

pub const StoreOptions = struct {
    time: i64 = 0,
    expires: i64 = 0,
    ttl: i64 = 0,
    cas: u64 = 0,
    flags: u32 = 0,
    keepttl: bool = false,
    casop: bool = false,
    restore_cas: bool = false,
    nx: bool = false,
    xx: bool = false,
    lowmem: bool = false,
    entry: ?StoreEntryFn = null,
    udata: ?*anyopaque = null,
};

pub const LoadOptions = struct {
    time: i64 = 0,
    notouch: bool = false,
    update: ?LoadUpdateFn = null,
    udata: ?*anyopaque = null,
};

pub const DeleteOptions = struct {
    time: i64 = 0,
    entry: ?DeleteEntryFn = null,
    udata: ?*anyopaque = null,
};

pub const IterOptions = struct {
    time: i64 = 0,
    oneshard: bool = false,
    oneshardidx: u32 = 0,
    entry: ?IterEntryFn = null,
    udata: ?*anyopaque = null,
};

pub const CountOptions = struct {
    time: i64 = 0,
    oneshard: bool = false,
    oneshardidx: u32 = 0,
};

pub const TotalOptions = struct {
    time: i64 = 0,
    oneshard: bool = false,
    oneshardidx: u32 = 0,
};

pub const SizeOptions = struct {
    time: i64 = 0,
    oneshard: bool = false,
    oneshardidx: u32 = 0,
    entriesonly: bool = false,
};

pub const SweepOptions = struct {
    time: i64 = 0,
    oneshard: bool = false,
    oneshardidx: u32 = 0,
};

pub const ClearOptions = struct {
    time: i64 = 0,
    oneshard: bool = false,
    oneshardidx: u32 = 0,
    deferfree: bool = false,
};

pub const SweepPollOptions = struct {
    time: i64 = 0,
    pollsize: u32 = 0,
};
