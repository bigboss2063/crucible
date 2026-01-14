const std = @import("std");
const builtin = @import("builtin");
const crucible = @import("crucible");
const persistence = crucible.server.persistence;
const aof = crucible.server.aof;

var shutdown_signal = std.atomic.Value(bool).init(false);
var shutdown_exit = std.atomic.Value(bool).init(false);

fn handleSignal(_: c_int) callconv(.c) void {
    shutdown_signal.store(true, .release);
}

const StopFn = *const fn (*anyopaque) void;

fn signalWatcher(stop_fn: StopFn, ctx: *anyopaque) void {
    while (true) {
        if (shutdown_signal.load(.acquire)) {
            stop_fn(ctx);
            return;
        }
        if (shutdown_exit.load(.acquire)) return;
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
}

fn stopServer(ptr: *anyopaque) void {
    const server = @as(*crucible.server.network.Server, @ptrCast(@alignCast(ptr)));
    server.stop();
}

fn stopThreadedServer(ptr: *anyopaque) void {
    const server = @as(*crucible.server.network.ThreadedServer, @ptrCast(@alignCast(ptr)));
    server.stop();
}

fn installSignalHandlers() void {
    if (builtin.os.tag == .windows) return;
    var action = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &action, null);
    std.posix.sigaction(std.posix.SIG.TERM, &action, null);
}

const CliOptions = struct {
    address: std.net.Address,
    protocol: crucible.server.network.Protocol,
    threads: usize,
    max_connections: usize,
    backlog: u31,
    loop_entries: u32,
    keepalive_ms: u64,
    cache_nshards: u32,
    cache_loadfactor: u8,
    cache_nosixpack: bool,
    cache_usecas: bool,
    maxmemory_bytes: ?u64,
    evict: bool,
    autosweep: bool,
    output_hard_bytes: usize,
    output_soft_bytes: usize,
    output_soft_seconds: u32,
    persist_dir: []const u8,
    dbfilename: []const u8,
    appendonly: bool,
    appendfilename: []const u8,
    appendfsync: aof.AppendFsync,
    auto_aof_rewrite_percentage: u32,
    auto_aof_rewrite_min_size: u64,
    unix_path: ?[]const u8,
    show_help: bool,
};

const ParseError = error{InvalidArgs};

fn defaultThreadCount() usize {
    return std.Thread.getCpuCount() catch 1;
}

fn defaultOptions(sysmem: u64) ParseError!CliOptions {
    const maxmemory = (try parseMaxMemory("80%", sysmem)) orelse return error.InvalidArgs;
    return .{
        .address = std.net.Address.parseIp("0.0.0.0", 6379) catch unreachable,
        .protocol = .auto,
        .threads = defaultThreadCount(),
        .max_connections = 10_000,
        .backlog = 128,
        .loop_entries = 256,
        .keepalive_ms = 60_000,
        .cache_nshards = 0,
        .cache_loadfactor = 0,
        .cache_nosixpack = false,
        .cache_usecas = false,
        .maxmemory_bytes = maxmemory,
        .evict = true,
        .autosweep = true,
        .output_hard_bytes = 0,
        .output_soft_bytes = 0,
        .output_soft_seconds = 0,
        .persist_dir = ".",
        .dbfilename = "dump.rdb",
        .appendonly = false,
        .appendfilename = "appendonly.aof",
        .appendfsync = .everysec,
        .auto_aof_rewrite_percentage = 100,
        .auto_aof_rewrite_min_size = 64 * 1024 * 1024,
        .unix_path = null,
        .show_help = false,
    };
}

fn parseIntRange(comptime T: type, value: []const u8, min: T, max: T) ParseError!T {
    const parsed = std.fmt.parseInt(T, value, 10) catch return error.InvalidArgs;
    if (parsed < min or parsed > max) return error.InvalidArgs;
    return parsed;
}

fn parsePort(value: []const u8) ParseError!u16 {
    return parseIntRange(u16, value, 1, std.math.maxInt(u16));
}

fn parseListen(value: []const u8) ParseError!std.net.Address {
    if (value.len == 0) return error.InvalidArgs;
    if (value[0] == '[') {
        const end = std.mem.indexOfScalar(u8, value, ']') orelse return error.InvalidArgs;
        if (end + 2 > value.len or value[end + 1] != ':') return error.InvalidArgs;
        const host = value[1..end];
        const port = try parsePort(value[end + 2 ..]);
        return std.net.Address.parseIp(host, port) catch return error.InvalidArgs;
    }

    const sep = std.mem.lastIndexOfScalar(u8, value, ':') orelse return error.InvalidArgs;
    if (sep == 0 or sep + 1 >= value.len) return error.InvalidArgs;
    if (std.mem.indexOfScalar(u8, value[0..sep], ':') != null) return error.InvalidArgs;
    const host = value[0..sep];
    const port = try parsePort(value[sep + 1 ..]);
    return std.net.Address.parseIp(host, port) catch return error.InvalidArgs;
}

fn parseBool(value: []const u8) ?bool {
    if (std.ascii.eqlIgnoreCase(value, "yes") or
        std.ascii.eqlIgnoreCase(value, "true") or
        std.mem.eql(u8, value, "1"))
    {
        return true;
    }
    if (std.ascii.eqlIgnoreCase(value, "no") or
        std.ascii.eqlIgnoreCase(value, "false") or
        std.mem.eql(u8, value, "0"))
    {
        return false;
    }
    return null;
}

fn parseAppendFsync(value: []const u8) ?aof.AppendFsync {
    if (std.ascii.eqlIgnoreCase(value, "always")) return .always;
    if (std.ascii.eqlIgnoreCase(value, "everysec")) return .everysec;
    if (std.ascii.eqlIgnoreCase(value, "no")) return .no;
    return null;
}

fn nextValue(args: []const []const u8, index: *usize) ParseError![]const u8 {
    if (index.* + 1 >= args.len) return error.InvalidArgs;
    index.* += 1;
    return args[index.*];
}

fn systemMemoryBytes() ParseError!u64 {
    return std.process.totalSystemMemory() catch return error.InvalidArgs;
}

fn parseMaxMemory(value: []const u8, sysmem: u64) ParseError!?u64 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidArgs;
    if (std.ascii.eqlIgnoreCase(trimmed, "unlimited")) return null;

    var end: usize = 0;
    while (end < trimmed.len and (std.ascii.isDigit(trimmed[end]) or trimmed[end] == '.')) : (end += 1) {}
    if (end == 0) return error.InvalidArgs;

    const number = std.fmt.parseFloat(f64, trimmed[0..end]) catch return error.InvalidArgs;
    if (!(number > 0) or !std.math.isFinite(number)) return error.InvalidArgs;
    const suffix = std.mem.trim(u8, trimmed[end..], " \t\r\n");

    var bytes: f64 = 0;
    if (suffix.len == 0) {
        bytes = number;
    } else if (suffix.len == 1 and suffix[0] == '%') {
        if (sysmem == 0) return error.InvalidArgs;
        bytes = number / 100.0 * @as(f64, @floatFromInt(sysmem));
    } else if (suffixEquals(suffix, "k", "kb")) {
        bytes = number * 1024.0;
    } else if (suffixEquals(suffix, "m", "mb")) {
        bytes = number * 1024.0 * 1024.0;
    } else if (suffixEquals(suffix, "g", "gb")) {
        bytes = number * 1024.0 * 1024.0 * 1024.0;
    } else if (suffixEquals(suffix, "t", "tb")) {
        bytes = number * 1024.0 * 1024.0 * 1024.0 * 1024.0;
    } else {
        return error.InvalidArgs;
    }

    if (!(bytes > 0) or !std.math.isFinite(bytes)) return error.InvalidArgs;
    const max = @as(f64, @floatFromInt(std.math.maxInt(u64)));
    if (bytes > max) return error.InvalidArgs;
    return @as(u64, @intFromFloat(bytes));
}

fn suffixEquals(value: []const u8, short: []const u8, long: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, short) or std.ascii.eqlIgnoreCase(value, long);
}

fn parseByteSize(value: []const u8) ParseError!u64 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidArgs;

    var end: usize = 0;
    while (end < trimmed.len and (std.ascii.isDigit(trimmed[end]) or trimmed[end] == '.')) : (end += 1) {}
    if (end == 0) return error.InvalidArgs;

    const number = std.fmt.parseFloat(f64, trimmed[0..end]) catch return error.InvalidArgs;
    if (!(number >= 0) or !std.math.isFinite(number)) return error.InvalidArgs;
    const suffix = std.mem.trim(u8, trimmed[end..], " \t\r\n");

    var bytes: f64 = 0;
    if (suffix.len == 0) {
        bytes = number;
    } else if (suffixEquals(suffix, "k", "kb")) {
        bytes = number * 1024.0;
    } else if (suffixEquals(suffix, "m", "mb")) {
        bytes = number * 1024.0 * 1024.0;
    } else if (suffixEquals(suffix, "g", "gb")) {
        bytes = number * 1024.0 * 1024.0 * 1024.0;
    } else if (suffixEquals(suffix, "t", "tb")) {
        bytes = number * 1024.0 * 1024.0 * 1024.0 * 1024.0;
    } else {
        return error.InvalidArgs;
    }

    if (!(bytes >= 0) or !std.math.isFinite(bytes)) return error.InvalidArgs;
    const max = @as(f64, @floatFromInt(std.math.maxInt(u64)));
    if (bytes > max) return error.InvalidArgs;
    return @as(u64, @intFromFloat(bytes));
}

fn parseByteSizeUsize(value: []const u8) ParseError!usize {
    const bytes = try parseByteSize(value);
    if (bytes > std.math.maxInt(usize)) return error.InvalidArgs;
    return @as(usize, @intCast(bytes));
}

fn resolvePersistPath(allocator: std.mem.Allocator, dir: []const u8, filename: []const u8) ![]u8 {
    if (filename.len == 0) return error.InvalidArgs;
    if (std.fs.path.isAbsolute(filename)) {
        return try allocator.dupe(u8, filename);
    }
    if (dir.len == 0) return error.InvalidArgs;
    return try std.fs.path.join(allocator, &[_][]const u8{ dir, filename });
}

fn loadPersistence(
    allocator: std.mem.Allocator,
    cache_instance: *crucible.Cache,
    snapshot_path: ?[]const u8,
    aof_path: ?[]const u8,
    appendonly: bool,
) !void {
    if (appendonly) {
        var loaded_aof = false;
        if (aof_path) |path| {
            loaded_aof = true;
            _ = aof.replay(allocator, cache_instance, path) catch |err| {
                if (err == error.FileNotFound) {
                    loaded_aof = false;
                } else {
                    return err;
                }
            };
        }
        if (!loaded_aof) {
            if (snapshot_path) |path| {
                _ = persistence.loadSnapshot(allocator, cache_instance, .{ .path = path }) catch |err| {
                    if (err != error.FileNotFound) return err;
                };
            }
        }
    } else if (snapshot_path) |path| {
        _ = persistence.loadSnapshot(allocator, cache_instance, .{ .path = path }) catch |err| {
            if (err != error.FileNotFound) return err;
        };
    }
}

fn parseArgs(args: []const []const u8) ParseError!CliOptions {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            const sysmem = try systemMemoryBytes();
            var help_opts = try defaultOptions(sysmem);
            help_opts.show_help = true;
            return help_opts;
        }
    }

    const sysmem = try systemMemoryBytes();
    var opts = try defaultOptions(sysmem);
    var host: []const u8 = "0.0.0.0";
    var port: u16 = 6379;
    var listen_override: ?std.net.Address = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h")) {
            host = try nextValue(args, &i);
        } else if (std.mem.eql(u8, arg, "-p")) {
            const value = try nextValue(args, &i);
            port = try parsePort(value);
        } else if (std.mem.eql(u8, arg, "--listen")) {
            const value = try nextValue(args, &i);
            listen_override = try parseListen(value);
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--unixsocket")) {
            const value = try nextValue(args, &i);
            if (value.len == 0) return error.InvalidArgs;
            opts.unix_path = value;
        } else if (std.mem.eql(u8, arg, "--protocol")) {
            const value = try nextValue(args, &i);
            if (std.ascii.eqlIgnoreCase(value, "auto")) {
                opts.protocol = .auto;
            } else if (std.ascii.eqlIgnoreCase(value, "http")) {
                opts.protocol = .http;
            } else if (std.ascii.eqlIgnoreCase(value, "resp")) {
                opts.protocol = .resp;
            } else {
                return error.InvalidArgs;
            }
        } else if (std.mem.eql(u8, arg, "--threads")) {
            const value = try nextValue(args, &i);
            opts.threads = try parseIntRange(usize, value, 1, std.math.maxInt(usize));
        } else if (std.mem.eql(u8, arg, "--maxconns")) {
            const value = try nextValue(args, &i);
            opts.max_connections = try parseIntRange(usize, value, 1, std.math.maxInt(usize));
        } else if (std.mem.eql(u8, arg, "--backlog")) {
            const value = try nextValue(args, &i);
            opts.backlog = try parseIntRange(u31, value, 1, std.math.maxInt(u31));
        } else if (std.mem.eql(u8, arg, "--queuesize")) {
            const value = try nextValue(args, &i);
            opts.loop_entries = try parseIntRange(u32, value, 1, std.math.maxInt(u32));
        } else if (std.mem.eql(u8, arg, "--keepalive-ms")) {
            const value = try nextValue(args, &i);
            opts.keepalive_ms = try parseIntRange(u64, value, 0, std.math.maxInt(u64));
        } else if (std.mem.eql(u8, arg, "--output-hard-bytes")) {
            const value = try nextValue(args, &i);
            opts.output_hard_bytes = try parseByteSizeUsize(value);
        } else if (std.mem.eql(u8, arg, "--output-soft-bytes")) {
            const value = try nextValue(args, &i);
            opts.output_soft_bytes = try parseByteSizeUsize(value);
        } else if (std.mem.eql(u8, arg, "--output-soft-seconds")) {
            const value = try nextValue(args, &i);
            opts.output_soft_seconds = try parseIntRange(u32, value, 0, std.math.maxInt(u32));
        } else if (std.mem.eql(u8, arg, "--shards")) {
            const value = try nextValue(args, &i);
            opts.cache_nshards = try parseIntRange(u32, value, 0, std.math.maxInt(u32));
        } else if (std.mem.eql(u8, arg, "--loadfactor")) {
            const value = try nextValue(args, &i);
            opts.cache_loadfactor = try parseIntRange(u8, value, 0, 100);
        } else if (std.mem.eql(u8, arg, "--keysixpack")) {
            const value = try nextValue(args, &i);
            const parsed = parseBool(value) orelse return error.InvalidArgs;
            opts.cache_nosixpack = !parsed;
        } else if (std.mem.eql(u8, arg, "--cas")) {
            const value = try nextValue(args, &i);
            opts.cache_usecas = parseBool(value) orelse return error.InvalidArgs;
        } else if (std.mem.eql(u8, arg, "--maxmemory")) {
            const value = try nextValue(args, &i);
            opts.maxmemory_bytes = try parseMaxMemory(value, sysmem);
        } else if (std.mem.eql(u8, arg, "--evict")) {
            const value = try nextValue(args, &i);
            opts.evict = parseBool(value) orelse return error.InvalidArgs;
        } else if (std.mem.eql(u8, arg, "--autosweep")) {
            const value = try nextValue(args, &i);
            opts.autosweep = parseBool(value) orelse return error.InvalidArgs;
        } else if (std.mem.eql(u8, arg, "--dir")) {
            const value = try nextValue(args, &i);
            if (value.len == 0) return error.InvalidArgs;
            opts.persist_dir = value;
        } else if (std.mem.eql(u8, arg, "--dbfilename")) {
            const value = try nextValue(args, &i);
            if (value.len == 0) return error.InvalidArgs;
            opts.dbfilename = value;
        } else if (std.mem.eql(u8, arg, "--appendonly")) {
            const value = try nextValue(args, &i);
            opts.appendonly = parseBool(value) orelse return error.InvalidArgs;
        } else if (std.mem.eql(u8, arg, "--appendfilename")) {
            const value = try nextValue(args, &i);
            if (value.len == 0) return error.InvalidArgs;
            opts.appendfilename = value;
        } else if (std.mem.eql(u8, arg, "--appendfsync")) {
            const value = try nextValue(args, &i);
            opts.appendfsync = parseAppendFsync(value) orelse return error.InvalidArgs;
        } else if (std.mem.eql(u8, arg, "--auto-aof-rewrite-percentage")) {
            const value = try nextValue(args, &i);
            opts.auto_aof_rewrite_percentage = try parseIntRange(u32, value, 0, std.math.maxInt(u32));
        } else if (std.mem.eql(u8, arg, "--auto-aof-rewrite-min-size")) {
            const value = try nextValue(args, &i);
            opts.auto_aof_rewrite_min_size = try parseByteSize(value);
        } else {
            return error.InvalidArgs;
        }
    }

    if (listen_override) |addr| {
        opts.address = addr;
    } else {
        opts.address = std.net.Address.parseIp(host, port) catch return error.InvalidArgs;
    }

    if (opts.maxmemory_bytes == null) {
        opts.evict = false;
    }
    return opts;
}

fn printUsage(file: std.fs.File) !void {
    var buffer: [1024]u8 = undefined;
    var writer = file.writer(&buffer);
    const out = &writer.interface;
    try out.writeAll(
        \\Usage: crucible [options]
        \\
        \\Basic options:
        \\  -h host                 listening host                (default: 0.0.0.0)
        \\  -p port                 listening port                (default: 6379)
        \\  --listen addr           listen address host:port or [ipv6]:port
        \\  -s, --unixsocket path   unix socket listener         (default: none)
        \\  --protocol auto|http|resp                          (default: auto)
        \\
        \\Performance options:
        \\  --threads count         number of worker threads     (default: cpu count)
        \\  --maxconns count        maximum connections          (default: 10000)
        \\  --backlog count         accept backlog               (default: 128)
        \\  --queuesize count       event loop queue size        (default: 256)
        \\  --keepalive-ms ms       keepalive timeout            (default: 60000)
        \\
        \\Output buffer options:
        \\  --output-hard-bytes n   hard output limit            (default: 0)
        \\  --output-soft-bytes n   soft output limit            (default: 0)
        \\  --output-soft-seconds n soft limit grace seconds     (default: 0)
        \\
        \\Cache options:
        \\  --shards count          number of shards             (default: engine)
        \\  --loadfactor percent    hash load factor 0-100       (default: engine)
        \\  --keysixpack yes/no     sixpack compress keys        (default: yes)
        \\  --cas yes/no            enable CAS                   (default: no)
        \\  --maxmemory value       max memory usage             (default: 80%)
        \\  --evict yes/no          evict keys at maxmemory      (default: yes)
        \\  --autosweep yes/no      automatic eviction sweeps    (default: yes)
        \\
        \\Persistence options:
        \\  --dir path              persistence directory       (default: .)
        \\  --dbfilename name       snapshot file name          (default: dump.rdb)
        \\  --appendonly yes/no     enable append-only file     (default: no)
        \\  --appendfilename name   append-only file name       (default: appendonly.aof)
        \\  --appendfsync policy    always|everysec|no          (default: everysec)
        \\  --auto-aof-rewrite-percentage n                    (default: 100)
        \\  --auto-aof-rewrite-min-size bytes                  (default: 64mb)
        \\  --help
        \\
    );
    try out.flush();
}

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const opts = parseArgs(args[1..]) catch {
        try printUsage(std.fs.File.stderr());
        std.process.argsFree(allocator, args);
        std.process.exit(1);
    };

    if (opts.show_help) {
        try printUsage(std.fs.File.stdout());
        return;
    }

    shutdown_signal.store(false, .release);
    shutdown_exit.store(false, .release);

    var snapshot_path: ?[]u8 = null;
    var aof_path: ?[]u8 = null;
    defer {
        if (snapshot_path) |path| allocator.free(path);
        if (aof_path) |path| allocator.free(path);
    }

    snapshot_path = try resolvePersistPath(allocator, opts.persist_dir, opts.dbfilename);
    if (opts.appendonly) {
        aof_path = try resolvePersistPath(allocator, opts.persist_dir, opts.appendfilename);
    }

    const cache_instance = try crucible.init(.{
        .allocator = allocator,
        .nshards = opts.cache_nshards,
        .loadfactor = opts.cache_loadfactor,
        .nosixpack = opts.cache_nosixpack,
        .usecas = opts.cache_usecas,
        .noevict = !opts.evict,
    });
    defer crucible.deinit(cache_instance);

    try loadPersistence(allocator, cache_instance, snapshot_path, aof_path, opts.appendonly);

    const server_opts = crucible.server.network.ServerOptions{
        .allocator = allocator,
        .cache = cache_instance,
        .persistence = .{
            .snapshot_path = snapshot_path,
            .appendonly = opts.appendonly,
            .aof_path = aof_path,
            .appendfsync = opts.appendfsync,
            .auto_aof_rewrite_percentage = opts.auto_aof_rewrite_percentage,
            .auto_aof_rewrite_min_size = opts.auto_aof_rewrite_min_size,
        },
        .address = opts.address,
        .protocol = opts.protocol,
        .max_connections = opts.max_connections,
        .keepalive_timeout_ns = opts.keepalive_ms * std.time.ns_per_ms,
        .backlog = opts.backlog,
        .loop_entries = opts.loop_entries,
        .unix_path = opts.unix_path,
        .maxmemory_bytes = opts.maxmemory_bytes,
        .evict = opts.evict,
        .autosweep = opts.autosweep,
        .output_limits = .{
            .hard_bytes = opts.output_hard_bytes,
            .soft_bytes = opts.output_soft_bytes,
            .soft_seconds = opts.output_soft_seconds,
        },
    };

    if (opts.threads <= 1) {
        var server: crucible.server.network.Server = undefined;
        try server.initInPlace(server_opts);
        defer server.deinit();
        var signal_thread: ?std.Thread = null;
        if (builtin.os.tag != .windows) {
            installSignalHandlers();
            signal_thread = try std.Thread.spawn(.{}, signalWatcher, .{ stopServer, &server });
        }
        try server.run();
        shutdown_exit.store(true, .release);
        if (signal_thread) |thread| {
            thread.join();
        }
        if (snapshot_path) |path| {
            if (shutdown_signal.load(.acquire)) {
                server.persistence.waitForIdle();
                _ = try persistence.saveSnapshot(allocator, cache_instance, .{ .path = path });
            }
        }
    } else {
        var server = try crucible.server.network.ThreadedServer.init(server_opts, opts.threads);
        defer server.deinit();
        var signal_thread: ?std.Thread = null;
        if (builtin.os.tag != .windows) {
            installSignalHandlers();
            signal_thread = try std.Thread.spawn(.{}, signalWatcher, .{ stopThreadedServer, &server });
        }
        try server.run();
        shutdown_exit.store(true, .release);
        if (signal_thread) |thread| {
            thread.join();
        }
        if (snapshot_path) |path| {
            if (shutdown_signal.load(.acquire)) {
                server.persistence.waitForIdle();
                _ = try persistence.saveSnapshot(allocator, cache_instance, .{ .path = path });
            }
        }
    }
}

test "parse args defaults" {
    const opts = try parseArgs(&[_][]const u8{});
    const expected = try std.net.Address.parseIp("0.0.0.0", 6379);
    try std.testing.expect(std.net.Address.eql(expected, opts.address));
    try std.testing.expectEqual(crucible.server.network.Protocol.auto, opts.protocol);
    try std.testing.expect(opts.threads >= 1);
    try std.testing.expectEqual(@as(usize, 10_000), opts.max_connections);
    try std.testing.expectEqualStrings(".", opts.persist_dir);
    try std.testing.expectEqualStrings("dump.rdb", opts.dbfilename);
    try std.testing.expect(!opts.appendonly);
    try std.testing.expectEqualStrings("appendonly.aof", opts.appendfilename);
    try std.testing.expectEqual(aof.AppendFsync.everysec, opts.appendfsync);
    try std.testing.expectEqual(@as(u32, 100), opts.auto_aof_rewrite_percentage);
    try std.testing.expectEqual(@as(u64, 64 * 1024 * 1024), opts.auto_aof_rewrite_min_size);
    try std.testing.expect(opts.evict);
    try std.testing.expect(opts.autosweep);
    try std.testing.expect(opts.unix_path == null);
    try std.testing.expectEqual(@as(usize, 0), opts.output_hard_bytes);
    try std.testing.expectEqual(@as(usize, 0), opts.output_soft_bytes);
    try std.testing.expectEqual(@as(u32, 0), opts.output_soft_seconds);
    const sysmem = try systemMemoryBytes();
    const expected_max = @as(u64, @intFromFloat(@as(f64, @floatFromInt(sysmem)) * 0.8));
    try std.testing.expectEqual(@as(?u64, expected_max), opts.maxmemory_bytes);
}

test "parse args listen and protocol" {
    const opts = try parseArgs(&[_][]const u8{
        "--listen",
        "127.0.0.1:6380",
        "--protocol",
        "resp",
    });
    const expected = try std.net.Address.parseIp("127.0.0.1", 6380);
    try std.testing.expect(std.net.Address.eql(expected, opts.address));
    try std.testing.expectEqual(crucible.server.network.Protocol.resp, opts.protocol);
}

test "parse args unixsocket" {
    const opts = try parseArgs(&[_][]const u8{
        "-s",
        "crucible.sock",
    });
    try std.testing.expect(opts.unix_path != null);
    try std.testing.expectEqualStrings("crucible.sock", opts.unix_path.?);
}

test "parse args output limits" {
    const opts = try parseArgs(&[_][]const u8{
        "--output-hard-bytes",
        "64kb",
        "--output-soft-bytes",
        "32kb",
        "--output-soft-seconds",
        "5",
    });
    try std.testing.expectEqual(@as(usize, 64 * 1024), opts.output_hard_bytes);
    try std.testing.expectEqual(@as(usize, 32 * 1024), opts.output_soft_bytes);
    try std.testing.expectEqual(@as(u32, 5), opts.output_soft_seconds);
}

test "parse args cache options" {
    const opts = try parseArgs(&[_][]const u8{
        "--shards",
        "1024",
        "--loadfactor",
        "80",
        "--keysixpack",
        "no",
        "--cas",
        "yes",
    });
    try std.testing.expectEqual(@as(u32, 1024), opts.cache_nshards);
    try std.testing.expectEqual(@as(u8, 80), opts.cache_loadfactor);
    try std.testing.expectEqual(true, opts.cache_nosixpack);
    try std.testing.expectEqual(true, opts.cache_usecas);
}

test "parse args maxmemory and evict" {
    const opts = try parseArgs(&[_][]const u8{
        "--maxmemory",
        "64mb",
        "--evict",
        "no",
        "--autosweep",
        "no",
    });
    try std.testing.expectEqual(@as(?u64, 64 * 1024 * 1024), opts.maxmemory_bytes);
    try std.testing.expectEqual(false, opts.evict);
    try std.testing.expectEqual(false, opts.autosweep);
}

test "parse args maxmemory unlimited disables eviction" {
    const opts = try parseArgs(&[_][]const u8{
        "--maxmemory",
        "unlimited",
        "--evict",
        "yes",
    });
    try std.testing.expect(opts.maxmemory_bytes == null);
    try std.testing.expectEqual(false, opts.evict);
}

test "parse maxmemory formats" {
    const sysmem: u64 = 1_000_000;
    try std.testing.expectEqual(@as(?u64, 500_000), try parseMaxMemory("50%", sysmem));
    try std.testing.expectEqual(@as(?u64, 1024), try parseMaxMemory("1kb", sysmem));
    try std.testing.expectEqual(@as(?u64, 2 * 1024 * 1024), try parseMaxMemory("2m", sysmem));
    try std.testing.expectEqual(@as(?u64, 3 * 1024 * 1024 * 1024), try parseMaxMemory("3GB", sysmem));
    try std.testing.expectEqual(@as(?u64, null), try parseMaxMemory("unlimited", sysmem));
}

test "parse args persistence flags" {
    const opts = try parseArgs(&[_][]const u8{
        "--dir",
        "/tmp",
        "--dbfilename",
        "snap.rdb",
        "--appendonly",
        "yes",
        "--appendfilename",
        "append.aof",
        "--appendfsync",
        "always",
        "--auto-aof-rewrite-percentage",
        "200",
        "--auto-aof-rewrite-min-size",
        "8mb",
    });
    try std.testing.expectEqualStrings("/tmp", opts.persist_dir);
    try std.testing.expectEqualStrings("snap.rdb", opts.dbfilename);
    try std.testing.expect(opts.appendonly);
    try std.testing.expectEqualStrings("append.aof", opts.appendfilename);
    try std.testing.expectEqual(aof.AppendFsync.always, opts.appendfsync);
    try std.testing.expectEqual(@as(u32, 200), opts.auto_aof_rewrite_percentage);
    try std.testing.expectEqual(@as(u64, 8 * 1024 * 1024), opts.auto_aof_rewrite_min_size);
}

test "load persistence prefers aof when present" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const snap_path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "dump.rdb",
    });
    defer allocator.free(snap_path);

    const aof_path = try std.fs.path.join(allocator, &[_][]const u8{
        ".zig-cache",
        "tmp",
        tmp.sub_path[0..],
        "appendonly.aof",
    });
    defer allocator.free(aof_path);

    const cache_snapshot = try crucible.init(.{ .allocator = allocator, .nshards = 1 });
    defer crucible.deinit(cache_snapshot);
    _ = try crucible.store(cache_snapshot, "k", "snap", .{});
    _ = try persistence.saveSnapshot(allocator, cache_snapshot, .{ .path = snap_path });

    var mgr = aof.Manager.init(allocator, cache_snapshot, .{ .path = aof_path, .enabled = true });
    try mgr.start();
    try mgr.appendSet("k", "aof", 0, 0, 0);
    mgr.deinit();

    const cache_loaded = try crucible.init(.{ .allocator = allocator, .nshards = 1 });
    defer crucible.deinit(cache_loaded);

    try loadPersistence(allocator, cache_loaded, snap_path, aof_path, true);
    const entry = try crucible.load(cache_loaded, "k", .{});
    try std.testing.expect(entry != null);
    if (entry) |handle| {
        defer handle.release();
        try std.testing.expectEqualStrings("aof", handle.value());
    }
}

test "parse args invalid threads" {
    try std.testing.expectError(error.InvalidArgs, parseArgs(&[_][]const u8{
        "--threads",
        "0",
    }));
}

test "parse args help" {
    const opts = try parseArgs(&[_][]const u8{"--help"});
    try std.testing.expect(opts.show_help);
}

test "parse listen ipv6" {
    const addr = try parseListen("[::1]:6380");
    const expected = try std.net.Address.parseIp("::1", 6380);
    try std.testing.expect(std.net.Address.eql(expected, addr));
}

test "parse maxmemory raw and tb" {
    const sysmem: u64 = 1_000_000;
    try std.testing.expectEqual(@as(?u64, 4096), try parseMaxMemory("4096", sysmem));
    try std.testing.expectEqual(@as(?u64, 1 * 1024 * 1024 * 1024 * 1024), try parseMaxMemory("1tb", sysmem));
}

test "parse bool invalid returns null" {
    try std.testing.expect(parseBool("maybe") == null);
}

test "parse args network tuning" {
    const opts = try parseArgs(&[_][]const u8{
        "-h",
        "127.0.0.1",
        "-p",
        "6381",
        "--protocol",
        "auto",
        "--protocol",
        "http",
        "--maxconns",
        "100",
        "--backlog",
        "64",
        "--queuesize",
        "512",
        "--keepalive-ms",
        "5000",
        "--maxmemory",
        "1tb",
    });
    const expected = try std.net.Address.parseIp("127.0.0.1", 6381);
    try std.testing.expect(std.net.Address.eql(expected, opts.address));
    try std.testing.expectEqual(crucible.server.network.Protocol.http, opts.protocol);
    try std.testing.expectEqual(@as(usize, 100), opts.max_connections);
    try std.testing.expectEqual(@as(u31, 64), opts.backlog);
    try std.testing.expectEqual(@as(u32, 512), opts.loop_entries);
    try std.testing.expectEqual(@as(u64, 5000), opts.keepalive_ms);
    try std.testing.expectEqual(@as(?u64, 1 * 1024 * 1024 * 1024 * 1024), opts.maxmemory_bytes);
}
