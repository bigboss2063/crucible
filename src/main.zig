const std = @import("std");
const builtin = @import("builtin");
const crucible = @import("crucible");
const persistence = crucible.server.persistence;

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
    read_buffer_bytes: usize,
    write_buffer_bytes: usize,
    max_request_bytes: usize,
    max_response_bytes: usize,
    keepalive_ms: u64,
    cache_nshards: u32,
    cache_loadfactor: u8,
    cache_nosixpack: bool,
    cache_usecas: bool,
    maxmemory_bytes: ?u64,
    evict: bool,
    autosweep: bool,
    persist_path: ?[]const u8,
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
        .read_buffer_bytes = 16 * 1024,
        .write_buffer_bytes = 16 * 1024,
        .max_request_bytes = 1024 * 1024,
        .max_response_bytes = 1024 * 1024,
        .keepalive_ms = 60_000,
        .cache_nshards = 0,
        .cache_loadfactor = 0,
        .cache_nosixpack = false,
        .cache_usecas = false,
        .maxmemory_bytes = maxmemory,
        .evict = true,
        .autosweep = true,
        .persist_path = null,
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
        } else if (std.mem.eql(u8, arg, "--read-buffer-size")) {
            const value = try nextValue(args, &i);
            opts.read_buffer_bytes = try parseIntRange(usize, value, 1, std.math.maxInt(usize));
        } else if (std.mem.eql(u8, arg, "--write-buffer-size")) {
            const value = try nextValue(args, &i);
            opts.write_buffer_bytes = try parseIntRange(usize, value, 1, std.math.maxInt(usize));
        } else if (std.mem.eql(u8, arg, "--max-request-bytes")) {
            const value = try nextValue(args, &i);
            opts.max_request_bytes = try parseIntRange(usize, value, 1, std.math.maxInt(usize));
        } else if (std.mem.eql(u8, arg, "--max-response-bytes")) {
            const value = try nextValue(args, &i);
            opts.max_response_bytes = try parseIntRange(usize, value, 1, std.math.maxInt(usize));
        } else if (std.mem.eql(u8, arg, "--keepalive-ms")) {
            const value = try nextValue(args, &i);
            opts.keepalive_ms = try parseIntRange(u64, value, 0, std.math.maxInt(u64));
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
        } else if (std.mem.eql(u8, arg, "--persist")) {
            const value = try nextValue(args, &i);
            if (value.len == 0) return error.InvalidArgs;
            opts.persist_path = value;
        } else {
            return error.InvalidArgs;
        }
    }

    if (listen_override) |addr| {
        opts.address = addr;
    } else {
        opts.address = std.net.Address.parseIp(host, port) catch return error.InvalidArgs;
    }

    if (opts.read_buffer_bytes > opts.max_request_bytes) return error.InvalidArgs;
    if (opts.write_buffer_bytes > opts.max_response_bytes) return error.InvalidArgs;
    if (opts.max_response_bytes < opts.max_request_bytes) return error.InvalidArgs;

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
        \\  --read-buffer-size bytes     read buffer size        (default: 16384)
        \\  --write-buffer-size bytes    write buffer size       (default: 16384)
        \\  --max-request-bytes bytes    max request size        (default: 1048576)
        \\  --max-response-bytes bytes   max response size       (default: 1048576)
        \\  --keepalive-ms ms       keepalive timeout            (default: 60000)
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
        \\  --persist path          snapshot path for save/load
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

    var persist_path: ?[]u8 = null;
    defer if (persist_path) |path| allocator.free(path);
    if (opts.persist_path) |path| {
        persist_path = try allocator.dupe(u8, path);
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

    if (persist_path) |path| {
        _ = persistence.loadSnapshot(allocator, cache_instance, .{ .path = path }) catch |err| {
            if (err != error.FileNotFound) return err;
        };
    }

    const server_opts = crucible.server.network.ServerOptions{
        .allocator = allocator,
        .cache = cache_instance,
        .persist_path = persist_path,
        .address = opts.address,
        .protocol = opts.protocol,
        .max_connections = opts.max_connections,
        .read_buffer_bytes = opts.read_buffer_bytes,
        .write_buffer_bytes = opts.write_buffer_bytes,
        .max_request_bytes = opts.max_request_bytes,
        .max_response_bytes = opts.max_response_bytes,
        .keepalive_timeout_ns = opts.keepalive_ms * std.time.ns_per_ms,
        .backlog = opts.backlog,
        .loop_entries = opts.loop_entries,
        .unix_path = opts.unix_path,
        .maxmemory_bytes = opts.maxmemory_bytes,
        .evict = opts.evict,
        .autosweep = opts.autosweep,
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
        if (persist_path) |path| {
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
        if (persist_path) |path| {
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
    try std.testing.expect(opts.persist_path == null);
    try std.testing.expect(opts.evict);
    try std.testing.expect(opts.autosweep);
    try std.testing.expectEqual(@as(usize, 16 * 1024), opts.read_buffer_bytes);
    try std.testing.expectEqual(@as(usize, 16 * 1024), opts.write_buffer_bytes);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), opts.max_request_bytes);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), opts.max_response_bytes);
    try std.testing.expect(opts.unix_path == null);
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

test "parse args buffer sizing options" {
    const opts = try parseArgs(&[_][]const u8{
        "--read-buffer-size",
        "8192",
        "--write-buffer-size",
        "16384",
        "--max-request-bytes",
        "65536",
        "--max-response-bytes",
        "131072",
    });
    try std.testing.expectEqual(@as(usize, 8192), opts.read_buffer_bytes);
    try std.testing.expectEqual(@as(usize, 16384), opts.write_buffer_bytes);
    try std.testing.expectEqual(@as(usize, 65536), opts.max_request_bytes);
    try std.testing.expectEqual(@as(usize, 131072), opts.max_response_bytes);
}

test "parse args rejects invalid buffer sizing" {
    try std.testing.expectError(error.InvalidArgs, parseArgs(&[_][]const u8{
        "--write-buffer-size",
        "16384",
        "--max-response-bytes",
        "4096",
    }));
    try std.testing.expectError(error.InvalidArgs, parseArgs(&[_][]const u8{
        "--max-request-bytes",
        "8192",
        "--max-response-bytes",
        "4096",
    }));
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

test "parse args persist path" {
    const opts = try parseArgs(&[_][]const u8{
        "--persist",
        "/tmp/snap.crucible",
    });
    try std.testing.expectEqualStrings("/tmp/snap.crucible", opts.persist_path.?);
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
