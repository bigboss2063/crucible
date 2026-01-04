# Crucible

Crucible is an embedded cache storage engine written in Zig with an optional server layer for HTTP and RESP (Valkey/Redis) protocols.
The built-in server uses libxev (io_uring on Linux, kqueue on macOS).

## Architecture

- Cache -> shards -> map -> buckets -> entries.
- Shards use spinlocks, CAS counters, and a robin-hood hashmap.
- Buckets use a 10-byte layout (48-bit entry pointer + 24-bit hash + DIB).
- Entries are single allocations with a packed header/payload layout.
- Optional sixpack key compression for compact keys.
- Batch mode holds shard locks across multiple operations; thread-local batches are supported.
- Server I/O uses per-connection ring buffers and incremental parsers.

## Advantages

- Embedded usage: no network overhead; direct in-process API.
- Predictable memory layout aligned.
- Sharded locking for high concurrency.
- Callbacks for eviction/notify and load/update hooks.
- Incremental protocol parsing with buffer reuse on the hot path.
- Built-in metrics and snapshot persistence endpoints.

## Defaults and Limits

Cache defaults (engine):

- Shards: 4096
- Initial map capacity: 64
- Load factor: 75% (clamped to 55-95)
- Sixpack: enabled
- CAS: disabled
- Eviction: enabled
- Allow shrink: disabled
- Thread-local batch: disabled

Server defaults (binary):

- Listen: 0.0.0.0:6379
- Protocol: auto (detects HTTP vs RESP)
- Threads: CPU count
- Max connections: 10,000 (buffers are preallocated)
- Backlog: 128
- Event loop entries: 256
- Buffer size: 4096 bytes (read/write/scratch per connection)
- Keepalive: 60s
- Max memory: 80% of system memory (RSS-based); eviction and autosweep enabled
  by default; `--maxmemory unlimited` disables eviction

Protocol limits (server):

- Max key length: buffer size
- Max value length: buffer size
- Max RESP args: 32

## Getting Started

Requirements: Zig 0.15.x on 64-bit Linux or macOS.

Build and run the server:

```sh
zig build
./zig-out/bin/crucible
```

By default the server listens on `0.0.0.0:6379` with protocol auto-detection.
Run `./zig-out/bin/crucible --help` for all options.

Run tests:

```sh
zig build test
```

Run the example:

```sh
zig build example
```

## Embedded Usage

`load` returns an optional retained entry handle. Read data from the handle and
call `release` when done.

```zig
const std = @import("std");
const crucible = @import("crucible");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const cache = try crucible.init(.{
        .allocator = allocator,
        .nshards = 4,
        .usecas = true,
    });
    defer crucible.deinit(cache);

    _ = try crucible.store(cache, "key", "value", .{});

    if (try crucible.load(cache, "key", .{})) |entry_handle| {
        defer entry_handle.release();
        const val = entry_handle.value();
        _ = val; // use the value
    }
}
```

`entryIter` returns a retained entry handle. Use `Entry.key`/`Entry.value` to read data and `release` when done (call `retain` if you need to keep it longer).

```zig
var cursor: u64 = 0;
if (crucible.entryIter(cache, 0, &cursor)) |entry_handle| {
    defer entry_handle.release();
    var key_buf: [128]u8 = undefined;
    const key = entry_handle.key(&key_buf);
    const value = entry_handle.value();
    _ = key;
    _ = value;
}
```

For a fuller walkthrough, see `examples/cache_demo.zig`.

## Server Layer

The server layer uses libxev for async I/O and supports HTTP and RESP protocols.
Use the built-in binary for a deployable server, or embed the server in your own Zig program for custom wiring.
Protocol auto-detection uses the first byte(s): `*`/`$` for RESP and `GET `/`PUT `/`POST `/`DELETE ` for HTTP.

Example CLI usage:

```sh
./zig-out/bin/crucible --listen 127.0.0.1:6379 --protocol resp --threads 4
```

Resource control flags:

```sh
./zig-out/bin/crucible --maxmemory 80% --evict yes --autosweep yes
```

Example embedded server:

```zig
const std = @import("std");
const crucible = @import("crucible");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const cache = try crucible.init(.{
        .allocator = allocator,
        .nshards = 4,
    });
    defer crucible.deinit(cache);

    var server = try crucible.server.network.Server.init(.{
        .allocator = allocator,
        .cache = cache,
        .address = try std.net.Address.parseIp("127.0.0.1", 8080),
        .protocol = .auto,
        .buffer_size = 4096,
    });
    defer server.deinit();

    try server.run();
}
```

### Metrics

`Server.metricsSnapshot()` returns counters for connections, requests, bytes,
and error types. `GET /@stats` returns JSON and `INFO`/`STATS` return
`key:value` lines.

Snapshot fields:

- `server.active_connections`
- `server.total_connections`
- `server.total_requests`
- `server.total_responses`
- `server.bytes_read`
- `server.bytes_written`
- `errors.accept`
- `errors.read`
- `errors.write`
- `errors.parse`
- `errors.protocol`
- `errors.pool_full`
- `errors.buffer_overflow`
- `errors.cache`
- `errors.timeout`
- `cache.items`
- `cache.total_items`
- `cache.bytes`
- `cache.shards`

### Ops

HTTP endpoints:

- `GET /<key>` loads the key.
- `POST /<key>` stores the body (requires `Content-Length`).
- `PUT /<key>` stores only if the key exists (xx semantics).
- `DELETE /<key>` deletes the key.
- `GET /@health` returns `200 OK` with body `OK`.
- `GET /@stats` returns a JSON metrics snapshot.
- `POST /@save` writes a snapshot (optional query `path` and `fast=1`).
- `POST /@load` loads a snapshot (optional query `path` and `fast=1`).

RESP commands:

- `PING` replies with `+PONG`.
- `INFO` and `STATS` return a bulk string of `key:value` lines.
- `GET <key>` returns a bulk string or `$-1`.
- `SET <key> <value> [NX|XX] [EX seconds|PX ms]` sets a value.
- `DEL <key>` returns `:1` if deleted, `:0` otherwise.
- `INCR <key>` and `DECR <key>` update integer counters.
- `EXPIRE <key> <seconds>` sets TTL and returns `:1` or `:0`.
- `TTL <key>` returns seconds remaining, `-1` for no TTL, `-2` if missing.
- `SAVE [TO <path>] [FAST]` writes a snapshot.
- `LOAD [FROM <path>] [FAST]` loads a snapshot.
  RESP pipeline is supported; commands are processed in order.

### Persistence

- `--persist <path>` enables snapshot load at startup and save on SIGINT/SIGTERM.
- `SAVE`/`LOAD` use the configured path unless an override is provided.
- `FAST` enables parallel save/load workers.
- `SAVE`/`LOAD` run asynchronously; if a save/load is already in progress the server returns HTTP 409 or RESP `-ERR`, so retry after a short delay.
- Snapshots use LZ4-compressed blocks with CRC32; TTLs are stored as remaining time and recomputed against wall clock on load, and CAS is restored only when CAS is enabled and the snapshot recorded CAS.

## Roadmap

* [X]  Background autosweep and RSS-based maxmemory monitoring with low-memory eviction gating.
* [X]  HTTP/RESP server layer with protocol auto-detection and incremental parsing.
* [X]  Metrics endpoints over HTTP (`/@health`, `/@stats`) and RESP (`INFO`, `STATS`).
* [X]  Snapshot persistence with `SAVE`/`LOAD` (including `FAST` mode).
* [ ]  Security: TLS and auth token support.
* [ ]  Ops: structured logging and benchmarking harness.
