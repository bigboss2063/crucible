# Crucible

[![coverage](https://codecov.io/gh/bigboss2063/crucible/branch/main/graph/badge.svg)](https://codecov.io/gh/bigboss2063/crucible) [![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/bigboss2063/crucible)

Crucible 是一个用 Zig 编写的嵌入式缓存存储引擎，带有可选的 HTTP 和 RESP（Valkey/Redis）协议服务器层。
内置服务器使用 libxev（Linux 上为 io_uring，macOS 上为 kqueue）。
灵感来自 [Pogocache](https://github.com/tidwall/pogocache)。

## 架构

- 缓存 -> 分片 -> 映射 -> 桶 -> 条目
- 分片使用自旋锁、CAS 计数器和罗宾 hood 哈希表
- 桶使用 10 字节布局（48 位条目指针 + 24 位哈希 + DIB）
- 条目为单次分配，具有紧凑的 header/payload 布局
- 可选的 sixpack 键压缩，用于紧凑键
- 批量模式在多个操作期间保持分片锁；支持线程本地批处理
- 服务器 I/O 使用每连接环形缓冲区和增量解析器

## 优势

- 嵌入式使用：无网络开销；直接进程内 API
- 可预测的内存布局对齐
- 分片锁实现高并发
- 驱逐/通知回调和加载/更新钩子
- 热路径上缓冲区重用的增量协议解析
- 内置指标和快照持久化端点

## 为什么选择 Zig

- 手动内存管理，无 GC 暂停，实现可预测的延迟
- 精确控制内存布局和对齐，用于紧凑数据结构
- Debug/ReleaseSafe 中的安全检查，ReleaseFast 中类似 C 的性能
- 简单的 C 互操作，易于嵌入系统栈
- 单一工具链即可构建 Linux 和 macOS 可执行文件

## 基准测试

详见 `BENCHMARKS.md` 了解机器详情、配置、参数和完整结果。

## 默认值和限制

缓存默认值（引擎）：

- 分片数：4096
- 初始映射容量：64
- 负载因子：75%（限制在 55-95%）
- Sixpack：启用
- CAS：禁用
- 驱逐：启用
- 允许收缩：禁用
- 线程本地批处理：禁用

服务器默认值（二进制）：

- 监听：0.0.0.0:6379
- 协议：自动（检测 HTTP vs RESP）
- 线程数：CPU 数量
- 最大连接数：10,000（缓冲区预分配）
- 待处理队列：128
- 事件循环条目：256
- 读取缓冲区：初始 16KB，按需增长；输出缓冲区：16KB 内联 + 16KB 块队列（按需增长）
- Keepalive：60 秒
- 最大内存：系统内存的 80%（基于 RSS）；默认启用驱逐和自动清理
  使用 `--maxmemory unlimited` 可禁用驱逐

协议限制（服务器）：

- 最大键长：1MB（固定）
- 最大值长：1MB（固定）
- 最大 RESP 参数：32

## 快速开始

要求：64 位 Linux 或 macOS 上的 Zig 0.15.x。

构建并运行服务器：

```sh
zig build
./zig-out/bin/crucible
```

默认情况下，服务器监听 `0.0.0.0:6379` 并自动检测协议。
运行 `./zig-out/bin/crucible --help` 查看所有选项。

运行测试：

```sh
zig build test
```

运行示例：

```sh
zig build example
```

## 嵌入式使用

`load` 返回一个可选的保留条目句柄。从句柄读取数据，并在完成时调用 `release`。

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
        _ = val; // 使用值
    }
}
```

`entryIter` 返回一个保留的条目句柄。使用 `Entry.key`/`Entry.value` 读取数据，并在完成时调用 `release`（如需保留更长时间，调用 `retain`）。

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

更完整的示例见 `examples/cache_demo.zig`。

## 服务器层

服务器层使用 libxev 进行异步 I/O，支持 HTTP 和 RESP 协议。
使用内置二进制文件作为可部署服务器，或将服务器嵌入你自己的 Zig 程序以实现自定义连接。
协议自动检测使用首字节：`*`/`$` 表示 RESP，`GET`/`PUT`/`POST`/`DELETE` 表示 HTTP。

示例 CLI 用法：

```sh
./zig-out/bin/crucible --listen 127.0.0.1:6379 --protocol resp --threads 4
```

可选的 Unix 套接字监听器（与 TCP 一起）：

```sh
./zig-out/bin/crucible -s /tmp/crucible.sock
```

Unix 套接字路径在启动时取消链接，关闭时不会删除。

资源控制标志：

```sh
./zig-out/bin/crucible --maxmemory 80% --evict yes --autosweep yes
```

嵌入式服务器示例：

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
    });
    defer server.deinit();

    try server.run();
}
```

### 命令监控（RESP MONITOR）

RESP `MONITOR` 命令将连接切换到监控模式，并流式传输每个接受的命令（不包括 `MONITOR` 请求本身）。

行格式：

```
+<unix_time_seconds>.<micros> [0 <client_addr>] "ARG0" "ARG1" ...
```

注意：

- `client_addr` 对于 TCP 是 `ip:port`，对于 Unix 套接字是 `unix`
- 转义包括 `\n`、`\r`、`\t`、`\"`、`\\`，以及非打印字节为 `\xNN`
- 监控时仅接受 `PING`；任何其他命令都会关闭连接

### 指标

`Server.metricsSnapshot()` 返回连接、请求、字节和错误类型的计数器。
`GET /@stats` 返回 JSON，`INFO`/`STATS` 返回 `key:value` 行。

快照字段：

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

### 操作

HTTP 端点：

- `GET /<key>` 加载键
- `POST /<key>` 存储主体（需要 `Content-Length`）
- `PUT /<key>` 仅在键存在时存储（xx 语义）
- `DELETE /<key>` 删除键
- `GET /@health` 返回 `200 OK`，主体为 `OK`
- `GET /@stats` 返回 JSON 指标快照
- `POST /@save` 写入快照（可选查询 `path` 和 `fast=1`）
- `POST /@load` 加载快照（可选查询 `path` 和 `fast=1`）

RESP 命令：

- `PING` 回复 `+PONG`
- `INFO` 和 `STATS` 返回 `key:value` 行的批量字符串
- `GET <key>` 返回批量字符串或 `$-1`
- `SET <key> <value> [NX|XX] [EX seconds|PX ms]` 设置值
- `DEL <key>` 返回 `:1`（已删除）或 `:0`（未删除）
- `INCR <key>` 和 `DECR <key>` 更新整数计数器
- `EXPIRE <key> <seconds>` 设置 TTL，返回 `:1` 或 `:0`
- `TTL <key>` 返回剩余秒数，`-1` 表示无 TTL，`-2` 表示不存在
- `SAVE [TO <path>] [FAST]` 写入快照
- `LOAD [FROM <path>] [FAST]` 加载快照
  支持 RESP 流水线；命令按顺序处理

### 持久化

- `--persist <path>` 启用启动时加载快照并在 SIGINT/SIGTERM 时保存
- `SAVE`/`LOAD` 使用配置的路径，除非提供了覆盖
- `FAST` 启用并行保存/加载 workers
- `SAVE`/`LOAD` 异步运行；如果保存/加载已在进行中，服务器返回 HTTP 409 或 RESP `-ERR`，请稍后重试
- 快照使用 LZ4 压缩的块和 CRC32；TTL 存储为剩余时间，并在加载时根据挂钟重新计算，仅当启用 CAS 且快照记录了 CAS 时才恢复 CAS

## 路线图

- [X] 后台自动清理和基于 RSS 的最大内存监控，低内存时驱逐
- [X] 带协议自动检测和增量解析的 HTTP/RESP 服务器层
- [X] HTTP（`/@health`、`/@stats`）和 RESP（`INFO`、`STATS`）上的指标端点
- [X] 通过 `MONITOR` 进行 RESP 命令监控流
- [X] 带 `SAVE`/`LOAD` 的快照持久化（包括 `FAST` 模式）
- [ ] 协议兼容性：扩展 RESP 命令覆盖范围以实现更广泛的客户端互操作性
- [ ] 服务端 batch 语义：跨多条命令持有 shard 锁
- [ ] 持久化和恢复：定期快照和增量/基于 WAL 的恢复
- [ ] 安全性：TLS 和身份验证令牌支持
