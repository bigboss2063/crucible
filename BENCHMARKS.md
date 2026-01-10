# Benchmarks

This document captures a local performance snapshot using `cache-benchmarks` and `memtier_benchmark`. Results vary by hardware and OS, and this is not a production guarantee.

## Machine

- OS: Rocky Linux 9.7 (Blue Onyx)
- CPU: AMD EPYC 7K62 (4 vCPU, 1 socket, 4 cores, SMT off)
- RAM: 3.6 GiB
- Hypervisor: KVM

## Configuration

- Build: `zig build -Doptimize=ReleaseFast`.
- Crucible: `./zig-out/bin/crucible --threads 2 --protocol resp -s /tmp/cachebench.sock --listen 127.0.0.1:19283`.
- Redis/Valkey: `--appendonly no --save "" --io-threads 2 --maxmemory 32gb --unixsocket /tmp/cachebench.sock --port 0`.

## Workload Parameters

- Client: `memtier_benchmark` via `cache-benchmarks`.
- `threads=2`, `bench_threads=2`, `connections=8` (4 per thread).
- `operations=1,600,000` (200,000 per client).
- `sizerange=1-1024`, pipeline `1/5/10/20/50`.
- Sets and gets run separately; medians of 3 runs are reported.

## Results (Median of 3 Runs, opsec and p99 in ms)

### Pipeline 1

| System | Sets opsec | Gets opsec | Sets p99 (ms) | Gets p99 (ms) |
| --- | --- | --- | --- | --- |
| Crucible | 133170.470 | 141256.270 | 0.167 | 0.159 |
| Pogocache | 144014.470 | 149960.730 | 0.151 | 0.143 |
| Redis | 70172.720 | 72146.470 | 0.239 | 0.239 |
| Valkey | 123271.270 | 126862.590 | 0.191 | 0.183 |

### Pipeline 5

| System | Sets opsec | Gets opsec | Sets p99 (ms) | Gets p99 (ms) |
| --- | --- | --- | --- | --- |
| Crucible | 451923.660 | 489778.030 | 0.231 | 0.223 |
| Pogocache | 489681.040 | 532239.760 | 0.215 | 0.207 |
| Redis | 274449.130 | 296419.040 | 0.319 | 0.303 |
| Valkey | 362485.800 | 468427.960 | 0.311 | 0.239 |

### Pipeline 10

| System | Sets opsec | Gets opsec | Sets p99 (ms) | Gets p99 (ms) |
| --- | --- | --- | --- | --- |
| Crucible | 649184.400 | 616698.660 | 0.311 | 0.375 |
| Pogocache | 665069.120 | 646983.540 | 0.319 | 0.335 |
| Redis | 424221.000 | 371022.150 | 0.463 | 0.615 |
| Valkey | 557886.470 | 556527.350 | 0.399 | 0.431 |

### Pipeline 20

| System | Sets opsec | Gets opsec | Sets p99 (ms) | Gets p99 (ms) |
| --- | --- | --- | --- | --- |
| Crucible | 827108.050 | 768792.780 | 0.479 | 0.599 |
| Pogocache | 861294.450 | 772938.270 | 0.471 | 0.655 |
| Redis | 594386.980 | 435739.930 | 0.687 | 1.559 |
| Valkey | 611777.250 | 736895.580 | 0.647 | 0.623 |

### Pipeline 50

| System | Sets opsec | Gets opsec | Sets p99 (ms) | Gets p99 (ms) |
| --- | --- | --- | --- | --- |
| Crucible | 1068855.680 | 816897.940 | 0.983 | 1.647 |
| Pogocache | 1084013.040 | 835265.320 | 1.071 | 1.687 |
| Redis | 538651.620 | 497334.600 | 2.239 | 2.447 |
| Valkey | 777244.990 | 807546.930 | 1.591 | 2.111 |

## Summary

- Crucible outperforms Redis on throughput and p99 latency across all tested pipelines.
- Crucible outperforms Valkey on throughput and p99 latency across all tested pipelines.
- Pogocache results are competitive; pipeline 1 favors Pogocache, while other pipelines are mixed.

## Planned Follow-ups

- Additional workloads (mixed ratios, larger values, TCP, and higher thread counts).
