# Benchmarks

This document captures a local performance snapshot using `cache-benchmarks` and `memtier_benchmark`. Results vary by hardware and OS, and this is not a production guarantee. The tables below use Crucible as the baseline for comparison.

## Machine

- OS: Rocky Linux 9.7 (Blue Onyx)
- CPU: AMD EPYC 7K62 (4 vCPU, 1 socket, 4 cores, SMT off)
- RAM: 3.6 GiB
- Hypervisor: KVM

## Configuration

- Build: `zig build -Doptimize=ReleaseFast`.
- Crucible: `./zig-out/bin/crucible --threads N --protocol resp -s /tmp/cachebench.sock --listen 127.0.0.1:19283`.
- Redis/Valkey: `--appendonly no --save "" --io-threads N --maxmemory 32gb --unixsocket /tmp/cachebench.sock --port 0`.
- Client: `memtier_benchmark` via `cache-benchmarks`.
- `operations=1,600,000` (200,000 per client), `sizerange=1-1024`.
- Sets and gets run separately.
- `N` is 2 or 4 in these results.

## Results (Throughput, Crucible Baseline)

All throughput numbers are ops/sec. `vs Crucible (%)` is computed as `(system - Crucible) / Crucible`, rounded to 0.1%. Positive means higher throughput.

### Pipeline 1

#### 2 Threads

| System | Sets | vs Crucible (Sets) | Gets | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 133170 | +0.0% | 141256 | +0.0% |
| Pogocache | 144014 | +8.1% | 149961 | +6.2% |
| Redis | 70173 | -47.3% | 72146 | -48.9% |
| Valkey | 123271 | -7.4% | 126863 | -10.2% |

#### 4 Threads

| System | Sets | vs Crucible (Sets) | Gets | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 115110 | +0.0% | 130954 | +0.0% |
| Pogocache | 115731 | +0.5% | 141088 | +7.7% |
| Redis | 72866 | -36.7% | 70534 | -46.1% |
| Valkey | 53801 | -53.3% | 52597 | -59.8% |

### Pipeline 5

#### 2 Threads

| System | Sets | vs Crucible (Sets) | Gets | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 451924 | +0.0% | 489778 | +0.0% |
| Pogocache | 489681 | +8.4% | 532240 | +8.7% |
| Redis | 274449 | -39.3% | 296419 | -39.5% |
| Valkey | 362486 | -19.8% | 468428 | -4.4% |

#### 4 Threads

| System | Sets | vs Crucible (Sets) | Gets | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 547042 | +0.0% | 461293 | +0.0% |
| Pogocache | 562221 | +2.8% | 496968 | +7.7% |
| Redis | 301802 | -44.8% | 326880 | -29.1% |
| Valkey | 274816 | -49.8% | 298949 | -35.2% |

### Pipeline 10

#### 2 Threads

| System | Sets | vs Crucible (Sets) | Gets | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 649184 | +0.0% | 616699 | +0.0% |
| Pogocache | 665069 | +2.4% | 646984 | +4.9% |
| Redis | 424221 | -34.7% | 371022 | -39.8% |
| Valkey | 557886 | -14.1% | 556527 | -9.8% |

#### 4 Threads

| System | Sets | vs Crucible (Sets) | Gets | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 580798 | +0.0% | 808920 | +0.0% |
| Pogocache | 601102 | +3.5% | 845093 | +4.5% |
| Redis | 354774 | -38.9% | 383218 | -52.6% |
| Valkey | 311354 | -46.4% | 349949 | -56.7% |

### Pipeline 20

#### 2 Threads

| System | Sets | vs Crucible (Sets) | Gets | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 827108 | +0.0% | 768793 | +0.0% |
| Pogocache | 861294 | +4.1% | 772938 | +0.5% |
| Redis | 594387 | -28.1% | 435740 | -43.3% |
| Valkey | 611777 | -26.0% | 736896 | -4.1% |

#### 4 Threads

| System | Sets | vs Crucible (Sets) | Gets | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 933130 | +0.0% | 755803 | +0.0% |
| Pogocache | 949802 | +1.8% | 786168 | +4.0% |
| Redis | 389544 | -58.3% | 435182 | -42.4% |
| Valkey | 358054 | -61.6% | 402918 | -46.7% |

### Pipeline 50

#### 2 Threads

| System | Sets | vs Crucible (Sets) | Gets | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 1068856 | +0.0% | 816898 | +0.0% |
| Pogocache | 1084013 | +1.4% | 835265 | +2.2% |
| Redis | 538652 | -49.6% | 497335 | -39.1% |
| Valkey | 777245 | -27.3% | 807547 | -1.1% |

#### 4 Threads

| System | Sets | vs Crucible (Sets) | Gets | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 1099327 | +0.0% | 1007434 | +0.0% |
| Pogocache | 1106150 | +0.6% | 958189 | -4.9% |
| Redis | 369636 | -66.4% | 401287 | -60.2% |
| Valkey | 405992 | -63.1% | 478806 | -52.5% |

## p99 Latency (ms, Crucible Baseline)

Lower is better. `vs Crucible (%)` uses the same formula as throughput and is rounded to 0.1%. Positive means higher latency.

### Pipeline 1

#### 2 Threads

| System | Sets p99 | vs Crucible (Sets) | Gets p99 | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 0.167 | +0.0% | 0.159 | +0.0% |
| Pogocache | 0.151 | -9.6% | 0.143 | -10.1% |
| Redis | 0.239 | +43.1% | 0.239 | +50.3% |
| Valkey | 0.191 | +14.4% | 0.183 | +15.1% |

#### 4 Threads

| System | Sets p99 | vs Crucible (Sets) | Gets p99 | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 0.199 | +0.0% | 0.191 | +0.0% |
| Pogocache | 0.191 | -4.0% | 0.191 | +0.0% |
| Redis | 0.263 | +32.2% | 0.287 | +50.3% |
| Valkey | 0.863 | +333.7% | 0.807 | +322.5% |

### Pipeline 50

#### 2 Threads

| System | Sets p99 | vs Crucible (Sets) | Gets p99 | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 0.983 | +0.0% | 1.647 | +0.0% |
| Pogocache | 1.071 | +9.0% | 1.687 | +2.4% |
| Redis | 2.239 | +127.8% | 2.447 | +48.6% |
| Valkey | 1.591 | +61.9% | 2.111 | +28.2% |

#### 4 Threads

| System | Sets p99 | vs Crucible (Sets) | Gets p99 | vs Crucible (Gets) |
| --- | --- | --- | --- | --- |
| Crucible | 1.135 | +0.0% | 2.479 | +0.0% |
| Pogocache | 1.655 | +45.8% | 1.863 | -24.8% |
| Redis | 9.087 | +700.6% | 7.295 | +194.3% |
| Valkey | 8.895 | +683.7% | 3.599 | +45.2% |

## Summary

- Crucible leads Redis and Valkey on throughput across all pipelines and thread counts in this snapshot.
- Crucible p99 latency is consistently lower than Redis and Valkey on the sampled pipelines.
- Pogocache is close on throughput, typically +0.5% to +8.7% vs Crucible, with one regression on pipeline 50 gets at 4 threads (-4.9%).
- Pogocache p99 is mixed: lower or equal at pipeline 1, higher on pipeline 50 sets, and split on pipeline 50 gets (higher at 2 threads, lower at 4 threads).

## Planned Follow-ups

- Additional workloads (mixed ratios, larger values, TCP, and higher thread counts).
