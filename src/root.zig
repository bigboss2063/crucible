//! Crucible embedded cache engine.
//!
//! Create a cache with `init`, operate on it with store/load/delete, and
//! destroy it with `deinit`. Use `begin`/`end` for batch locking.

/// Low-level modules (engine, entry, map, etc).
pub const cache = @import("cache/mod.zig");
/// Server layer modules.
pub const server = @import("server/mod.zig");
/// Cache handle.
pub const Cache = cache.api.Cache;
/// Batch handle.
pub const Batch = cache.api.Batch;
/// Entry handle (opaque).
pub const Entry = cache.api.Entry;
/// Store operation result.
pub const StoreResult = cache.api.StoreResult;
/// Delete operation result.
pub const DeleteResult = cache.api.DeleteResult;
/// Iteration result.
pub const IterResult = cache.api.IterResult;
/// Eviction reasons passed to callbacks.
pub const EvictReason = cache.api.EvictReason;
/// Iterator action.
pub const IterAction = cache.api.IterAction;
/// Optional update returned by load callbacks.
pub const Update = cache.api.Update;
/// Yield callback for spinlocks.
pub const YieldFn = cache.api.YieldFn;
/// Eviction callback.
pub const EvictedFn = cache.api.EvictedFn;
/// Notify callback on insert/replace/delete.
pub const NotifyFn = cache.api.NotifyFn;
/// Store callback signature.
pub const StoreEntryFn = cache.api.StoreEntryFn;
/// Load callback signature.
pub const LoadUpdateFn = cache.api.LoadUpdateFn;
/// Delete callback signature.
pub const DeleteEntryFn = cache.api.DeleteEntryFn;
/// Iter callback signature.
pub const IterEntryFn = cache.api.IterEntryFn;
/// Cache creation options.
pub const Options = cache.api.Options;
/// Store options.
pub const StoreOptions = cache.api.StoreOptions;
/// Load options.
pub const LoadOptions = cache.api.LoadOptions;
/// Delete options.
pub const DeleteOptions = cache.api.DeleteOptions;
/// Iter options.
pub const IterOptions = cache.api.IterOptions;
/// Count options.
pub const CountOptions = cache.api.CountOptions;
/// Total options.
pub const TotalOptions = cache.api.TotalOptions;
/// Size options.
pub const SizeOptions = cache.api.SizeOptions;
/// Sweep options.
pub const SweepOptions = cache.api.SweepOptions;
/// Clear options.
pub const ClearOptions = cache.api.ClearOptions;
/// Sweep polling options.
pub const SweepPollOptions = cache.api.SweepPollOptions;

/// Create a cache instance.
pub const init = cache.engine.init;
/// Destroy a cache instance and release memory.
pub const deinit = cache.engine.deinit;
/// Begin a batch for batch-aware operations.
pub const begin = cache.engine.begin;
/// End a batch.
pub const end = cache.engine.end;
/// Store a key/value pair.
pub const store = cache.engine.store;
/// Store a key/value pair inside a batch.
pub const storeBatch = cache.engine.storeBatch;
/// Load a key.
pub const load = cache.engine.load;
/// Load a key inside a batch.
pub const loadBatch = cache.engine.loadBatch;
/// Delete a key.
pub const delete = cache.engine.delete;
/// Delete a key inside a batch.
pub const deleteBatch = cache.engine.deleteBatch;
/// Iterate entries via callbacks.
pub const iter = cache.engine.iter;
/// Iterate entries via callbacks inside a batch.
pub const iterBatch = cache.engine.iterBatch;
/// Entry iterator for manual iteration.
pub const entryIter = cache.engine.entryIter;
/// Sweep expired entries.
pub const sweep = cache.engine.sweep;
/// Sweep expired entries inside a batch.
pub const sweepBatch = cache.engine.sweepBatch;
/// Sample sweep rate.
pub const sweepPoll = cache.engine.sweepPoll;
/// Sample sweep rate inside a batch.
pub const sweepPollBatch = cache.engine.sweepPollBatch;
/// Clear all entries.
pub const clear = cache.engine.clear;
/// Clear all entries inside a batch.
pub const clearBatch = cache.engine.clearBatch;
/// Count entries.
pub const count = cache.engine.count;
/// Total inserts.
pub const total = cache.engine.total;
/// Memory size accounting.
pub const size = cache.engine.size;
/// Configured shard count.
pub const nshards = cache.engine.nshards;
/// Monotonic time source used by the engine.
pub const now = cache.engine.now;
