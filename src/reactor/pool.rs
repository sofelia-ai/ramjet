//! The read-buffer free list behind `Op::ReadPooled`, shared by every backend.

/// Size of a pooled read buffer, and the size a `Vec` should be to be worth
/// recycling.
///
/// 64 KiB, and the mechanism is **frames per read, not bytes per frame**. That
/// distinction cost two wrong guesses, so it is worth stating plainly.
///
/// The obvious story is a threshold: a client's WebSocket frame carries a masked
/// header, so a 4 KiB payload is 4,104 bytes on the wire and misses a 4,096-byte
/// buffer *by the header*, and eight pipelined 512-byte messages are 4,160 bytes
/// and overflow the same way. True, and nearly worthless on its own — clearing
/// exactly those thresholds with 8 KiB bought **+2.8%** in the container and
/// +11.5% on EC2, because an 8 KiB buffer still holds only *one* 4 KiB frame plus
/// a fragment of the next, so every batch is still split and reassembled.
///
/// What pays is holding a whole pipelined batch. At 64 KiB a read takes about
/// fifteen 4 KiB frames, so the zero-copy path applies to all of them and their
/// replies cork into a single write. Measured against 8 KiB, 200 connections at
/// pipeline depth 8: **+146% at 4 KiB payloads** and **+24% at 64 B**, with p99
/// better at both (6.1 ms against 15.7 ms, 3.1 ms against 8.0 ms). Ranges did not
/// overlap.
///
/// Cost is flat, not per connection: the kernel picks a buffer only when bytes
/// arrive (see [`super::uring`]), so a parked pooled read owns nothing and an
/// idle connection is unaffected by this number — 393 B/conn here, against
/// 4,325 B when the multishot path is forced off. 64 KiB across the ring's 32
/// entries is 2 MiB, exactly what 8 KiB across 256 entries cost, and only 131 KB
/// of that is ever resident on an idle server because registering a
/// provided-buffer ring hands the kernel a descriptor array rather than pinned
/// pages. The count came down as the size went up because the count was never
/// load-bearing; see `RING_BUFS`.
///
/// ponytail: one size class, and — corrected — that is the *answer* rather than a
/// deferral. Per-fd size classes with promotion were specced and then abandoned
/// on measurement: a small ring of large buffers takes the whole win for no
/// memory, so classes would have been ~300 lines and four new failure modes
/// buying nothing. Two notes for whoever revisits this. Mixed sizes in *one*
/// buffer group is not the upgrade: the kernel takes buffers at the ring head in
/// order, so it would hand out a random size per read and look correct until a
/// large frame drew a small buffer. And incremental buffer consumption
/// (`IOU_PBUF_RING_INC`) probes available on kernel 7.0 and EINVAL on 6.10.14 —
/// it would let the kernel consume one large buffer partially, but `ReadPooled`
/// hands the caller an owned `Vec` trimmed to `n`, which is what makes the
/// in-place echo possible, and a partially-consumed kernel buffer cannot be taken
/// out from under the kernel. That is a public contract change, not a drop-in.
pub const POOL_BUF_SIZE: usize = 65536;

/// How many buffers the free list will hold. Past this, `recycle` drops the
/// buffer and lets the allocator have it back.
///
/// Scaled down as the size went up, so the ceiling stays a ceiling: at 64 KiB a
/// 256-deep list could pin 16 MiB to save allocations for a ring that only
/// publishes 32 buffers. The list absorbs churn between a caller recycling a
/// buffer and the ring republishing it, and twice the ring's depth is ample.
/// ponytail: a flat ceiling, not a policy.
pub(crate) const POOL_CAP: usize = 64;

/// Borrow a buffer for a pooled read, allocating only when the free list is dry.
///
/// It comes back **empty**, not full-length, and nothing zeroes it. The caller
/// reads into the spare capacity and then claims exactly the bytes the kernel
/// filled, so no byte is ever read before it is written — which is what keeps a
/// 4 KiB memset off the hot path.
///
/// Restoring the length by zero-filling would put that memset back; doing it
/// with `set_len` instead would only be sound if every recycled buffer were
/// known to have had all its bytes written at some point, and `recycle` is a
/// safe function that cannot check that. Reading into the spare capacity needs
/// no such assumption about the caller.
pub(crate) fn take(pool: &mut Vec<Vec<u8>>) -> Vec<u8> {
    match pool.pop() {
        Some(mut buf) => {
            buf.clear();
            buf
        }
        // Uninitialised capacity: the read fills what it needs.
        None => Vec::with_capacity(POOL_BUF_SIZE),
    }
}

/// Return a buffer to the free list, or drop it.
///
/// Only the capacity matters — the length is irrelevant, because a pooled buffer
/// is emptied on the way out and refilled by the read itself.
///
/// Admission is by *capacity*, bounded on both sides. Too small cannot serve a
/// read without reallocating. Too large is worse than useless: recycling a
/// 1 MiB `Vec` would let the pool pin 256 MiB of memory to save 4 KiB of
/// allocation, so an oversized buffer goes back to the allocator instead.
pub(crate) fn put(pool: &mut Vec<Vec<u8>>, buf: Vec<u8>) {
    let fits = (POOL_BUF_SIZE..=POOL_BUF_SIZE * 2).contains(&buf.capacity());
    if fits && pool.len() < POOL_CAP {
        pool.push(buf);
    }
}
