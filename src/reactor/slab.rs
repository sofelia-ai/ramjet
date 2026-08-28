//! Generation-tagged slab of in-flight operations, shared by every backend.
//!
//! An [`OpId`] is `(generation << 32) | slot`, so finding an op is an array
//! index and a compare rather than a hash. The generation is what makes that
//! safe: a stale id — one whose op finished long ago — lands on a cell that has
//! since been reused, and the mismatched generation rejects it instead of
//! returning the wrong op. Both backends need exactly that, because both get
//! handed completion tokens by the kernel and must treat a late or duplicated
//! one as garbage: a fired kevent on kqueue, a CQE on io_uring.

use super::OpId;

/// Low half of an `OpId` is the slot, high half the generation.
const SLOT_BITS: u32 = 32;
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;

pub(crate) fn make_id(generation: u32, slot: usize) -> OpId {
    (u64::from(generation) << SLOT_BITS) | slot as u64
}

pub(crate) fn id_slot(id: OpId) -> usize {
    (id & SLOT_MASK) as usize
}

pub(crate) fn id_generation(id: OpId) -> u32 {
    (id >> SLOT_BITS) as u32
}

/// One slab cell.
struct Entry<T> {
    /// Bumped every time the cell is freed, so an id minted before the free can
    /// never be mistaken for one minted after it.
    generation: u32,
    /// The caller's `user_data`, carried from submission to completion.
    user: u64,
    /// The op itself, or `None` for a cell reserved only to mint an id.
    op: Option<T>,
    /// Next free cell while this one is free; `usize::MAX` ends the chain.
    next_free: usize,
}

/// In-flight ops, addressed by the id itself.
pub(crate) struct Slab<T> {
    cells: Vec<Entry<T>>,
    /// Head of the free chain, or `usize::MAX` when every cell is live.
    free_head: usize,
    /// Live cells, so a driver can tell whether anything can still wake it.
    live: usize,
}

impl<T> Slab<T> {
    pub(crate) fn new() -> Self {
        Slab {
            cells: Vec::new(),
            free_head: usize::MAX,
            live: 0,
        }
    }

    /// Reserve a cell and mint its id. The cell stays reserved — and the id
    /// therefore stays valid — until [`Slab::release`], however many times the
    /// op is taken out and put back in between.
    pub(crate) fn reserve(&mut self, user: u64) -> OpId {
        self.live += 1;
        if self.free_head != usize::MAX {
            let slot = self.free_head;
            self.free_head = self.cells[slot].next_free;
            self.cells[slot].user = user;
            return make_id(self.cells[slot].generation, slot);
        }
        let slot = self.cells.len();
        self.cells.push(Entry {
            generation: 0,
            user,
            op: None,
            next_free: usize::MAX,
        });
        make_id(0, slot)
    }

    /// Look up `id`'s cell, if the id is still the one that cell answers to.
    fn cell_mut(&mut self, id: OpId) -> Option<&mut Entry<T>> {
        let cell = self.cells.get_mut(id_slot(id))?;
        (cell.generation == id_generation(id)).then_some(cell)
    }

    /// The tag this op was submitted with, or 0 once its cell is gone.
    pub(crate) fn user(&self, id: OpId) -> u64 {
        match self.cells.get(id_slot(id)) {
            Some(cell) if cell.generation == id_generation(id) => cell.user,
            _ => 0,
        }
    }

    /// Take the op out to work on it. The cell stays reserved, so the op can be
    /// put back under the same id if it is not finished — which is exactly what
    /// a partial write does, over and over, until it drains.
    pub(crate) fn take_op(&mut self, id: OpId) -> Option<T> {
        self.cell_mut(id)?.op.take()
    }

    /// Put an op back into its still-reserved cell.
    pub(crate) fn put_op(&mut self, id: OpId, op: T) {
        if let Some(cell) = self.cell_mut(id) {
            cell.op = Some(op);
        }
    }

    /// Borrow the op in a cell without taking it.
    #[allow(dead_code, reason = "used by the io_uring backend")]
    pub(crate) fn peek(&self, id: OpId) -> Option<&T> {
        let cell = self.cells.get(id_slot(id))?;
        if cell.generation != id_generation(id) {
            return None;
        }
        cell.op.as_ref()
    }

    /// Release the cell for reuse. The id is dead from here: the generation bump
    /// means a stale copy of it can never match this cell again, and a second
    /// release is a no-op rather than a corrupted free chain.
    pub(crate) fn release(&mut self, id: OpId) {
        let free_head = self.free_head;
        let Some(cell) = self.cell_mut(id) else {
            return;
        };
        cell.op = None;
        cell.generation = cell.generation.wrapping_add(1);
        cell.next_free = free_head;
        self.free_head = id_slot(id);
        self.live -= 1;
    }

    #[allow(dead_code, reason = "used by the kqueue backend")]
    pub(crate) fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Cells currently reserved. A backend that keeps ops of its own here needs
    /// this to tell them apart from the caller's.
    #[allow(dead_code, reason = "used by the io_uring backend")]
    pub(crate) fn live(&self) -> usize {
        self.live
    }

    /// IDs whose cells currently contain an operation.
    ///
    /// The io_uring backend uses a snapshot during shutdown so it can cancel
    /// every kernel-facing request before any buffer owned by those requests
    /// is dropped. Reserved-but-empty cells are deliberately excluded: they
    /// do not name a request the kernel can still access.
    #[allow(dead_code, reason = "used by the io_uring backend")]
    pub(crate) fn occupied_ids(&self) -> Vec<OpId> {
        self.cells
            .iter()
            .enumerate()
            .filter_map(|(slot, cell)| cell.op.as_ref().map(|_| make_id(cell.generation, slot)))
            .collect()
    }
}
