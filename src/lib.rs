//! Ramjet — thread-per-core, completion-based networking runtime.
//!
//! The goal: standard wire protocols (TCP, TLS 1.3, WebSocket) over a novel
//! engine, with no moving parts — no locks, no work-stealing, no atomics on the
//! hot path. Today only the kqueue reactor and raw TCP exist; TLS and WebSocket
//! are roadmap, not shipped.
//!
//! Sockets are ramjet's own from birth ([`net`]): std binds and listens in one
//! call, leaving nowhere to set `SO_REUSEPORT` before `bind(2)`.

pub mod net;
pub mod reactor;
