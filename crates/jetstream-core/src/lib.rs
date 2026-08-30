//! Jetstream — the transfer engine.
//!
//! A replacement for Dukto built around one idea: **resume is a property of the
//! wire format, not a feature bolted onto it.** Every file is content-addressed
//! in fixed chunks and described by a manifest sent up front, and the
//! *receiver* drives the transfer by asking for the chunks it does not have.
//!
//! Resume, integrity verification, duplicate-file skipping, and crash recovery
//! all fall out of that single decision. The sender keeps no per-transfer
//! state, so reconnecting after a dropped Wi-Fi link is not a special case — it
//! is the receiver recomputing what it still needs and asking again.
//!
//! This crate is deliberately free of UI dependencies. It is driven by the
//! `jet` CLI and by the Tauri desktop app alike.

pub mod chunk;
pub mod error;
pub mod identity;
pub mod manifest;
pub mod path;
pub mod proto;
pub mod staging;
pub mod throttle;
pub mod tls;
pub mod transfer;
pub mod trust;
pub mod transport;

pub use error::{Error, Result};
pub use identity::{DeviceId, Identity};

/// Default port. Dukto's 4644, offset so the two can coexist on one machine
/// while somebody migrates.
pub const DEFAULT_PORT: u16 = 4646;

/// A sensible display name for this device, taken from the machine name.
///
/// Peer-visible, so it goes through the same sanitizer as a name arriving off
/// the wire — a machine name can legitimately contain surprising characters.
pub fn default_device_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default();

    proto::sanitize_name(&raw)
}
