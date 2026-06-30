//! `srt-win` — Windows network sandbox helper for sandbox-runtime.
//!
//! This crate is the Rust half of the Windows backend. The library
//! exposes the SID, group, and WFP primitives so they can be unit-
//! tested; the binary (`main.rs`) is a thin CLI over them.
//!
//! Windows-only. Building on other platforms yields an empty crate so
//! `cargo check` from a non-Windows host doesn't error.

#![cfg(windows)]

pub mod sam;
pub mod sid;
pub mod util;
pub mod wfp;

pub mod token;
pub mod job;
pub mod winsta;
pub mod self_protect;
pub mod launch;

pub mod acl;
pub mod path_id;
pub mod fence;
pub mod state_db;

pub mod dpapi;
pub mod user;
pub mod install;

pub mod cert_store;
pub mod logon;
pub mod runner;
