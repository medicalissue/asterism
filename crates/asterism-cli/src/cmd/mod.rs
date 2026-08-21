//! One module per area of the CLI, and the whole point of the arrangement.
//!
//! Every module here owns three things about its area and nothing about
//! anybody else's: the clap enum that spells its commands, the code that
//! turns one of them into a [`Request`], and the code that prints the reply.
//! `main.rs` holds the eight-line list of areas and does not know what any of
//! them contains.
//!
//! [`Request`]: asterism_core::protocol::Request
//!
//! # Why the top-level commands are still top-level
//!
//! The enums are stitched into one command tree with clap's
//! `#[command(flatten)]`, so `ast up dev` is still `ast up dev` — no group
//! became a word the user has to type. That is the trade this split is built
//! on: the grouping is for the people editing the file, and it costs the
//! people typing the command nothing.
//!
//! The areas are the seams a feature lands on. Adding a command means a
//! variant in one of these enums, an arm in that module's `run`, and a
//! variant in [`asterism_core::protocol`] — three edits in two files, none of
//! them in a file another branch is also editing.

pub(crate) mod device;
pub(crate) mod image;
pub(crate) mod instance;
pub(crate) mod parts;
pub(crate) mod service;
pub(crate) mod snapshot;
pub(crate) mod volume;
