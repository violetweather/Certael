//! Security-critical, engine-neutral Certael client primitives.
//!
//! This crate deliberately does not decide whether gameplay is legitimate.
//! It creates replay-resistant envelopes for requests that remain untrusted
//! until an authoritative game server validates them.

mod action;
mod error;
mod session;
mod verify;

pub use action::{ActionEnvelope, ActionSequencer};
pub use error::{CertaelError, Result};
pub use session::{EphemeralIdentity, SessionBinding, SessionState};
pub use verify::{verify_action, VerifiedAction, VerifiedSession};
