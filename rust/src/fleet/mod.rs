//! Reader identity, grants and queries inside a grant. A reader is a separate principal from an
//! enrolled device: its credential and store never overlap with ingest.
pub mod auth;
pub mod coverage;
pub mod cursor;
pub mod finding;
pub mod history;
pub mod http;
pub mod query;
pub mod untrusted;
