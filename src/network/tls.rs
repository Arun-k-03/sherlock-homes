//! rustls is selected via reqwest features; this module documents TLS posture.

pub fn stack_name() -> &'static str {
    "rustls"
}
