pub fn text(detector_id: &str) -> &'static str {
    match detector_id {
        "missing_csp" => {
            "Set a Content-Security-Policy that defaults to restrictive sources (default-src 'self') and avoid unsafe-inline where possible."
        }
        "missing_hsts" => {
            "Serve Strict-Transport-Security with a long max-age on HTTPS responses, including subdomains if applicable."
        }
        "missing_xcto" => "Send X-Content-Type-Options: nosniff on all responses.",
        "x_frame_options" => {
            "Set X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors to prevent clickjacking."
        }
        "missing_referrer_policy" => {
            "Send Referrer-Policy: no-referrer or strict-origin-when-cross-origin."
        }
        "cookie_flags" => {
            "Mark session cookies HttpOnly; Secure on HTTPS; SameSite=Lax or Strict as appropriate."
        }
        "cors_misconfig" => {
            "Reflect only explicitly allowed origins. Never combine Access-Control-Allow-Origin: * with credentials."
        }
        "open_redirect" => {
            "Avoid reflecting user-supplied URLs in Location. Use an allow-list of relative paths or internal identifiers."
        }
        "reflected_xss" => {
            "Context-encode untrusted input before embedding in HTML. Prefer templating auto-escape and a strong CSP."
        }
        "authz_inconsistency" => {
            "Enforce object-level authorization on every request. Do not rely on unguessable IDs alone."
        }
        "secret_exposure" => {
            "Rotate the exposed credential immediately. Remove secrets from client-side bundles and responses."
        }
        "exposed_file" => {
            "Block public access to VCS, environment, and backup files at the web server and origin."
        }
        "verbose_error" => "Disable debug mode in production. Return generic error pages.",
        "source_map" => "Do not publish source maps to production origins.",
        "server_banner" => "Remove or genericize Server / X-Powered-By headers.",
        "info_disclosure" => "Minimize technical detail in public responses.",
        _ => "Review the affected endpoint, apply least privilege, and re-test after the change.",
    }
}
