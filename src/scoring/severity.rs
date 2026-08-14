use crate::core::types::Severity;

/// Conservative class-to-severity defaults. CVSS is used only when metrics exist.
pub fn map_class_severity(class_id: &str) -> Severity {
    match class_id {
        "reflected_xss" | "open_redirect" => Severity::Medium,
        "missing_hsts" | "cookie_flags" | "missing_csp" | "x_frame_options" => Severity::Low,
        "cors_misconfig" => Severity::Medium,
        "source_map" | "server_banner" | "verbose_error" => Severity::Low,
        "secret_exposure" | "exposed_file" => Severity::High,
        "authz_inconsistency" => Severity::High,
        "info_disclosure" => Severity::Low,
        _ => Severity::Informational,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_high() {
        assert_eq!(map_class_severity("secret_exposure"), Severity::High);
    }
}
