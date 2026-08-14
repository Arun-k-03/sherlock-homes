pub fn for_detector(id: &str) -> String {
    crate::remediation::mapping::text(id).to_string()
}
