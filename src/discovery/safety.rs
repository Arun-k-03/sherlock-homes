//! Crawl explosion / generated-artifact heuristics.

pub fn is_generated_artifact_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let segs: Vec<&str> = lower.split('/').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        return false;
    }
    if segs.contains(&"node_modules") {
        return true;
    }
    if segs.windows(2).any(|w| w[0] == ".git" && w[1] == "objects") {
        return true;
    }
    if segs.len() >= 2 && segs[0] == ".git" && segs[1] != "head" && segs[1] != "config" {
        return true;
    }
    if segs.windows(2).any(|w| {
        w[0] == "target" && matches!(w[1], "debug" | "release" | "tmp" | "doc" | "incremental")
    }) {
        return true;
    }
    if segs.iter().any(|s| {
        matches!(
            *s,
            ".svn" | ".hg" | "__pycache__" | ".cache" | "cargo-target"
        )
    }) {
        return true;
    }
    hex_object_fanout(&segs)
}

fn hex_object_fanout(segs: &[&str]) -> bool {
    if segs.len() < 3 {
        return false;
    }
    let last = segs[segs.len() - 1];
    let parent = segs[segs.len() - 2];
    parent.len() == 2
        && parent.chars().all(|c| c.is_ascii_hexdigit())
        && last.len() >= 16
        && last.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn parent_dir(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((p, _)) if !p.is_empty() => p.to_string(),
        _ => "/".into(),
    }
}

pub fn looks_like_generated_child(name: &str) -> bool {
    let n = name.trim_start_matches('/');
    (n.len() == 2 && n.chars().all(|c| c.is_ascii_hexdigit()))
        || (n.len() >= 16 && n.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_git_objects_and_build_trees() {
        assert!(is_generated_artifact_path("/.git/objects/ab/abcdef"));
        assert!(is_generated_artifact_path(
            "/app/node_modules/lodash/index.js"
        ));
        assert!(is_generated_artifact_path(
            "/proj/target/debug/sherlock.exe"
        ));
        assert!(is_generated_artifact_path("/proj/target/release/deps/foo"));
        assert!(!is_generated_artifact_path("/target"));
        assert!(!is_generated_artifact_path("/services/target-audience"));
        assert!(!is_generated_artifact_path("/"));
        assert!(!is_generated_artifact_path("/.git/HEAD"));
    }
}
