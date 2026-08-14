pub mod cvss;
pub mod severity;

pub use cvss::{score_from_metrics, CvssVector};
pub use severity::map_class_severity;
