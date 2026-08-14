pub mod crawler;
pub mod endpoints;
pub mod forms;
pub mod javascript;
pub mod normalization;
pub mod parser;

pub use crawler::crawl;
pub use normalization::normalize_path;
