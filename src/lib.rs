pub mod anchors;
pub mod client;
pub mod config;
pub mod daemon;
pub mod exec;
pub mod layers;
pub mod policy;
pub mod process_tree;
pub mod protocol;
pub mod proxy;
pub mod redact;
pub mod refresh;
pub mod run;
pub mod runtime_dir;
pub mod sandbox;
pub mod secrets;
pub mod service;
pub mod trust;

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    /// Crate-wide serialization point for tests that mutate or rely on the
    /// process environment. `cargo test` runs tests in parallel and every
    /// thread shares the env; without this, one test's `set_var`/`remove_var`
    /// can race with another test reading the same variable.
    pub static ENV_MUTEX: Mutex<()> = Mutex::new(());
}
