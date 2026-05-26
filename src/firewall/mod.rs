// Auto firewall management — opens listen ports at startup, closes at shutdown.
// Set `firewall_manage = false` in config or RUNALEXDB_FIREWALL_DRY_RUN=1 to disable.

pub mod backend;
pub use backend::FirewallManager;
