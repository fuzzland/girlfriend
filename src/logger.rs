use tracing::Level;
use tracing_subscriber::FmtSubscriber;

pub fn init() {
    let subscriber_builder = FmtSubscriber::builder().compact().with_target(false).without_time();
    #[cfg(debug_assertions)]
    let subscriber = subscriber_builder.with_max_level(Level::DEBUG).finish();
    #[cfg(not(debug_assertions))]
    let subscriber = subscriber_builder.with_max_level(Level::INFO).finish();

    tracing::subscriber::set_global_default(subscriber).expect("failed to initialize logger");
}
