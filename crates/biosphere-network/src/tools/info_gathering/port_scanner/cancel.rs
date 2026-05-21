use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;

static SCANNER_CANCELLED: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| {
    Arc::new(AtomicBool::new(false))
});

pub fn request_cancel() {
    SCANNER_CANCELLED.store(true, Ordering::Relaxed);
}

pub fn is_cancelled() -> bool {
    SCANNER_CANCELLED.load(Ordering::Relaxed)
}

pub fn reset_cancel() {
    SCANNER_CANCELLED.store(false, Ordering::Relaxed);
}

pub fn get_cancel_flag() -> Arc<AtomicBool> {
    SCANNER_CANCELLED.clone()
}
