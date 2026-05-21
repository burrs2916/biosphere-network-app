pub trait ProgressReporter: Send + Sync {
    fn report(&self, current: usize, total: usize, message: String);
}

pub struct NoOpProgressReporter;

impl ProgressReporter for NoOpProgressReporter {
    fn report(&self, _current: usize, _total: usize, _message: String) {
        // No-op implementation
    }
}
