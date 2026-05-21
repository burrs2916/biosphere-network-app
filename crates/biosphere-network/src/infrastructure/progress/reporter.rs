use crate::core::ProgressReporter;

pub struct ConsoleProgressReporter;

impl ProgressReporter for ConsoleProgressReporter {
    fn report(&self, current: usize, total: usize, message: String) {
        let percent = if total > 0 {
            (current * 100) / total
        } else {
            0
        };
        println!("[{}/{}] {}% - {}", current, total, percent, message);
    }
}
