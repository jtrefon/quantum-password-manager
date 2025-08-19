use std::sync::Arc;

/// Progress callback function type
///
/// The callback is wrapped in an `Arc` so it can be shared across threads
/// without needing a `Mutex`. This avoids unnecessary locking overhead
/// while still allowing the callback to be shared safely.
pub type ProgressCallback = Arc<dyn Fn(&str, f32) + Send + Sync>;

/// Progress indicator for encryption operations
pub struct ProgressIndicator {
    callback: Option<ProgressCallback>,
    operation: String,
    total_steps: u32,
    current_step: u32,
}

impl ProgressIndicator {
    pub fn new(operation: &str, total_steps: u32) -> Self {
        Self {
            callback: None,
            operation: operation.to_string(),
            total_steps,
            current_step: 0,
        }
    }

    pub fn with_callback(mut self, callback: ProgressCallback) -> Self {
        self.callback = Some(callback);
        self
    }

    pub fn update(&mut self, step: u32, message: &str) {
        self.current_step = step;
        let progress = if self.total_steps > 0 {
            (step as f32) / (self.total_steps as f32)
        } else {
            0.0
        };

        if let Some(callback) = &self.callback {
            callback(&format!("{}: {}", self.operation, message), progress);
        }
    }

    #[allow(dead_code)]
    pub fn increment(&mut self, message: &str) {
        self.current_step += 1;
        self.update(self.current_step, message);
    }

    pub fn finish(&mut self, message: &str) {
        self.update(self.total_steps, message);
    }
}
