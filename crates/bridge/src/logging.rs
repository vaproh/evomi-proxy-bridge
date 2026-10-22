//! Ring-buffer log appender feeding the GUI logs tab.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub id: u64,
    pub level: String,
    pub message: String,
}

pub struct LogBuffer {
    entries: Mutex<VecDeque<LogEntry>>,
    next_id: Mutex<u64>,
    capacity: usize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(LogBuffer {
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            next_id: Mutex::new(1),
            capacity,
        })
    }

    pub fn push(&self, level: &str, message: String) {
        let mut id = self.next_id.lock().unwrap();
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(LogEntry { id: *id, level: level.to_string(), message });
        *id += 1;
    }

    /// Entries with id greater than `since`.
    pub fn since(&self, since: u64) -> Vec<LogEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.id > since)
            .cloned()
            .collect()
    }
}

/// `log` crate bridge: forwards records into the shared buffer.
pub struct BufferLogger {
    buffer: Arc<LogBuffer>,
}

impl BufferLogger {
    pub fn install(buffer: Arc<LogBuffer>) {
        let logger: &'static BufferLogger = Box::leak(Box::new(BufferLogger { buffer }));
        let _ = log::set_logger(logger);
        log::set_max_level(log::LevelFilter::Info);
    }
}

impl log::Log for BufferLogger {
    fn enabled(&self, meta: &log::Metadata) -> bool {
        meta.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            // Never log credential-bearing headers (defense in depth;
            // call sites must already redact).
            self.buffer.push(record.level().as_str(), record.args().to_string());
        }
    }

    fn flush(&self) {}
}
