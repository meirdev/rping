use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

#[derive(Debug, Default)]
pub struct Stats {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    pub errors: AtomicU64,
}

impl Stats {
    pub fn record_sent(&self, bytes: u64) {
        self.packets.fetch_add(1, Ordering::SeqCst);
        self.bytes.fetch_add(bytes, Ordering::SeqCst);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::SeqCst);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            packets: self.packets.load(Ordering::SeqCst),
            bytes: self.bytes.load(Ordering::SeqCst),
            errors: self.errors.load(Ordering::SeqCst),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StatsSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub errors: u64,
}
