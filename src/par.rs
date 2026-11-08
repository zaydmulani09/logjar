//! Minimal ordered parallel map over scoped threads.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Worker count used when the caller doesn't say: all cores, capped at 8
/// because each in-flight segment holds tens of MiB.
pub fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(8)
}

/// Runs `f` over `items` on up to `threads` threads and returns the results
/// in input order.
pub fn map<I: Sync, T: Send>(items: &[I], threads: usize, f: impl Fn(&I) -> T + Sync) -> Vec<T> {
    if threads <= 1 || items.len() <= 1 {
        return items.iter().map(f).collect();
    }
    let slots: Vec<Mutex<Option<T>>> = items.iter().map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..threads.min(items.len()) {
            s.spawn(|| loop {
                let k = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(k) else { break };
                let r = f(item);
                *slots[k].lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
            });
        }
    });
    slots
        .into_iter()
        .map(|m| {
            m.into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .expect("every slot filled")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn keeps_order() {
        let v: Vec<u64> = (0..1000).collect();
        assert_eq!(
            super::map(&v, 7, |x| x * 2),
            v.iter().map(|x| x * 2).collect::<Vec<_>>()
        );
    }
}
