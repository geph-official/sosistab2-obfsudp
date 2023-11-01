use std::time::Duration;
use std::{collections::BTreeMap, time::Instant};

use once_cell::sync::Lazy;

#[derive(Clone, Copy)]
pub struct Bucket {
    sent: u64,
    acked: u64,
    lost: u64,
    latency_sum: f64,
    latency_squared_sum: f64,
}

#[derive(Default)]
pub struct StatsCalculator {
    dead: bool,
    buckets: BTreeMap<u64, Bucket>,
    sent_packets: BTreeMap<u64, u64>, // To record when each packet was sent
}

const BUCKET_SIZE_MS: u64 = 5000;

static START: Lazy<Instant> = Lazy::new(Instant::now);

fn timestamp_ms() -> u64 {
    Instant::now().duration_since(*START).as_millis() as u64
}

impl StatsCalculator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an acknowledgement, along with a `time_offset` that represents the local delay before the acknowledgement was sent by the remote end.
    pub fn add_ack(&mut self, seqno: u64, time_offset: Duration) {
        if let Some(&send_time) = self.sent_packets.get(&seqno) {
            let bucket_index = send_time / BUCKET_SIZE_MS;
            if let Some(bucket) = self.buckets.get_mut(&bucket_index) {
                bucket.acked += 1;
                let latency =
                    Duration::from_millis(timestamp_ms() - send_time).saturating_sub(time_offset);
                bucket.latency_sum += latency.as_secs_f64();
                bucket.latency_squared_sum += latency.as_secs_f64().powi(2);
            }
        }
    }

    /// Adds a negative acknowledgement of a packet.
    pub fn add_nak(&mut self, seqno: u64) {
        if let Some(&send_time) = self.sent_packets.get(&seqno) {
            let bucket_index = send_time / BUCKET_SIZE_MS;
            if let Some(bucket) = self.buckets.get_mut(&bucket_index) {
                bucket.lost += 1;
            }
        }
    }

    /// Adds a sent packet to the StatsCalculator
    pub fn add_sent(&mut self, seqno: u64) {
        let sent_time = timestamp_ms();
        let bucket_index = sent_time / BUCKET_SIZE_MS;
        let bucket = self.buckets.entry(bucket_index).or_insert(Bucket {
            sent: 0,
            acked: 0,
            lost: 0,
            latency_sum: 0.0,
            latency_squared_sum: 0.0,
        });
        bucket.sent += 1;
        self.sent_packets.insert(seqno, sent_time);

        // If we have too many buckets, remove the oldest one
        if self.buckets.len() > 60 {
            let (_, bucket) = self.buckets.pop_first().unwrap();

            for _ in 0..bucket.sent {
                if let Some((&seqno, _)) = self.sent_packets.iter().next() {
                    self.sent_packets.remove(&seqno);
                }
            }
        }
    }

    /// Sets the death flag
    pub fn set_dead(&mut self, dead: bool) {
        self.dead = dead;
    }

    /// Returns statistics of the pipe, including dead status, loss rate, latency, jitter, and number of samples.
    pub fn get_stats(&self) -> PipeStats {
        let mut total_samples = 0;
        let mut total_loss = 0f64;
        let mut total_latency = 0.0f64;
        let mut total_latency_squared = 0.0f64;

        let mut all_buckets: Vec<Bucket> = self.buckets.values().copied().collect();
        all_buckets.sort_unstable_by_key(|b| b.sent);
        let threshold = if all_buckets.is_empty() {
            0
        } else {
            all_buckets[all_buckets.len() * 9 / 10].sent
        } * 9
            / 10;

        log::debug!("threshold to ignore is {} in one bucket", threshold);

        for bucket in self.buckets.values() {
            log::debug!(
                "bucket acked = {}, lost {}, sent {}",
                bucket.acked,
                bucket.lost,
                bucket.sent
            );
            if bucket.sent >= threshold {
                log::debug!("IGNORED!");
                continue;
            }

            total_samples += bucket.acked;
            total_loss += (bucket.lost as f64) / ((bucket.acked + bucket.lost) as f64).max(1.0);
            total_latency += bucket.latency_sum;
            total_latency_squared += bucket.latency_squared_sum;
        }

        let total_samples = total_samples.max(1);

        let average_loss = total_loss / (self.buckets.len() as f64).max(1.0);
        let average_latency = total_latency / (total_samples as f64);
        let average_latency_squared = total_latency_squared / (total_samples as f64);
        let jitter = Duration::from_secs_f64(
            (average_latency_squared - average_latency.powi(2))
                .max(0.0)
                .sqrt(),
        );

        log::debug!("average_loss = {average_loss}");
        log::debug!("average_latency = {average_latency}");

        PipeStats {
            dead: self.dead,
            loss: average_loss,
            latency: Duration::from_secs_f64(average_latency),
            jitter,
            samples: total_samples as _,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PipeStats {
    pub dead: bool,
    pub loss: f64, // 0 to 1
    pub latency: Duration,
    pub jitter: Duration,
    pub samples: usize,
}
