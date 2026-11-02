//! The measuring rig for a publication: what one run's publication costs under
//! the one lock, with every run of a loaded node stamped, for one record moved
//! and for the whole book moved. By hand, in release: `cargo test --release -p
//! rmule-core publish_bench -- --ignored --nocapture`.

use std::net::Ipv4Addr;

use rmule_primitives::{Ipv4Endpoint, PeerEndpoint, UserHash};

use super::*;

const SIZES: [(usize, usize); 3] = [(10, 300), (100, 300), (300, 300)];

fn names(run: usize, record: usize) -> Vec<AskName> {
    let run = u16::try_from(run).unwrap();
    let record = u16::try_from(record).unwrap();
    let [a, b] = run.to_be_bytes();
    let [c, d] = record.to_be_bytes();
    let endpoint = Ipv4Endpoint::new(Ipv4Addr::new(a, b, c, d), 4662);
    let mut hash = [0x5a; 16];
    hash[..4].copy_from_slice(&[a, b, c, d]);
    vec![
        AskName::Endpoint(PeerEndpoint::V4(endpoint)),
        AskName::User(UserHash::from_bytes(hash)),
    ]
}

#[test]
#[ignore = "by hand, in release: prints what one publication costs"]
fn publish_bench() {
    for (runs, records) in SIZES {
        let t0 = Instant::now();
        let standings = QueueStandings::shared();
        let seats: Vec<StandingSeat> = (0..runs)
            .map(|run| {
                StandingSeat::new(
                    Arc::clone(&standings),
                    DownloadId::from_u64(run as u64 + 1),
                    FileHash::from_bytes([u8::try_from(run % 256).unwrap(); 16]),
                )
            })
            .collect();
        let place = |run: usize, record: usize, asked: Instant| PlaceChange {
            id: PlaceId(record as u64),
            place: Some(Place {
                names: names(run, record),
                asked: Some(asked),
                needs_parts: true,
                pooled: false,
                after_ping: false,
            }),
        };
        for (run, seat) in seats.iter().enumerate() {
            seat.publish((0..records).map(|at| place(run, at, t0)).collect());
        }
        let stamps = standings.lock().stamps.len();
        let (mut one, mut whole) = (Duration::MAX, Duration::MAX);
        for round in 0..40_usize {
            let run = round % runs;
            let asked = t0 + Duration::from_millis(round as u64 + 1);
            let moved = vec![place(run, 0, asked)];
            let began = Instant::now();
            seats[run].publish(moved);
            one = one.min(began.elapsed());

            let asked = asked + Duration::from_micros(1);
            let moved = (0..records).map(|at| place(run, at, asked)).collect();
            let began = Instant::now();
            seats[run].publish(moved);
            whole = whole.min(began.elapsed());
        }
        let per_second = |cost: Duration| cost.as_secs_f64() * 1e3 * runs as f64;
        println!(
            "D={runs} R={records} stamps={stamps}: one record moved, publish best {} us, every \
             run once a second {:.2} ms/s; whole book moved, best {} us, {:.1} ms/s",
            one.as_micros(),
            per_second(one),
            whole.as_micros(),
            per_second(whole),
        );
    }
}
