use std::{collections::HashSet, str::FromStr, thread};

use fcp_core::RequestId;

fn request_id_sequence(id: &RequestId) -> u64 {
    id.0.strip_prefix("req_")
        .expect("generated request IDs must use req_ prefix")
        .parse()
        .expect("generated request IDs must end in a decimal sequence")
}

#[test]
fn sequential_generated_request_ids_are_strictly_increasing() {
    let ids = [
        RequestId::random(),
        RequestId::random(),
        RequestId::random(),
        RequestId::random(),
    ];

    for window in ids.windows(2) {
        let previous = request_id_sequence(&window[0]);
        let current = request_id_sequence(&window[1]);
        assert!(
            previous < current,
            "expected {previous} to be strictly less than {current}"
        );
    }
}

#[test]
fn concurrent_generated_request_ids_do_not_duplicate() {
    const THREADS: usize = 8;
    const IDS_PER_THREAD: usize = 64;

    let handles = (0..THREADS)
        .map(|_| {
            thread::spawn(|| {
                (0..IDS_PER_THREAD)
                    .map(|_| RequestId::random())
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();

    let ids = handles
        .into_iter()
        .flat_map(|handle| {
            handle
                .join()
                .expect("request ID worker thread must not panic")
        })
        .collect::<Vec<_>>();

    let unique = ids.iter().map(ToString::to_string).collect::<HashSet<_>>();
    assert_eq!(unique.len(), THREADS * IDS_PER_THREAD);
}

#[test]
fn request_id_format_roundtrips_through_display_and_from_str() {
    let generated = RequestId::random();
    let displayed = generated.to_string();

    let parsed = RequestId::from_str(&displayed).expect("RequestId parsing is infallible");

    assert_eq!(parsed, generated);
    assert_eq!(parsed.to_string(), displayed);
}
