use fcp_core::{CrdtActorId, GCounter, OrSet, OrSetTag, PnCounter};

fn actor(name: &str) -> CrdtActorId {
    CrdtActorId::new(name)
}

fn tag(actor_name: &str, nonce: u64) -> OrSetTag {
    OrSetTag::new(actor(actor_name), nonce)
}

fn counter_sequence(counter: &GCounter) -> Vec<(String, u64)> {
    counter
        .counts
        .iter()
        .map(|(actor, value)| (actor.to_string(), *value))
        .collect()
}

fn build_counter(order: &[(&str, u64)]) -> GCounter {
    let mut counter = GCounter::default();
    for (actor_name, value) in order {
        counter.increment(actor(actor_name), *value);
    }
    counter
}

fn build_orset(order: &[(&str, OrSetTag)]) -> OrSet<String> {
    let mut set = OrSet::default();
    for (value, tag) in order {
        set.add((*value).to_owned(), tag.clone());
    }
    set
}

#[test]
fn orset_values_iterate_deterministically_across_calls_and_insert_orders() {
    let canonical_order = vec![
        ("zeta", tag("node-c", 3)),
        ("alpha", tag("node-a", 1)),
        ("mu", tag("node-b", 2)),
    ];
    let reordered = vec![
        ("mu", tag("node-b", 2)),
        ("zeta", tag("node-c", 3)),
        ("alpha", tag("node-a", 1)),
    ];

    let set = build_orset(&canonical_order);
    let first = set.values();
    let second = set.values();

    assert_eq!(first, vec!["alpha", "mu", "zeta"]);
    assert_eq!(first, second, "same OR-Set input must iterate stably");

    let set_from_reordered_insertions = build_orset(&reordered);
    assert_eq!(
        first,
        set_from_reordered_insertions.values(),
        "OR-Set iteration must be independent of insertion order"
    );
}

#[test]
fn gcounter_counts_iterate_deterministically_across_calls_and_insert_orders() {
    let canonical_order = [("node-c", 30), ("node-a", 10), ("node-b", 20)];
    let reordered = [("node-b", 20), ("node-c", 30), ("node-a", 10)];

    let counter = build_counter(&canonical_order);
    let first = counter_sequence(&counter);
    let second = counter_sequence(&counter);

    assert_eq!(
        first,
        vec![
            ("node-a".to_string(), 10),
            ("node-b".to_string(), 20),
            ("node-c".to_string(), 30),
        ]
    );
    assert_eq!(
        first, second,
        "same GCounter input must expose a stable actor sequence"
    );

    let counter_from_reordered_insertions = build_counter(&reordered);
    assert_eq!(
        first,
        counter_sequence(&counter_from_reordered_insertions),
        "GCounter actor iteration must be independent of insertion order"
    );
}

#[test]
fn pncounter_component_counts_iterate_deterministically_across_insert_orders() {
    let mut counter = PnCounter::default();
    counter.increment(actor("node-c"), 30);
    counter.decrement(actor("node-b"), 2);
    counter.increment(actor("node-a"), 10);
    counter.decrement(actor("node-a"), 1);

    let first_positive = counter_sequence(&counter.positive);
    let second_positive = counter_sequence(&counter.positive);
    let first_negative = counter_sequence(&counter.negative);
    let second_negative = counter_sequence(&counter.negative);

    assert_eq!(first_positive, second_positive);
    assert_eq!(first_negative, second_negative);
    assert_eq!(
        first_positive,
        vec![("node-a".to_string(), 10), ("node-c".to_string(), 30)]
    );
    assert_eq!(
        first_negative,
        vec![("node-a".to_string(), 1), ("node-b".to_string(), 2)]
    );

    let mut reordered = PnCounter::default();
    reordered.decrement(actor("node-a"), 1);
    reordered.increment(actor("node-a"), 10);
    reordered.increment(actor("node-c"), 30);
    reordered.decrement(actor("node-b"), 2);

    assert_eq!(first_positive, counter_sequence(&reordered.positive));
    assert_eq!(first_negative, counter_sequence(&reordered.negative));
}
