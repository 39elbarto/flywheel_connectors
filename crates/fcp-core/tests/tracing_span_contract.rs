use std::{
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use fcp_core::{
    canonical_operation_span, CapabilityId, InstanceId, PrincipalId, RequestId, ZoneId,
    CANONICAL_OPERATION_SPAN_ATTRIBUTE_NAMES, CANONICAL_OPERATION_SPAN_NAME,
};
use tracing::{
    field::{Field, Visit},
    span::{Attributes, Record},
    Event, Id, Level, Metadata, Subscriber,
};

const DOCUMENTED_STABLE_CONTRACT: [&str; 5] = [
    "zone_id",
    "capability_id",
    "principal_id",
    "instance_id",
    "request_id",
];

#[derive(Default)]
struct CapturingSubscriber {
    next_id: AtomicU64,
    spans: Mutex<Vec<CapturedSpan>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CapturedSpan {
    name: &'static str,
    fields: Vec<String>,
}

impl Subscriber for CapturingSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= &Level::INFO
    }

    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        let mut visitor = FieldNameVisitor::default();
        attrs.record(&mut visitor);

        self.spans
            .lock()
            .expect("span capture mutex poisoned")
            .push(CapturedSpan {
                name: attrs.metadata().name(),
                fields: visitor.fields,
            });

        Id::from_u64(self.next_id.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _span: &Id, values: &Record<'_>) {
        let mut visitor = FieldNameVisitor::default();
        values.record(&mut visitor);
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[derive(Default)]
struct FieldNameVisitor {
    fields: Vec<String>,
}

impl FieldNameVisitor {
    fn push(&mut self, field: &Field) {
        self.fields.push(field.name().to_owned());
    }
}

impl Visit for FieldNameVisitor {
    fn record_debug(&mut self, field: &Field, _value: &dyn fmt::Debug) {
        self.push(field);
    }

    fn record_i64(&mut self, field: &Field, _value: i64) {
        self.push(field);
    }

    fn record_u64(&mut self, field: &Field, _value: u64) {
        self.push(field);
    }

    fn record_bool(&mut self, field: &Field, _value: bool) {
        self.push(field);
    }

    fn record_str(&mut self, field: &Field, _value: &str) {
        self.push(field);
    }
}

#[test]
fn canonical_operation_span_attribute_names_match_documented_stable_contract() {
    assert_eq!(
        CANONICAL_OPERATION_SPAN_ATTRIBUTE_NAMES,
        DOCUMENTED_STABLE_CONTRACT
    );

    let subscriber = CapturingSubscriber::default();
    let dispatch = tracing::Dispatch::new(subscriber);
    let spans = tracing::dispatcher::with_default(&dispatch, || {
        let zone_id = ZoneId::work();
        let capability_id = CapabilityId::from_static("fcp.example.read");
        let principal_id = PrincipalId::new("user:alice").expect("principal id is canonical");
        let instance_id: InstanceId = "inst_example".parse().expect("instance id is canonical");
        let request_id = RequestId::new("req_trace_contract");

        let span = canonical_operation_span(
            &zone_id,
            &capability_id,
            &principal_id,
            &instance_id,
            &request_id,
        );
        drop(span);

        dispatch
            .downcast_ref::<CapturingSubscriber>()
            .expect("installed subscriber is the capturing subscriber")
            .spans
            .lock()
            .expect("span capture mutex poisoned")
            .clone()
    });

    assert_eq!(
        spans,
        vec![CapturedSpan {
            name: CANONICAL_OPERATION_SPAN_NAME,
            fields: DOCUMENTED_STABLE_CONTRACT
                .iter()
                .map(ToString::to_string)
                .collect(),
        }]
    );
}
