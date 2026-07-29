use fcp_core::{ApprovalToken, Approved, Pending};

fn delegate_approved(_: ApprovalToken<Approved>) {}

fn main() {
    let pending = ApprovalToken::<Pending>::new();
    delegate_approved(pending);
}
