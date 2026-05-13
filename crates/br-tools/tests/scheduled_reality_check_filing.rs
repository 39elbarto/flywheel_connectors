use std::fs;

use br_tools::scheduled_reality_check::{
    ExistingBead, check_monthly_cadence, check_monthly_cadence_with_existing,
};
use chrono::NaiveDate;
use tempfile::tempdir;

const fn date(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("test date is valid")
}

#[test]
fn test_files_bead_when_month_missing() {
    let tmp = tempdir().expect("tempdir");
    let proposed = check_monthly_cadence(date(2026, 6, 1), tmp.path());

    assert_eq!(proposed.len(), 1);
    assert_eq!(
        proposed[0].title,
        "[reality-check] 2026-06 reality-check pass overdue"
    );
    assert_eq!(proposed[0].priority, 2);
}

#[test]
fn test_no_bead_when_month_present() {
    let tmp = tempdir().expect("tempdir");
    fs::write(
        tmp.path().join("2026-06-15-reality-check.md"),
        "# June reality check\n",
    )
    .expect("write fixture");

    let proposed = check_monthly_cadence(date(2026, 6, 1), tmp.path());

    assert!(proposed.is_empty());
}

#[test]
fn test_idempotency_skips_when_open_bead_exists() {
    let tmp = tempdir().expect("tempdir");
    let title = "[reality-check] 2026-06 reality-check pass overdue";
    let existing = [ExistingBead::open(title)];

    let proposed = check_monthly_cadence_with_existing(date(2026, 6, 1), tmp.path(), &existing);

    assert!(proposed.is_empty());
}

#[test]
fn test_reissue_after_close() {
    let tmp = tempdir().expect("tempdir");
    let title = "[reality-check] 2026-06 reality-check pass overdue";
    let existing = [ExistingBead::closed(title, true)];

    let proposed = check_monthly_cadence_with_existing(date(2026, 6, 1), tmp.path(), &existing);

    assert_eq!(proposed.len(), 1);
    assert_eq!(proposed[0].title, title);
}

#[test]
fn test_double_run_same_day_no_duplicates() {
    let tmp = tempdir().expect("tempdir");
    let first = check_monthly_cadence(date(2026, 6, 1), tmp.path());
    assert_eq!(first.len(), 1);

    let existing = [ExistingBead::open(first[0].title.clone())];
    let second = check_monthly_cadence_with_existing(date(2026, 6, 1), tmp.path(), &existing);

    assert!(second.is_empty());
}
