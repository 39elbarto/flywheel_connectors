use std::{fs, path::Path};

use br_tools::scheduled_reality_check::{ProposedBead, check_reality_cadence_with_existing};
use chrono::NaiveDate;

const fn date(year: i32, month: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(year, month, day).expect("test date is valid")
}

#[test]
fn six_month_ci_cadence_emits_monthly_artifacts_and_q3_quarterly_once() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let reality_dir = tempdir.path().join("docs/reality");
    let quarterly_dir = tempdir.path().join("docs/quarterly");
    fs::create_dir_all(&reality_dir).expect("create reality dir");
    fs::create_dir_all(&quarterly_dir).expect("create quarterly dir");

    fs::write(
        quarterly_dir.join("2026-Q2-claims-vs-reality.md"),
        "# 2026 Q2 claims vs reality\n",
    )
    .expect("seed prior quarterly artifact");

    let ci_boundaries = [
        date(2026, 4, 1),
        date(2026, 5, 1),
        date(2026, 6, 1),
        date(2026, 7, 1),
        date(2026, 8, 1),
        date(2026, 9, 1),
    ];

    let mut monthly_titles = Vec::new();
    let mut quarterly_titles = Vec::new();

    for today in ci_boundaries {
        let proposals =
            check_reality_cadence_with_existing(today, &reality_dir, &quarterly_dir, &[]);

        for proposal in &proposals {
            persist_artifact_for_proposal(proposal, &reality_dir, &quarterly_dir);
            if proposal.labels.iter().any(|label| label == "quarterly") {
                quarterly_titles.push(proposal.title.clone());
            } else {
                monthly_titles.push(proposal.title.clone());
            }
        }

        let after_persist =
            check_reality_cadence_with_existing(today, &reality_dir, &quarterly_dir, &[]);
        assert!(
            after_persist.is_empty(),
            "persisted artifacts must suppress duplicate cadence proposals for {today}: {after_persist:?}"
        );
    }

    assert_eq!(
        monthly_titles,
        [
            "[reality-check] 2026-04 reality-check pass overdue",
            "[reality-check] 2026-05 reality-check pass overdue",
            "[reality-check] 2026-06 reality-check pass overdue",
            "[reality-check] 2026-07 reality-check pass overdue",
            "[reality-check] 2026-08 reality-check pass overdue",
            "[reality-check] 2026-09 reality-check pass overdue",
        ]
    );
    assert_eq!(
        quarterly_titles,
        ["[reality-check] 2026-Q3 claims-vs-reality pass overdue"]
    );
    assert_eq!(count_md_files(&reality_dir), 6);
    assert!(quarterly_dir.join("2026-Q2-claims-vs-reality.md").is_file());
    assert!(quarterly_dir.join("2026-Q3-claims-vs-reality.md").is_file());
}

fn persist_artifact_for_proposal(
    proposal: &ProposedBead,
    reality_dir: &Path,
    quarterly_dir: &Path,
) {
    if proposal.labels.iter().any(|label| label == "quarterly") {
        let quarter = proposal
            .title
            .split_whitespace()
            .nth(1)
            .expect("quarterly title contains quarter key");
        fs::write(
            quarterly_dir.join(format!("{quarter}-claims-vs-reality.md")),
            format!("# {quarter} claims vs reality\n"),
        )
        .expect("write quarterly artifact");
    } else {
        let month = proposal
            .title
            .split_whitespace()
            .nth(1)
            .expect("monthly title contains month key");
        fs::write(
            reality_dir.join(format!("{month}-reality-check.md")),
            format!("# {month} reality check\n"),
        )
        .expect("write monthly artifact");
    }
}

fn count_md_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .expect("read dir")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("md"))
        .count()
}
