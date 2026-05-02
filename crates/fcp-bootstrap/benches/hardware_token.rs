use std::path::PathBuf;

use criterion::{Criterion, criterion_group, criterion_main};
use fcp_bootstrap::hardware_token::{
    DetectedToken, DetectionIssue, DetectionStage, ProviderDetectionResult, TokenDetectionReport,
    rank_detected_tokens,
};

const PROVIDER_COUNTS: [usize; 3] = [1, 10, 100];
const TOKENS_PER_PROVIDER: usize = 8;
const ISSUES_PER_PROVIDER: usize = 2;

fn detected_token(provider_index: usize, slot: usize) -> DetectedToken {
    let compatible = slot % 2 == 0;
    let mechanisms = if compatible {
        vec!["CKM_EDDSA".to_string(), "CKM_ECDH1_DERIVE".to_string()]
    } else {
        vec!["CKM_RSA_PKCS".to_string()]
    };

    DetectedToken {
        provider: PathBuf::from(format!("/usr/lib/pkcs11/provider-{provider_index}.so")),
        slot: u32::try_from(slot).unwrap_or(u32::MAX),
        label: format!("fcp-token-{provider_index}-{slot}"),
        manufacturer: format!("vendor-{provider_index}"),
        serial: format!("serial-{provider_index}-{slot:04}"),
        mechanisms,
    }
}

fn detection_issue(provider_index: usize, issue_index: usize) -> DetectionIssue {
    DetectionIssue {
        provider: PathBuf::from(format!("/usr/lib/pkcs11/provider-{provider_index}.so")),
        stage: DetectionStage::ReadMechanisms,
        slot: Some(u64::try_from(issue_index).unwrap_or(u64::MAX)),
        message: format!("synthetic mechanism warning {issue_index}"),
    }
}

fn detection_report(provider_count: usize) -> TokenDetectionReport {
    let providers = (0..provider_count)
        .map(|provider_index| ProviderDetectionResult {
            provider: PathBuf::from(format!("/usr/lib/pkcs11/provider-{provider_index}.so")),
            tokens: (0..TOKENS_PER_PROVIDER)
                .map(|slot| detected_token(provider_index, slot))
                .collect(),
            issues: (0..ISSUES_PER_PROVIDER)
                .map(|issue_index| detection_issue(provider_index, issue_index))
                .collect(),
        })
        .collect();

    TokenDetectionReport { providers }
}

fn discovery_report_scans(c: &mut Criterion) {
    let mut group = c.benchmark_group("hardware_token_discovery_report");
    for provider_count in PROVIDER_COUNTS {
        let report = detection_report(provider_count);

        group.bench_function(format!("all_tokens_providers_{provider_count}"), |b| {
            b.iter(|| std::hint::black_box(report.all_tokens()));
        });
        group.bench_function(
            format!("fcp_compatible_tokens_providers_{provider_count}"),
            |b| {
                b.iter(|| std::hint::black_box(report.fcp_compatible_tokens()));
            },
        );
        group.bench_function(format!("issues_providers_{provider_count}"), |b| {
            b.iter(|| std::hint::black_box(report.issues()));
        });
    }
    group.finish();
}

fn token_ranking(c: &mut Criterion) {
    let mut group = c.benchmark_group("hardware_token_ranking");
    for provider_count in PROVIDER_COUNTS {
        let report = detection_report(provider_count);
        let tokens = report.all_tokens();

        group.bench_function(format!("rank_tokens_providers_{provider_count}"), |b| {
            b.iter(|| std::hint::black_box(rank_detected_tokens(&tokens)));
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(std::time::Duration::from_millis(100))
        .measurement_time(std::time::Duration::from_millis(500));
    targets = discovery_report_scans, token_ranking
}
criterion_main!(benches);
