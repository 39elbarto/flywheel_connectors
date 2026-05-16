//! Mutation testing harness for connector response parsers.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::MutationKind;

/// Deterministic mutation runner for recorded connector responses.
#[derive(Debug, Clone)]
pub struct MutationHarness {
    seed: u64,
    max_mutations: usize,
}

impl Default for MutationHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl MutationHarness {
    /// Create a harness with seed `0` and `1000` maximum attempted mutations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seed: 0,
            max_mutations: 1000,
        }
    }

    /// Set the deterministic mutation seed.
    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Set the maximum number of mutation attempts.
    #[must_use]
    pub const fn with_max_mutations(mut self, n: usize) -> Self {
        self.max_mutations = n;
        self
    }

    /// Apply mutations and classify each parser result.
    ///
    /// By default every `Ok(_)` result is classified as [`ResultClass::SilentAccept`].
    /// Connector pilots that can prove a mutation hit semantically irrelevant
    /// padding or whitespace should use [`Self::run_with_classifier`].
    #[must_use]
    pub fn run<T, E, F>(&self, response: &[u8], parse_fn: F) -> MutationReport
    where
        F: Fn(&[u8]) -> Result<T, E>,
    {
        self.run_with_classifier(response, parse_fn, |_| ResultClass::SilentAccept)
    }

    /// Apply mutations with connector-specific classification for successful parses.
    #[must_use]
    pub fn run_with_classifier<T, E, F, C>(
        &self,
        response: &[u8],
        parse_fn: F,
        classify_ok: C,
    ) -> MutationReport
    where
        F: Fn(&[u8]) -> Result<T, E>,
        C: Fn(&T) -> ResultClass,
    {
        let mut report = MutationReport::default();

        for mutation_index in 0..self.max_mutations {
            let kind = MutationKind::for_index(self.seed, mutation_index);
            let Some(mutant) = kind.apply(response, self.seed, mutation_index) else {
                continue;
            };

            report.total_attempts = report.total_attempts.saturating_add(1);
            let kind_report = report.by_kind.entry(kind).or_default();
            kind_report.attempts = kind_report.attempts.saturating_add(1);

            let result = catch_unwind(AssertUnwindSafe(|| parse_fn(&mutant.bytes)));
            match result {
                Ok(Ok(value)) => match classify_ok(&value) {
                    ResultClass::Rejected => {
                        kind_report.rejected = kind_report.rejected.saturating_add(1);
                    }
                    ResultClass::GracefulPartialAccept => {
                        kind_report.graceful_partial_accept =
                            kind_report.graceful_partial_accept.saturating_add(1);
                    }
                    ResultClass::GracefulFieldError => {
                        kind_report.graceful_field_error =
                            kind_report.graceful_field_error.saturating_add(1);
                    }
                    ResultClass::SilentAccept => {
                        kind_report.silent_accept = kind_report.silent_accept.saturating_add(1);
                        report.record_silent_accept(kind, mutant.index);
                    }
                },
                Ok(Err(_)) => {
                    kind_report.rejected = kind_report.rejected.saturating_add(1);
                }
                Err(_) => {
                    kind_report.panics = kind_report.panics.saturating_add(1);
                    report.never_panics = false;
                    report.overall_verdict = OverallVerdict::PanicDetected;
                }
            }
        }

        report.finalize();
        report
    }
}

/// Connector-specific result class for a mutated response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultClass {
    Rejected,
    GracefulPartialAccept,
    GracefulFieldError,
    SilentAccept,
}

/// Aggregate mutation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationReport {
    pub total_attempts: usize,
    pub by_kind: BTreeMap<MutationKind, KindReport>,
    pub never_panics: bool,
    pub overall_verdict: OverallVerdict,
}

impl Default for MutationReport {
    fn default() -> Self {
        Self {
            total_attempts: 0,
            by_kind: BTreeMap::new(),
            never_panics: true,
            overall_verdict: OverallVerdict::AllGraceful,
        }
    }
}

impl MutationReport {
    /// Count rejected mutations across all kinds.
    #[must_use]
    pub fn rejected(&self) -> usize {
        self.by_kind.values().map(|report| report.rejected).sum()
    }

    /// Count silent accepts across all kinds.
    #[must_use]
    pub fn silent_accepts(&self) -> usize {
        self.by_kind
            .values()
            .map(|report| report.silent_accept)
            .sum()
    }

    /// Count panics across all kinds.
    #[must_use]
    pub fn panics(&self) -> usize {
        self.by_kind.values().map(|report| report.panics).sum()
    }

    fn record_silent_accept(&mut self, kind: MutationKind, index: usize) {
        match &mut self.overall_verdict {
            OverallVerdict::AllGraceful => {
                self.overall_verdict = OverallVerdict::SilentAcceptDetected {
                    kind,
                    examples: vec![index],
                };
            }
            OverallVerdict::SilentAcceptDetected { examples, .. } => {
                if examples.len() < 8 {
                    examples.push(index);
                }
            }
            OverallVerdict::PanicDetected => {}
        }
    }

    fn finalize(&mut self) {
        if self.panics() > 0 {
            self.never_panics = false;
            self.overall_verdict = OverallVerdict::PanicDetected;
            return;
        }

        if self.silent_accepts() == 0 {
            self.never_panics = true;
            self.overall_verdict = OverallVerdict::AllGraceful;
        }
    }
}

/// Per-kind mutation counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KindReport {
    pub attempts: usize,
    pub rejected: usize,
    pub graceful_partial_accept: usize,
    pub graceful_field_error: usize,
    pub silent_accept: usize,
    pub panics: usize,
}

/// Overall verdict for a mutation run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverallVerdict {
    AllGraceful,
    SilentAcceptDetected {
        kind: MutationKind,
        examples: Vec<usize>,
    },
    PanicDetected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ok_classifies_as_silent_accept() {
        let report = MutationHarness::new()
            .with_seed(1)
            .with_max_mutations(8)
            .run(b"{\"ok\":true}", |_| Ok::<_, &'static str>("accepted"));

        assert!(report.never_panics);
        assert!(report.silent_accepts() > 0);
        assert!(matches!(
            report.overall_verdict,
            OverallVerdict::SilentAcceptDetected { .. }
        ));
    }

    #[test]
    fn errors_are_rejections() {
        let report = MutationHarness::new()
            .with_seed(1)
            .with_max_mutations(16)
            .run::<(), _, _>(b"{\"ok\":true}", |_| Err("bad shape"));

        assert_eq!(report.silent_accepts(), 0);
        assert_eq!(report.rejected(), report.total_attempts);
        assert_eq!(report.overall_verdict, OverallVerdict::AllGraceful);
    }

    #[test]
    fn panics_are_captured() {
        let report = MutationHarness::new()
            .with_seed(1)
            .with_max_mutations(4)
            .run::<(), &'static str, _>(b"{\"ok\":true}", |_| panic!("parser panic"));

        assert!(!report.never_panics);
        assert_eq!(report.overall_verdict, OverallVerdict::PanicDetected);
        assert!(report.panics() > 0);
    }

    #[test]
    fn classifier_can_mark_ok_as_partial_accept() {
        let report = MutationHarness::new()
            .with_seed(1)
            .with_max_mutations(8)
            .run_with_classifier(
                b"{\"ok\":true}",
                |_| Ok::<_, &'static str>("accepted"),
                |_| ResultClass::GracefulPartialAccept,
            );

        assert_eq!(report.silent_accepts(), 0);
        assert!(
            report
                .by_kind
                .values()
                .any(|kind| kind.graceful_partial_accept > 0)
        );
        assert_eq!(report.overall_verdict, OverallVerdict::AllGraceful);
    }
}
