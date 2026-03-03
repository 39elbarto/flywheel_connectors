//! Routing engine for provider/model selection.

use crate::error::{RouterError, RouterResult};
use crate::types::{ModelCapability, ModelInfo, ProviderConfig, ProviderStatus, RoutingStrategy};

/// Candidate for routing consideration.
#[derive(Debug, Clone)]
pub struct RouteCandidate {
    pub provider_name: String,
    pub model: ModelInfo,
    pub status: ProviderStatus,
    pub estimated_cost: f64,
    pub latency_p50_ms: u64,
    pub priority: u32,
}

/// Select the best candidate based on strategy and constraints.
pub fn select_candidate(
    candidates: &[RouteCandidate],
    strategy: RoutingStrategy,
    required_capabilities: &[ModelCapability],
    budget_limit: Option<f64>,
    preferred_provider: Option<&str>,
    preferred_model: Option<&str>,
) -> RouterResult<(usize, String)> {
    if candidates.is_empty() {
        return Err(RouterError::NoProviderAvailable {
            reason: "no candidates available".into(),
        });
    }

    // Filter to available candidates with required capabilities
    let eligible: Vec<(usize, &RouteCandidate)> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| c.status != ProviderStatus::Unavailable)
        .filter(|(_, c)| {
            required_capabilities
                .iter()
                .all(|cap| c.model.capabilities.contains(cap))
        })
        .filter(|(_, c)| match budget_limit {
            Some(limit) => c.estimated_cost <= limit,
            None => true,
        })
        .collect();

    if eligible.is_empty() {
        return Err(RouterError::NoProviderAvailable {
            reason: "no eligible candidates after filtering".into(),
        });
    }

    // Check for preferred provider/model match
    if let Some(pref_provider) = preferred_provider {
        if let Some((idx, _)) = eligible
            .iter()
            .find(|(_, c)| c.provider_name == pref_provider)
        {
            if strategy == RoutingStrategy::Fallback {
                return Ok((*idx, format!("preferred provider '{pref_provider}' available")));
            }
        }
    }

    if let Some(pref_model) = preferred_model {
        if let Some((idx, _)) = eligible.iter().find(|(_, c)| c.model.id == pref_model) {
            if strategy == RoutingStrategy::Fallback {
                return Ok((*idx, format!("preferred model '{pref_model}' available")));
            }
        }
    }

    let (selected_idx, reason) = match strategy {
        RoutingStrategy::Cost => {
            let (idx, c) = eligible
                .iter()
                .min_by(|(_, a), (_, b)| {
                    a.estimated_cost
                        .partial_cmp(&b.estimated_cost)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .expect("eligible is non-empty");
            (
                *idx,
                format!(
                    "lowest cost: {:.6} USD via {}/{}",
                    c.estimated_cost, c.provider_name, c.model.id
                ),
            )
        }
        RoutingStrategy::Latency => {
            let (idx, c) = eligible
                .iter()
                .min_by_key(|(_, c)| c.latency_p50_ms)
                .expect("eligible is non-empty");
            (
                *idx,
                format!(
                    "lowest latency: {}ms via {}/{}",
                    c.latency_p50_ms, c.provider_name, c.model.id
                ),
            )
        }
        RoutingStrategy::Capability => {
            // Prefer the candidate with the most capabilities
            let (idx, c) = eligible
                .iter()
                .max_by_key(|(_, c)| c.model.capabilities.len())
                .expect("eligible is non-empty");
            (
                *idx,
                format!(
                    "best capabilities ({} caps) via {}/{}",
                    c.model.capabilities.len(),
                    c.provider_name,
                    c.model.id
                ),
            )
        }
        RoutingStrategy::Fallback => {
            // Try in priority order
            let (idx, c) = eligible
                .iter()
                .min_by_key(|(_, c)| c.priority)
                .expect("eligible is non-empty");
            (
                *idx,
                format!(
                    "fallback priority {} via {}/{}",
                    c.priority, c.provider_name, c.model.id
                ),
            )
        }
    };

    Ok((selected_idx, reason))
}

/// Estimate token count from message content (simple heuristic).
pub fn estimate_tokens(text: &str) -> u64 {
    // Rough approximation: ~4 chars per token for English text
    let char_count = text.len() as u64;
    (char_count + 3) / 4
}

/// Estimate cost for a request given token estimates.
pub fn estimate_cost(model: &ModelInfo, input_tokens: u64, output_tokens: u64) -> f64 {
    (input_tokens as f64 * model.cost_per_input_token)
        + (output_tokens as f64 * model.cost_per_output_token)
}

/// Build candidates from provider configurations and current status.
pub fn build_candidates(
    providers: &[ProviderConfig],
    statuses: &[(String, ProviderStatus, u64)], // (name, status, latency_p50_ms)
    input_tokens: u64,
    output_tokens: u64,
) -> Vec<RouteCandidate> {
    let mut candidates = Vec::new();

    for provider in providers {
        let (status, latency) = statuses
            .iter()
            .find(|(name, _, _)| name == &provider.name)
            .map(|(_, s, l)| (*s, *l))
            .unwrap_or((ProviderStatus::Healthy, 100));

        for model in &provider.models {
            let cost = estimate_cost(model, input_tokens, output_tokens);
            candidates.push(RouteCandidate {
                provider_name: provider.name.clone(),
                model: model.clone(),
                status,
                estimated_cost: cost,
                latency_p50_ms: latency,
                priority: provider.priority,
            });
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_model(id: &str, cost_in: f64, cost_out: f64, caps: &[ModelCapability]) -> ModelInfo {
        ModelInfo {
            id: id.into(),
            capabilities: caps.to_vec(),
            context_window: 128_000,
            cost_per_input_token: cost_in,
            cost_per_output_token: cost_out,
        }
    }

    fn test_candidates() -> Vec<RouteCandidate> {
        vec![
            RouteCandidate {
                provider_name: "anthropic".into(),
                model: test_model(
                    "claude-sonnet-4",
                    0.000003,
                    0.000015,
                    &[ModelCapability::Code, ModelCapability::ToolUse],
                ),
                status: ProviderStatus::Healthy,
                estimated_cost: 0.012,
                latency_p50_ms: 800,
                priority: 1,
            },
            RouteCandidate {
                provider_name: "openai".into(),
                model: test_model(
                    "gpt-4o",
                    0.000005,
                    0.000015,
                    &[
                        ModelCapability::Code,
                        ModelCapability::Vision,
                        ModelCapability::ToolUse,
                    ],
                ),
                status: ProviderStatus::Healthy,
                estimated_cost: 0.020,
                latency_p50_ms: 500,
                priority: 2,
            },
            RouteCandidate {
                provider_name: "google-ai".into(),
                model: test_model(
                    "gemini-2.0-flash",
                    0.0000001,
                    0.0000004,
                    &[ModelCapability::Code, ModelCapability::LongContext],
                ),
                status: ProviderStatus::Healthy,
                estimated_cost: 0.001,
                latency_p50_ms: 200,
                priority: 3,
            },
        ]
    }

    #[test]
    fn cost_strategy_selects_cheapest() {
        let candidates = test_candidates();
        let (idx, reason) = select_candidate(
            &candidates,
            RoutingStrategy::Cost,
            &[],
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(candidates[idx].provider_name, "google-ai");
        assert!(reason.contains("lowest cost"));
    }

    #[test]
    fn latency_strategy_selects_fastest() {
        let candidates = test_candidates();
        let (idx, reason) = select_candidate(
            &candidates,
            RoutingStrategy::Latency,
            &[],
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(candidates[idx].provider_name, "google-ai");
        assert!(reason.contains("lowest latency"));
    }

    #[test]
    fn capability_strategy_selects_most_capable() {
        let candidates = test_candidates();
        let (idx, reason) = select_candidate(
            &candidates,
            RoutingStrategy::Capability,
            &[],
            None,
            None,
            None,
        )
        .unwrap();
        // OpenAI has 3 capabilities vs others with 2
        assert_eq!(candidates[idx].provider_name, "openai");
        assert!(reason.contains("best capabilities"));
    }

    #[test]
    fn fallback_strategy_uses_priority() {
        let candidates = test_candidates();
        let (idx, _) = select_candidate(
            &candidates,
            RoutingStrategy::Fallback,
            &[],
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(candidates[idx].provider_name, "anthropic"); // priority 1
    }

    #[test]
    fn required_capabilities_filter() {
        let candidates = test_candidates();
        let (idx, _) = select_candidate(
            &candidates,
            RoutingStrategy::Cost,
            &[ModelCapability::Vision],
            None,
            None,
            None,
        )
        .unwrap();
        // Only OpenAI has vision
        assert_eq!(candidates[idx].provider_name, "openai");
    }

    #[test]
    fn budget_limit_filters_expensive() {
        let candidates = test_candidates();
        let (idx, _) = select_candidate(
            &candidates,
            RoutingStrategy::Latency,
            &[],
            Some(0.015), // Excludes OpenAI at 0.020
            None,
            None,
        )
        .unwrap();
        assert_ne!(candidates[idx].provider_name, "openai");
    }

    #[test]
    fn no_eligible_candidates_errors() {
        let candidates = test_candidates();
        let result = select_candidate(
            &candidates,
            RoutingStrategy::Cost,
            &[ModelCapability::Vision, ModelCapability::LongContext], // No provider has both
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn empty_candidates_errors() {
        let result = select_candidate(
            &[],
            RoutingStrategy::Cost,
            &[],
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn token_estimation() {
        assert_eq!(estimate_tokens("hello"), 2); // 5 chars -> ~2 tokens
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("a"), 1);
    }
}
