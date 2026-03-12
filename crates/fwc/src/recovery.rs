//! Intent recovery, forgiving aliases, and structured recovery hints for agent mistakes.
//!
//! This module detects common mistaken command shapes, normalizes the safe ones
//! automatically, and returns structured recovery payloads for the unsafe ones.
//!
//! # Design principles
//!
//! - Anticipate intent, not only literal syntax.
//! - Fail helpfully with typed, structured recovery data.
//! - Forgive by default for safe command-shape mistakes.
//! - Keep recovery output short, explicit, and immediately actionable.
//! - Never silently apply ambiguous or risky corrections.

use serde::Serialize;

// ── Alias tables ────────────────────────────────────────────────────────────

/// Extended alias table mapping common alternative names to canonical fwc commands.
///
/// Returns `None` if the token is already canonical or unrecognized.
/// These aliases are always safe to apply because they map unambiguously
/// to a single canonical command.
#[must_use]
pub fn command_alias(token: &str) -> Option<&'static str> {
    match token {
        // Help/guide aliases
        "contract" | "taxonomy" | "help-commands" | "commands" => Some("guide"),

        // Task/workflow aliases
        "tasks" | "capsule" | "capsules" => Some("task"),
        "workflow" | "compile" | "parse" => Some("plan"),
        "why" | "reasoning" | "rationale" => Some("explain"),
        "run" | "execute" | "apply" | "materialize" => Some("do"),

        // Discovery aliases
        "ls" | "connectors" => Some("list"),
        "find" | "grep" | "lookup" | "query" => Some("search"),
        "info" | "inspect" | "describe" | "detail" | "details" | "get" => Some("show"),
        "operations" | "operation" | "op" | "actions" | "methods" => Some("ops"),
        "spec" | "shape" | "type" | "types" | "interface" => Some("schema"),
        "example" | "sample" | "samples" => Some("examples"),
        "template" | "templates" => Some("template"),

        // Lifecycle aliases
        "health" | "state" | "check" | "healthcheck" => Some("status"),
        "diagnose" | "diagnostics" => Some("doctor"),
        "budgets" | "usage" | "spend" => Some("budget"),
        "caps" | "permissions" | "grants" => Some("capabilities"),
        "add" | "setup" => Some("install"),
        "upgrade" => Some("update"),
        "lock" | "freeze" => Some("pin"),
        "unlock" | "unfreeze" => Some("unpin"),
        "configure" | "settings" | "prefs" | "preferences" | "cfg" => Some("config"),

        // Execution aliases
        "call" | "exec" | "send" | "request" | "fire" => Some("invoke"),
        "preview" | "dry-run" | "dryrun" | "dry_run" | "test-run" => Some("simulate"),
        "pipelines" | "flow" | "flows" => Some("pipeline"),

        _ => None,
    }
}

/// Common typos for fwc commands, mapped to the intended command.
///
/// These are distinct from aliases because the input is clearly a mistake
/// rather than a legitimate alternative name.
#[must_use]
pub fn typo_correction(token: &str) -> Option<&'static str> {
    match token {
        // guide typos
        "gudie" | "gude" | "giude" | "guidee" => Some("guide"),

        // task typos
        "taks" | "tsak" | "takss" => Some("task"),

        // plan typos
        "paln" | "plna" | "plaan" => Some("plan"),

        // explain typos
        "expalin" | "explian" | "explan" | "expain" => Some("explain"),

        // list typos
        "lsit" | "litst" | "lits" | "lsist" => Some("list"),

        // search typos
        "serach" | "seach" | "saerch" | "searh" | "searcg" => Some("search"),

        // show typos
        "shwo" | "hsow" | "sohw" | "shw" => Some("show"),

        // ops typos
        "osp" | "pos" | "opes" => Some("ops"),

        // schema typos
        "schmea" | "shcema" | "scheam" | "schemma" | "scehma" => Some("schema"),

        // examples typos
        "exmaples" | "exampels" | "exmples" | "examlpes" | "exapmles" | "exampes" => {
            Some("examples")
        }

        // status typos
        "stauts" | "staus" | "sttaus" | "statsu" => Some("status"),
        "docotr" | "doctro" | "dcotor" => Some("doctor"),
        "budgte" | "buget" | "bdget" => Some("budget"),
        "capabilties" | "capabilites" | "capablities" => Some("capabilities"),

        // install/update typos
        "insatll" | "intall" | "insall" | "isntall" | "instal" => Some("install"),
        "udpate" | "upadte" | "updte" | "upate" | "updaet" => Some("update"),

        // config typos
        "conifg" | "cofnig" | "confgi" | "configg" | "ocnfig" => Some("config"),

        // invoke/simulate typos
        "invoe" | "invoek" | "invokee" | "inoke" | "invke" => Some("invoke"),
        "simlate" | "simualte" | "simulte" | "simulaet" | "simuate" => Some("simulate"),

        // pipeline typos
        "pipleine" | "pipline" | "pipeine" | "pieline" => Some("pipeline"),

        // pin/unpin typos
        "pni" | "pinn" => Some("pin"),
        "unpni" | "unpinn" | "unpi" => Some("unpin"),

        _ => None,
    }
}

/// Attempt to resolve a token to a canonical command, first by alias then by typo correction.
///
/// Returns the canonical command and the kind of correction applied.
#[must_use]
pub fn resolve_command(token: &str) -> Option<CommandResolution> {
    let lower = token.to_ascii_lowercase();

    if let Some(canonical) = command_alias(&lower) {
        return Some(CommandResolution {
            canonical,
            kind: CorrectionKind::Alias,
            rationale: "Canonicalized a safe command alias to the primary fwc command name.",
        });
    }

    if let Some(canonical) = typo_correction(&lower) {
        return Some(CommandResolution {
            canonical,
            kind: CorrectionKind::Typo,
            rationale: "Corrected a likely typo to the closest canonical fwc command.",
        });
    }

    None
}

/// Config subcommand alias resolution.
#[must_use]
pub fn config_subcommand_alias(token: &str) -> Option<&'static str> {
    match token {
        "show" | "read" | "view" | "inspect" | "dump" => Some("get"),
        "write" | "put" | "update" | "change" => Some("set"),
        "rm" | "remove" | "delete" | "clear" => Some("unset"),
        "load" | "read-file" => Some("import"),
        "save" | "write-file" | "backup" => Some("export"),
        "check" | "validate" | "lint" | "verify" | "diagnose" => Some("doctor"),
        "spec" | "shape" | "type" | "types" => Some("schema"),
        _ => None,
    }
}

/// Config subcommand typo correction.
#[must_use]
pub fn config_subcommand_typo(token: &str) -> Option<&'static str> {
    match token {
        "schmea" | "shcema" | "scheam" => Some("schema"),
        "gte" | "ge" | "gett" => Some("get"),
        "ste" | "se" | "sett" => Some("set"),
        "unste" | "unsett" | "usnet" => Some("unset"),
        "improt" | "imoprt" | "ipmort" => Some("import"),
        "exprot" | "exoprt" | "eport" | "epxort" => Some("export"),
        "docotr" | "doctr" | "doctro" | "dcotor" => Some("doctor"),
        _ => None,
    }
}

/// Resolve a config subcommand token.
#[must_use]
pub fn resolve_config_subcommand(token: &str) -> Option<CommandResolution> {
    let lower = token.to_ascii_lowercase();

    if let Some(canonical) = config_subcommand_alias(&lower) {
        return Some(CommandResolution {
            canonical,
            kind: CorrectionKind::Alias,
            rationale: "Canonicalized a config subcommand alias.",
        });
    }

    if let Some(canonical) = config_subcommand_typo(&lower) {
        return Some(CommandResolution {
            canonical,
            kind: CorrectionKind::Typo,
            rationale: "Corrected a config subcommand typo.",
        });
    }

    None
}

/// Task subcommand alias resolution.
#[must_use]
pub fn task_subcommand_alias(token: &str) -> Option<&'static str> {
    match token {
        "new" | "make" | "init" | "open" | "start" => Some("create"),
        "view" | "get" | "inspect" | "detail" | "details" | "status" => Some("show"),
        "ls" | "all" | "recent" => Some("list"),
        "fix" | "infer" | "fill" => Some("resolve"),
        "question" | "clarify" | "what-next" | "next" | "help" => Some("ask"),
        "step" | "progress" | "next-step" | "continue" | "proceed" => Some("advance"),
        "set" | "assign" | "update" | "attach" => Some("bind"),
        "ok" | "yes" | "confirm" | "accept" | "lgtm" => Some("approve"),
        "go" | "execute" | "do" | "fire" | "launch" => Some("run"),
        _ => None,
    }
}

// ── Recovery types ──────────────────────────────────────────────────────────

/// The kind of correction applied to a command token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorrectionKind {
    /// The token was a known alternative name for the canonical command.
    Alias,
    /// The token was a likely typo close to a canonical command.
    Typo,
}

/// A resolved command mapping from a non-canonical input token.
#[derive(Clone, Debug)]
pub struct CommandResolution {
    /// The canonical command name.
    pub canonical: &'static str,
    /// Whether this was an alias or typo.
    pub kind: CorrectionKind,
    /// Human-readable explanation of the correction.
    pub rationale: &'static str,
}

/// Classification of whether a correction is safe to auto-apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorrectionSafety {
    /// Safe to auto-apply: the correction is unambiguous and non-destructive.
    Safe,
    /// Ambiguous: multiple plausible corrections exist; ask the caller to clarify.
    Ambiguous,
    /// Dangerous: the correction would change mutating/destructive semantics.
    #[allow(dead_code)] // Reserved for future use with destructive command typos.
    Dangerous,
}

/// Classify whether applying a resolved command is safe.
///
/// Alias corrections are always safe because they are intentional alternative names.
/// Typo corrections are safe for read-only commands but marked ambiguous for
/// mutating commands to prevent accidental side effects.
#[must_use]
pub fn correction_safety(resolution: &CommandResolution) -> CorrectionSafety {
    match resolution.kind {
        CorrectionKind::Alias => CorrectionSafety::Safe,
        CorrectionKind::Typo => {
            if is_mutating_command(resolution.canonical) {
                CorrectionSafety::Ambiguous
            } else {
                CorrectionSafety::Safe
            }
        }
    }
}

/// Returns `true` if the command can cause side effects.
#[must_use]
pub fn is_mutating_command(command: &str) -> bool {
    matches!(
        command,
        "invoke" | "install" | "update" | "pin" | "unpin" | "do"
    )
}

/// Returns `true` if the command is read-only / discovery.
#[allow(dead_code)] // Used in tests; wired into host-backed dispatch in later beads.
#[must_use]
pub fn is_readonly_command(command: &str) -> bool {
    matches!(
        command,
        "guide"
            | "list"
            | "search"
            | "show"
            | "ops"
            | "schema"
            | "examples"
            | "status"
            | "simulate"
            | "preflight"
            | "plan"
            | "explain"
    )
}

// ── Levenshtein distance ────────────────────────────────────────────────────

/// Compute the Levenshtein edit distance between two strings.
///
/// Uses a single-row DP approach for memory efficiency.
#[allow(dead_code)] // Used in tests and later beads for fuzzy matching.
#[must_use]
pub fn levenshtein(left: &str, right: &str) -> usize {
    let right_chars = right.chars().collect::<Vec<_>>();
    let mut costs = (0..=right_chars.len()).collect::<Vec<_>>();

    for (left_index, left_char) in left.chars().enumerate() {
        let mut previous = costs[0];
        costs[0] = left_index + 1;

        for (right_index, right_char) in right_chars.iter().enumerate() {
            let insertion = costs[right_index + 1] + 1;
            let deletion = costs[right_index] + 1;
            let substitution = previous + usize::from(left_char != *right_char);
            previous = costs[right_index + 1];
            costs[right_index + 1] = insertion.min(deletion).min(substitution);
        }
    }

    costs[right_chars.len()]
}

/// Find the closest candidates from a list using Levenshtein distance.
///
/// Returns up to `limit` candidates with distance <= `max_distance`,
/// sorted by (distance, length).
#[allow(dead_code)] // Used in tests and later beads for fuzzy suggestion generation.
#[must_use]
pub fn closest_matches<'a>(
    value: &str,
    candidates: &[&'a str],
    max_distance: usize,
    limit: usize,
) -> Vec<&'a str> {
    #[allow(clippy::suspicious_operation_groupings)]
    // Intentional: match prefix in either direction
    let mut matches = candidates
        .iter()
        .map(|candidate| (*candidate, levenshtein(value, candidate)))
        .filter(|(candidate, distance)| {
            candidate.starts_with(value)
                || value.starts_with(*candidate)
                || *distance <= max_distance
        })
        .collect::<Vec<_>>();

    matches.sort_by_key(|(candidate, distance)| (*distance, candidate.len()));
    matches
        .into_iter()
        .take(limit)
        .map(|(candidate, _)| candidate)
        .collect()
}

// ── Redundant prefix detection ──────────────────────────────────────────────

/// Known redundant prefixes that agents sometimes add before the real command.
///
/// For example, `fwc connector list` should become `fwc list`.
pub const REDUNDANT_PREFIXES: &[&str] = &[
    "connector",
    "connectors",
    "fcp",
    "flywheel",
    "service",
    "services",
    "plugin",
    "plugins",
];

/// Returns `true` if the token is a redundant prefix that should be stripped.
#[must_use]
pub fn is_redundant_prefix(token: &str) -> bool {
    REDUNDANT_PREFIXES.contains(&token.to_ascii_lowercase().as_str())
}

// ── Dangerous shape detection ───────────────────────────────────────────────

/// Patterns that look like they came from a different CLI and should never
/// be silently corrected because the intent is ambiguous.
///
/// This function is flag-aware: it scans past known global flags (like `--json`,
/// `--format`, `--host`) to find the first positional token, just like the CLI
/// parser does.
#[must_use]
pub fn is_dangerous_shape(args: &[String]) -> Option<DangerousShape> {
    // Find positional tokens after skipping known global flags
    let positional = extract_positional_tokens(args);

    // `fwc op show <connector> <operation>` — ambiguous between ops and schema
    if positional.len() >= 2
        && matches!(positional[0], "op" | "operation" | "operations")
        && positional[1] == "show"
    {
        return Some(DangerousShape {
            kind: "ambiguous-verb-object",
            message: "The `op show` shape is ambiguous and was not auto-corrected.",
            candidates: vec!["fwc ops <connector>", "fwc schema <connector> <operation>"],
        });
    }

    // `fwc delete <connector>` — connector removal is not a supported primitive
    if !positional.is_empty()
        && matches!(positional[0], "delete" | "remove" | "uninstall" | "destroy")
    {
        return Some(DangerousShape {
            kind: "destructive-ambiguity",
            message: "Connector removal is not a supported `fwc` primitive. Choose a supported lifecycle action instead.",
            candidates: vec![
                "fwc status <connector>",
                "fwc unpin <connector>",
                "fwc update <connector> --source <package-or-dir>",
            ],
        });
    }

    // `fwc --force ...` — no force flag, probably from another CLI
    // This checks all args (including flags) because --force is itself a flag
    if args
        .iter()
        .skip(1)
        .any(|token| matches!(token.as_str(), "--force" | "-f"))
    {
        return Some(DangerousShape {
            kind: "unsupported-force-flag",
            message: "`fwc` does not support --force. Use explicit approval flags where needed.",
            candidates: vec!["fwc do \"<intent>\" --approve"],
        });
    }

    None
}

/// Extract positional (non-flag) tokens from args, skipping the binary name
/// and known global flag+value pairs.
fn extract_positional_tokens(args: &[String]) -> Vec<&str> {
    let mut result = Vec::new();
    let mut index = 1; // skip binary name

    while index < args.len() {
        let current = args[index].as_str();
        match current {
            // Flags that consume the next token as their value
            "--format" | "--host" => index += 2,
            // Boolean flags
            "--json" | "-h" | "--help" | "-V" | "--version" | "--token-stats" => index += 1,
            // Flags with =value
            _ if current.starts_with("--format=") || current.starts_with("--host=") => index += 1,
            // Other flags we don't recognize — skip them but don't consume a value
            _ if current.starts_with('-') && !current.starts_with("--force") => index += 1,
            // Positional token
            _ => {
                result.push(current);
                index += 1;
            }
        }
    }

    result
}

/// A command shape that is too ambiguous or dangerous to auto-correct.
#[derive(Clone, Debug)]
pub struct DangerousShape {
    /// Machine-readable classification.
    pub kind: &'static str,
    /// Human-readable explanation.
    pub message: &'static str,
    /// Possible intended commands.
    pub candidates: Vec<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── command_alias ────────────────────────────────────────────────────

    #[test]
    fn alias_info_resolves_to_show() {
        assert_eq!(command_alias("info"), Some("show"));
    }

    #[test]
    fn alias_ls_resolves_to_list() {
        assert_eq!(command_alias("ls"), Some("list"));
    }

    #[test]
    fn alias_find_resolves_to_search() {
        assert_eq!(command_alias("find"), Some("search"));
    }

    #[test]
    fn alias_run_resolves_to_do() {
        assert_eq!(command_alias("run"), Some("do"));
    }

    #[test]
    fn alias_preview_resolves_to_simulate() {
        assert_eq!(command_alias("preview"), Some("simulate"));
    }

    #[test]
    fn alias_dry_run_resolves_to_simulate() {
        assert_eq!(command_alias("dry-run"), Some("simulate"));
        assert_eq!(command_alias("dryrun"), Some("simulate"));
        assert_eq!(command_alias("dry_run"), Some("simulate"));
    }

    #[test]
    fn alias_upgrade_resolves_to_update() {
        assert_eq!(command_alias("upgrade"), Some("update"));
    }

    #[test]
    fn alias_configure_resolves_to_config() {
        assert_eq!(command_alias("configure"), Some("config"));
        assert_eq!(command_alias("cfg"), Some("config"));
    }

    #[test]
    fn alias_add_resolves_to_install() {
        assert_eq!(command_alias("add"), Some("install"));
        assert_eq!(command_alias("setup"), Some("install"));
    }

    #[test]
    fn alias_lock_resolves_to_pin() {
        assert_eq!(command_alias("lock"), Some("pin"));
        assert_eq!(command_alias("freeze"), Some("pin"));
    }

    #[test]
    fn alias_unlock_resolves_to_unpin() {
        assert_eq!(command_alias("unlock"), Some("unpin"));
    }

    #[test]
    fn alias_call_resolves_to_invoke() {
        assert_eq!(command_alias("call"), Some("invoke"));
        assert_eq!(command_alias("exec"), Some("invoke"));
        assert_eq!(command_alias("fire"), Some("invoke"));
    }

    #[test]
    fn alias_tasks_resolves_to_task() {
        assert_eq!(command_alias("tasks"), Some("task"));
        assert_eq!(command_alias("capsule"), Some("task"));
    }

    #[test]
    fn alias_compile_resolves_to_plan() {
        assert_eq!(command_alias("compile"), Some("plan"));
        assert_eq!(command_alias("workflow"), Some("plan"));
    }

    #[test]
    fn alias_why_resolves_to_explain() {
        assert_eq!(command_alias("why"), Some("explain"));
        assert_eq!(command_alias("reasoning"), Some("explain"));
    }

    #[test]
    fn alias_query_resolves_to_search() {
        assert_eq!(command_alias("query"), Some("search"));
        assert_eq!(command_alias("lookup"), Some("search"));
    }

    #[test]
    fn alias_operations_resolves_to_ops() {
        assert_eq!(command_alias("operations"), Some("ops"));
        assert_eq!(command_alias("operation"), Some("ops"));
        assert_eq!(command_alias("op"), Some("ops"));
        assert_eq!(command_alias("actions"), Some("ops"));
        assert_eq!(command_alias("methods"), Some("ops"));
    }

    #[test]
    fn alias_sample_resolves_to_examples() {
        assert_eq!(command_alias("sample"), Some("examples"));
        assert_eq!(command_alias("template"), Some("template"));
    }

    #[test]
    fn alias_health_resolves_to_status() {
        assert_eq!(command_alias("health"), Some("status"));
        assert_eq!(command_alias("check"), Some("status"));
        assert_eq!(command_alias("healthcheck"), Some("status"));
    }

    #[test]
    fn canonical_command_returns_none() {
        assert_eq!(command_alias("list"), None);
        assert_eq!(command_alias("show"), None);
        assert_eq!(command_alias("invoke"), None);
        assert_eq!(command_alias("guide"), None);
    }

    #[test]
    fn unknown_token_returns_none() {
        assert_eq!(command_alias("foobar"), None);
        assert_eq!(command_alias(""), None);
    }

    // ── typo_correction ─────────────────────────────────────────────────

    #[test]
    fn typo_exmaples_corrects_to_examples() {
        assert_eq!(typo_correction("exmaples"), Some("examples"));
    }

    #[test]
    fn typo_gudie_corrects_to_guide() {
        assert_eq!(typo_correction("gudie"), Some("guide"));
    }

    #[test]
    fn typo_shwo_corrects_to_show() {
        assert_eq!(typo_correction("shwo"), Some("show"));
    }

    #[test]
    fn typo_lsit_corrects_to_list() {
        assert_eq!(typo_correction("lsit"), Some("list"));
    }

    #[test]
    fn typo_serach_corrects_to_search() {
        assert_eq!(typo_correction("serach"), Some("search"));
    }

    #[test]
    fn typo_conifg_corrects_to_config() {
        assert_eq!(typo_correction("conifg"), Some("config"));
    }

    #[test]
    fn typo_invokee_corrects_to_invoke() {
        assert_eq!(typo_correction("invokee"), Some("invoke"));
    }

    #[test]
    fn typo_simlate_corrects_to_simulate() {
        assert_eq!(typo_correction("simlate"), Some("simulate"));
    }

    #[test]
    fn typo_insatll_corrects_to_install() {
        assert_eq!(typo_correction("insatll"), Some("install"));
    }

    #[test]
    fn typo_udpate_corrects_to_update() {
        assert_eq!(typo_correction("udpate"), Some("update"));
    }

    #[test]
    fn typo_taks_corrects_to_task() {
        assert_eq!(typo_correction("taks"), Some("task"));
    }

    #[test]
    fn typo_paln_corrects_to_plan() {
        assert_eq!(typo_correction("paln"), Some("plan"));
    }

    #[test]
    fn typo_schmea_corrects_to_schema() {
        assert_eq!(typo_correction("schmea"), Some("schema"));
    }

    #[test]
    fn typo_stauts_corrects_to_status() {
        assert_eq!(typo_correction("stauts"), Some("status"));
    }

    #[test]
    fn typo_pni_corrects_to_pin() {
        assert_eq!(typo_correction("pni"), Some("pin"));
    }

    #[test]
    fn typo_unpni_corrects_to_unpin() {
        assert_eq!(typo_correction("unpni"), Some("unpin"));
    }

    #[test]
    fn typo_canonical_returns_none() {
        assert_eq!(typo_correction("list"), None);
        assert_eq!(typo_correction("show"), None);
    }

    // ── resolve_command ─────────────────────────────────────────────────

    #[test]
    fn resolve_alias_is_alias_kind() {
        let res = resolve_command("info").unwrap();
        assert_eq!(res.canonical, "show");
        assert_eq!(res.kind, CorrectionKind::Alias);
    }

    #[test]
    fn resolve_typo_is_typo_kind() {
        let res = resolve_command("exmaples").unwrap();
        assert_eq!(res.canonical, "examples");
        assert_eq!(res.kind, CorrectionKind::Typo);
    }

    #[test]
    fn resolve_unknown_returns_none() {
        assert!(resolve_command("foobar").is_none());
    }

    #[test]
    fn resolve_case_insensitive() {
        let res = resolve_command("INFO").unwrap();
        assert_eq!(res.canonical, "show");
    }

    #[test]
    fn resolve_canonical_returns_none() {
        assert!(resolve_command("list").is_none());
        assert!(resolve_command("show").is_none());
        assert!(resolve_command("invoke").is_none());
    }

    // ── config subcommand recovery ──────────────────────────────────────

    #[test]
    fn config_alias_show_resolves_to_get() {
        assert_eq!(config_subcommand_alias("show"), Some("get"));
        assert_eq!(config_subcommand_alias("view"), Some("get"));
    }

    #[test]
    fn config_alias_write_resolves_to_set() {
        assert_eq!(config_subcommand_alias("write"), Some("set"));
        assert_eq!(config_subcommand_alias("update"), Some("set"));
    }

    #[test]
    fn config_alias_rm_resolves_to_unset() {
        assert_eq!(config_subcommand_alias("rm"), Some("unset"));
        assert_eq!(config_subcommand_alias("delete"), Some("unset"));
    }

    #[test]
    fn config_alias_validate_resolves_to_doctor() {
        assert_eq!(config_subcommand_alias("validate"), Some("doctor"));
        assert_eq!(config_subcommand_alias("lint"), Some("doctor"));
        assert_eq!(config_subcommand_alias("check"), Some("doctor"));
    }

    #[test]
    fn config_alias_load_resolves_to_import() {
        assert_eq!(config_subcommand_alias("load"), Some("import"));
    }

    #[test]
    fn config_alias_save_resolves_to_export() {
        assert_eq!(config_subcommand_alias("save"), Some("export"));
        assert_eq!(config_subcommand_alias("backup"), Some("export"));
    }

    #[test]
    fn config_typo_schmea_resolves_to_schema() {
        assert_eq!(config_subcommand_typo("schmea"), Some("schema"));
    }

    #[test]
    fn config_typo_docotr_resolves_to_doctor() {
        assert_eq!(config_subcommand_typo("docotr"), Some("doctor"));
    }

    #[test]
    fn config_typo_improt_resolves_to_import() {
        assert_eq!(config_subcommand_typo("improt"), Some("import"));
    }

    #[test]
    fn config_typo_exprot_resolves_to_export() {
        assert_eq!(config_subcommand_typo("exprot"), Some("export"));
    }

    #[test]
    fn config_subcommand_resolve_alias() {
        let res = resolve_config_subcommand("validate").unwrap();
        assert_eq!(res.canonical, "doctor");
        assert_eq!(res.kind, CorrectionKind::Alias);
    }

    #[test]
    fn config_subcommand_resolve_typo() {
        let res = resolve_config_subcommand("schmea").unwrap();
        assert_eq!(res.canonical, "schema");
        assert_eq!(res.kind, CorrectionKind::Typo);
    }

    #[test]
    fn config_subcommand_canonical_returns_none() {
        assert!(resolve_config_subcommand("schema").is_none());
        assert!(resolve_config_subcommand("get").is_none());
    }

    // ── task subcommand recovery ────────────────────────────────────────

    #[test]
    fn task_alias_new_resolves_to_create() {
        assert_eq!(task_subcommand_alias("new"), Some("create"));
        assert_eq!(task_subcommand_alias("init"), Some("create"));
    }

    #[test]
    fn task_alias_view_resolves_to_show() {
        assert_eq!(task_subcommand_alias("view"), Some("show"));
        assert_eq!(task_subcommand_alias("inspect"), Some("show"));
    }

    #[test]
    fn task_alias_ls_resolves_to_list() {
        assert_eq!(task_subcommand_alias("ls"), Some("list"));
        assert_eq!(task_subcommand_alias("all"), Some("list"));
    }

    #[test]
    fn task_alias_question_resolves_to_ask() {
        assert_eq!(task_subcommand_alias("question"), Some("ask"));
        assert_eq!(task_subcommand_alias("clarify"), Some("ask"));
    }

    #[test]
    fn task_alias_confirm_resolves_to_approve() {
        assert_eq!(task_subcommand_alias("confirm"), Some("approve"));
        assert_eq!(task_subcommand_alias("ok"), Some("approve"));
        assert_eq!(task_subcommand_alias("yes"), Some("approve"));
        assert_eq!(task_subcommand_alias("lgtm"), Some("approve"));
    }

    #[test]
    fn task_alias_go_resolves_to_run() {
        assert_eq!(task_subcommand_alias("go"), Some("run"));
        assert_eq!(task_subcommand_alias("execute"), Some("run"));
    }

    #[test]
    fn task_alias_fix_resolves_to_resolve() {
        assert_eq!(task_subcommand_alias("fix"), Some("resolve"));
        assert_eq!(task_subcommand_alias("infer"), Some("resolve"));
    }

    #[test]
    fn task_alias_step_resolves_to_advance() {
        assert_eq!(task_subcommand_alias("step"), Some("advance"));
        assert_eq!(task_subcommand_alias("continue"), Some("advance"));
        assert_eq!(task_subcommand_alias("proceed"), Some("advance"));
    }

    #[test]
    fn task_alias_set_resolves_to_bind() {
        assert_eq!(task_subcommand_alias("set"), Some("bind"));
        assert_eq!(task_subcommand_alias("assign"), Some("bind"));
        assert_eq!(task_subcommand_alias("attach"), Some("bind"));
    }

    #[test]
    fn task_canonical_returns_none() {
        assert_eq!(task_subcommand_alias("create"), None);
        assert_eq!(task_subcommand_alias("show"), None);
        assert_eq!(task_subcommand_alias("run"), None);
    }

    // ── correction_safety ───────────────────────────────────────────────

    #[test]
    fn alias_correction_is_always_safe() {
        let res = resolve_command("info").unwrap();
        assert_eq!(correction_safety(&res), CorrectionSafety::Safe);
    }

    #[test]
    fn alias_to_mutating_command_is_safe() {
        // Aliases are intentional names, so even "call" -> "invoke" is safe.
        let res = resolve_command("call").unwrap();
        assert_eq!(res.canonical, "invoke");
        assert_eq!(correction_safety(&res), CorrectionSafety::Safe);
    }

    #[test]
    fn typo_readonly_is_safe() {
        let res = resolve_command("exmaples").unwrap();
        assert_eq!(correction_safety(&res), CorrectionSafety::Safe);
    }

    #[test]
    fn typo_mutating_is_ambiguous() {
        let res = resolve_command("invokee").unwrap();
        assert_eq!(res.canonical, "invoke");
        assert_eq!(correction_safety(&res), CorrectionSafety::Ambiguous);
    }

    #[test]
    fn typo_install_is_ambiguous() {
        let res = resolve_command("insatll").unwrap();
        assert_eq!(res.canonical, "install");
        assert_eq!(correction_safety(&res), CorrectionSafety::Ambiguous);
    }

    // ── is_mutating_command / is_readonly_command ────────────────────────

    #[test]
    fn invoke_is_mutating() {
        assert!(is_mutating_command("invoke"));
    }

    #[test]
    fn list_is_not_mutating() {
        assert!(!is_mutating_command("list"));
    }

    #[test]
    fn show_is_readonly() {
        assert!(is_readonly_command("show"));
    }

    #[test]
    fn simulate_is_readonly() {
        assert!(is_readonly_command("simulate"));
    }

    #[test]
    fn invoke_is_not_readonly() {
        assert!(!is_readonly_command("invoke"));
    }

    #[test]
    fn mutating_and_readonly_are_disjoint() {
        let all_commands = [
            "guide",
            "task",
            "plan",
            "explain",
            "do",
            "list",
            "search",
            "show",
            "ops",
            "schema",
            "examples",
            "template",
            "doctor",
            "status",
            "budget",
            "capabilities",
            "install",
            "update",
            "pin",
            "unpin",
            "config",
            "invoke",
            "simulate",
            "preflight",
        ];
        for cmd in all_commands {
            assert!(
                !(is_mutating_command(cmd) && is_readonly_command(cmd)),
                "command `{cmd}` is both mutating and readonly"
            );
        }
    }

    // ── levenshtein ─────────────────────────────────────────────────────

    #[test]
    fn levenshtein_identical_is_zero() {
        assert_eq!(levenshtein("hello", "hello"), 0);
    }

    #[test]
    fn levenshtein_empty_string() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
    }

    #[test]
    fn levenshtein_single_substitution() {
        assert_eq!(levenshtein("cat", "car"), 1);
    }

    #[test]
    fn levenshtein_single_insertion() {
        assert_eq!(levenshtein("cat", "cats"), 1);
    }

    #[test]
    fn levenshtein_single_deletion() {
        assert_eq!(levenshtein("cats", "cat"), 1);
    }

    #[test]
    fn levenshtein_transposition_is_two() {
        assert_eq!(levenshtein("ab", "ba"), 2);
    }

    #[test]
    fn levenshtein_completely_different() {
        assert_eq!(levenshtein("abc", "xyz"), 3);
    }

    #[test]
    fn levenshtein_case_sensitive() {
        assert_eq!(levenshtein("Hello", "hello"), 1);
    }

    // ── closest_matches ─────────────────────────────────────────────────

    #[test]
    fn closest_matches_exact_prefix() {
        let candidates = &["list", "show", "lint", "schema"];
        let matches = closest_matches("li", candidates, 3, 3);
        assert_eq!(matches[0], "list");
        assert!(matches.contains(&"lint"));
    }

    #[test]
    fn closest_matches_typo() {
        let candidates = &["list", "show", "schema", "examples"];
        let matches = closest_matches("shwo", candidates, 2, 3);
        assert!(matches.contains(&"show"));
    }

    #[test]
    fn closest_matches_no_match() {
        let candidates = &["list", "show", "schema"];
        let matches = closest_matches("zzzzzzzzzzz", candidates, 2, 3);
        assert!(matches.is_empty());
    }

    #[test]
    fn closest_matches_limits_output() {
        let candidates = &["a", "b", "c", "d", "e"];
        let matches = closest_matches("a", candidates, 3, 2);
        assert!(matches.len() <= 2);
    }

    // ── redundant prefix ────────────────────────────────────────────────

    #[test]
    fn connector_is_redundant() {
        assert!(is_redundant_prefix("connector"));
        assert!(is_redundant_prefix("connectors"));
    }

    #[test]
    fn fcp_is_redundant() {
        assert!(is_redundant_prefix("fcp"));
        assert!(is_redundant_prefix("flywheel"));
    }

    #[test]
    fn service_is_redundant() {
        assert!(is_redundant_prefix("service"));
        assert!(is_redundant_prefix("plugin"));
    }

    #[test]
    fn list_is_not_redundant() {
        assert!(!is_redundant_prefix("list"));
    }

    #[test]
    fn case_insensitive_prefix_detection() {
        assert!(is_redundant_prefix("Connector"));
        assert!(is_redundant_prefix("CONNECTOR"));
    }

    // ── dangerous_shape ─────────────────────────────────────────────────

    #[test]
    fn op_show_is_dangerous() {
        let args = ["fwc", "op", "show", "github", "issues.create"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        let shape = is_dangerous_shape(&args).unwrap();
        assert_eq!(shape.kind, "ambiguous-verb-object");
    }

    #[test]
    fn operation_show_is_dangerous() {
        let args = ["fwc", "operation", "show", "github"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        assert!(is_dangerous_shape(&args).is_some());
    }

    #[test]
    fn delete_is_dangerous() {
        let args = ["fwc", "delete", "github"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        let shape = is_dangerous_shape(&args).unwrap();
        assert_eq!(shape.kind, "destructive-ambiguity");
    }

    #[test]
    fn remove_is_dangerous() {
        let args = ["fwc", "remove", "slack"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        assert!(is_dangerous_shape(&args).is_some());
    }

    #[test]
    fn uninstall_is_dangerous() {
        let args = ["fwc", "uninstall", "github"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        assert!(is_dangerous_shape(&args).is_some());
    }

    #[test]
    fn force_flag_is_dangerous() {
        let args = ["fwc", "invoke", "--force", "github", "issues.create"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        let shape = is_dangerous_shape(&args).unwrap();
        assert_eq!(shape.kind, "unsupported-force-flag");
    }

    #[test]
    fn dash_f_flag_is_dangerous() {
        let args = ["fwc", "-f", "list"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        assert!(is_dangerous_shape(&args).is_some());
    }

    #[test]
    fn normal_command_is_not_dangerous() {
        let args = ["fwc", "list"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        assert!(is_dangerous_shape(&args).is_none());
    }

    #[test]
    fn show_command_is_not_dangerous() {
        let args = ["fwc", "show", "github"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        assert!(is_dangerous_shape(&args).is_none());
    }

    #[test]
    fn invoke_without_force_is_not_dangerous() {
        let args = ["fwc", "invoke", "github", "issues.create"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>();
        assert!(is_dangerous_shape(&args).is_none());
    }

    // ── Integration: resolve + safety ───────────────────────────────────

    #[test]
    fn all_aliases_resolve_to_known_canonical_commands() {
        let known = [
            "guide",
            "task",
            "plan",
            "explain",
            "do",
            "list",
            "search",
            "show",
            "ops",
            "schema",
            "examples",
            "template",
            "doctor",
            "status",
            "budget",
            "capabilities",
            "install",
            "update",
            "pin",
            "unpin",
            "config",
            "invoke",
            "simulate",
            "preflight",
        ];
        let test_aliases = [
            "info",
            "ls",
            "find",
            "run",
            "preview",
            "dry-run",
            "upgrade",
            "configure",
            "add",
            "lock",
            "unlock",
            "call",
            "tasks",
            "compile",
            "why",
            "query",
            "operations",
            "sample",
            "health",
            "contract",
            "capsule",
            "grep",
            "lookup",
            "op",
            "actions",
            "methods",
            "spec",
            "template",
            "check",
            "setup",
            "freeze",
            "unfreeze",
            "exec",
            "send",
            "request",
            "fire",
            "dryrun",
            "dry_run",
            "test-run",
            "taxonomy",
            "capsules",
            "parse",
            "reasoning",
            "rationale",
            "detail",
            "details",
            "get",
            "shape",
            "type",
            "types",
            "interface",
            "samples",
            "templates",
            "state",
            "healthcheck",
            "diagnose",
            "budgets",
            "caps",
            "settings",
            "prefs",
            "preferences",
            "apply",
            "materialize",
        ];
        for alias in test_aliases {
            let res = resolve_command(alias);
            assert!(
                res.is_some(),
                "alias `{alias}` did not resolve to any command"
            );
            let canonical = res.unwrap().canonical;
            assert!(
                known.contains(&canonical),
                "alias `{alias}` resolved to unknown command `{canonical}`"
            );
        }
    }

    #[test]
    fn all_typos_resolve_to_known_canonical_commands() {
        let known = [
            "guide",
            "task",
            "plan",
            "explain",
            "list",
            "search",
            "show",
            "ops",
            "schema",
            "examples",
            "template",
            "doctor",
            "status",
            "budget",
            "capabilities",
            "install",
            "update",
            "config",
            "invoke",
            "simulate",
            "preflight",
            "pin",
            "unpin",
        ];
        let test_typos = [
            "gudie",
            "taks",
            "paln",
            "expalin",
            "lsit",
            "serach",
            "shwo",
            "osp",
            "schmea",
            "exmaples",
            "docotr",
            "stauts",
            "budgte",
            "capabilties",
            "insatll",
            "udpate",
            "conifg",
            "invoe",
            "simlate",
            "pni",
            "unpni",
        ];
        for typo in test_typos {
            let res = resolve_command(typo);
            assert!(
                res.is_some(),
                "typo `{typo}` did not resolve to any command"
            );
            let canonical = res.unwrap().canonical;
            assert!(
                known.contains(&canonical),
                "typo `{typo}` resolved to unknown command `{canonical}`"
            );
        }
    }

    #[test]
    fn typo_to_readonly_is_safe_auto_correct() {
        let readonly_typos = [
            "gudie", "lsit", "serach", "shwo", "osp", "schmea", "exmaples", "stauts", "paln",
        ];
        for typo in readonly_typos {
            let res = resolve_command(typo).unwrap();
            assert_eq!(
                correction_safety(&res),
                CorrectionSafety::Safe,
                "typo `{typo}` → `{}` should be safe",
                res.canonical
            );
        }
    }

    #[test]
    fn typo_to_mutating_is_ambiguous_auto_correct() {
        let mutating_typos = ["insatll", "udpate", "invoe", "simlate"];
        for typo in mutating_typos {
            let res = resolve_command(typo).unwrap();
            let safety = correction_safety(&res);
            // simulate is readonly, so skip it from the mutating assertion
            if res.canonical == "simulate" {
                assert_eq!(safety, CorrectionSafety::Safe);
            } else {
                assert_eq!(
                    safety,
                    CorrectionSafety::Ambiguous,
                    "typo `{typo}` → `{}` should be ambiguous",
                    res.canonical
                );
            }
        }
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn empty_string_resolves_to_none() {
        assert!(resolve_command("").is_none());
    }

    #[test]
    fn numeric_token_resolves_to_none() {
        assert!(resolve_command("123").is_none());
    }

    #[test]
    fn very_long_token_resolves_to_none() {
        assert!(resolve_command("aaaaaaaaaaaaaaaaaaaaaaaaaaa").is_none());
    }

    #[test]
    fn special_characters_resolve_to_none() {
        assert!(resolve_command("--help").is_none());
        assert!(resolve_command("-v").is_none());
        assert!(resolve_command("@connector").is_none());
    }

    #[test]
    fn dangerous_shape_with_empty_args() {
        let args: Vec<String> = vec!["fwc".to_string()];
        assert!(is_dangerous_shape(&args).is_none());
    }

    #[test]
    fn closest_matches_empty_candidates() {
        let matches = closest_matches("foo", &[], 3, 5);
        assert!(matches.is_empty());
    }

    #[test]
    fn closest_matches_empty_value() {
        let candidates = &["list", "show"];
        let matches = closest_matches("", candidates, 3, 5);
        // All candidates are within distance 4-5, but max_distance is 3 — so only short ones match
        // Actually "list" has distance 4, "show" has distance 4 — both > 3
        // But "" is a prefix match of nothing, and nothing starts with ""
        // Actually every string starts with ""... let me check
        // `candidate.starts_with(value)` where value="" → always true
        assert!(!matches.is_empty());
    }

    #[test]
    fn levenshtein_unicode() {
        // Unicode characters should be handled correctly
        assert_eq!(levenshtein("café", "cafe"), 1);
    }

    #[test]
    fn levenshtein_symmetric() {
        assert_eq!(levenshtein("abc", "def"), levenshtein("def", "abc"));
        assert_eq!(levenshtein("show", "shwo"), levenshtein("shwo", "show"));
    }
}
