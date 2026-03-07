use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::intent::{self, CompiledIntent, IntentMode};

const TASK_SCHEMA_VERSION: u32 = 1;
const PAYLOAD_PLACEHOLDER: &str = "./intent-payload.json";
const TASK_SUBCOMMANDS: &[&str] = &[
    "create", "show", "list", "advance", "bind", "approve", "run",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowRequest {
    pub intent: String,
    pub connector_override: Option<String>,
    pub zone_override: Option<String>,
}

impl WorkflowRequest {
    #[must_use]
    pub fn compile(&self, approved: bool) -> CompiledIntent {
        intent::compile(&intent::IntentRequest {
            intent: self.intent.clone(),
            connector_override: self.connector_override.clone(),
            zone_override: self.zone_override.clone(),
            mode: if approved {
                IntentMode::DoApprove
            } else {
                IntentMode::DoSimulate
            },
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApprovalState {
    pub workflow: bool,
    pub approved_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub recorded_at: String,
    pub trigger: String,
    pub mode: String,
    pub status: String,
    pub executed_count: usize,
    pub withheld_count: usize,
    pub stopped_before_side_effect: bool,
    pub execution: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowTask {
    pub schema_version: u32,
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    pub capsule_status: String,
    pub request: WorkflowRequest,
    pub bindings: BTreeMap<String, String>,
    pub approval: ApprovalState,
    pub compiled: CompiledIntent,
    pub unresolved_bindings: Vec<String>,
    pub next_actions: Vec<String>,
    pub execution_history: Vec<ExecutionReceipt>,
}

impl WorkflowTask {
    #[must_use]
    pub fn has_side_effects(&self) -> bool {
        self.compiled.steps.iter().any(|step| step.side_effecting)
    }

    #[must_use]
    pub fn last_execution(&self) -> Option<&ExecutionReceipt> {
        self.execution_history.last()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskOverview {
    pub id: String,
    pub capsule_status: String,
    pub intent: String,
    pub chosen_connector: Option<String>,
    pub approval_required: bool,
    pub approved: bool,
    pub unresolved_bindings: usize,
    pub last_execution_status: Option<String>,
    pub updated_at: String,
}

#[derive(Clone, Debug)]
pub struct TaskStore {
    root_dir: PathBuf,
}

impl TaskStore {
    pub fn discover() -> Result<Self> {
        Ok(Self {
            root_dir: default_state_root()?,
        })
    }

    #[cfg(test)]
    #[must_use]
    pub const fn at_path(path: PathBuf) -> Self {
        Self { root_dir: path }
    }

    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn create(&self, request: WorkflowRequest) -> Result<WorkflowTask> {
        self.ensure_tasks_dir()?;

        let mut task = WorkflowTask {
            schema_version: TASK_SCHEMA_VERSION,
            id: self.allocate_task_id()?,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            capsule_status: "new".to_owned(),
            compiled: request.compile(false),
            request,
            bindings: BTreeMap::new(),
            approval: ApprovalState::default(),
            unresolved_bindings: Vec::new(),
            next_actions: Vec::new(),
            execution_history: Vec::new(),
        };
        recompute_task(&mut task, true);
        self.save(&task)?;
        Ok(task)
    }

    pub fn load(&self, task_id: &str) -> Result<Option<WorkflowTask>> {
        let path = self.task_path(task_id);
        if !path.exists() {
            return Ok(None);
        }

        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read workflow capsule `{task_id}`"))?;
        let mut task: WorkflowTask = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse workflow capsule `{task_id}`"))?;
        recompute_task(&mut task, false);
        Ok(Some(task))
    }

    pub fn list(&self, limit: usize, status_filter: Option<&str>) -> Result<Vec<TaskOverview>> {
        let tasks_dir = self.tasks_dir();
        if !tasks_dir.exists() {
            return Ok(Vec::new());
        }

        let mut tasks = fs::read_dir(&tasks_dir)
            .with_context(|| format!("failed to read task store `{}`", tasks_dir.display()))?
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(std::fs::FileType::is_file)
                    .filter(|_| {
                        entry
                            .path()
                            .extension()
                            .is_some_and(|ext| ext == std::ffi::OsStr::new("json"))
                    })
                    .map(|_| entry)
            })
            .filter_map(|entry| {
                let task_id = entry
                    .path()
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().replace('_', ":"))?;
                self.load(&task_id).ok().flatten()
            })
            .filter(|task| status_filter.is_none_or(|status| task.capsule_status == status))
            .map(|task| {
                let approval_required = task.has_side_effects();
                let last_execution_status =
                    task.last_execution().map(|receipt| receipt.status.clone());
                let unresolved_bindings = task.unresolved_bindings.len();
                TaskOverview {
                    id: task.id,
                    capsule_status: task.capsule_status,
                    intent: task.request.intent,
                    chosen_connector: task.compiled.chosen_connector.map(|candidate| candidate.id),
                    approval_required,
                    approved: task.approval.workflow,
                    unresolved_bindings,
                    last_execution_status,
                    updated_at: task.updated_at,
                }
            })
            .collect::<Vec<_>>();

        tasks.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
        tasks.truncate(limit);
        Ok(tasks)
    }

    pub fn bind(
        &self,
        task_id: &str,
        bindings: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Option<WorkflowTask>> {
        let Some(mut task) = self.load(task_id)? else {
            return Ok(None);
        };

        for (key, value) in bindings {
            match key.as_str() {
                "connector" => task.request.connector_override = Some(value),
                "zone" => task.request.zone_override = Some(value),
                _ => {
                    task.bindings.insert(key, value);
                }
            }
        }

        recompute_task(&mut task, true);
        self.save(&task)?;
        Ok(Some(task))
    }

    pub fn approve(&self, task_id: &str) -> Result<Option<WorkflowTask>> {
        let Some(mut task) = self.load(task_id)? else {
            return Ok(None);
        };

        task.approval.workflow = true;
        task.approval.approved_at = Some(now_rfc3339());
        recompute_task(&mut task, true);
        self.save(&task)?;
        Ok(Some(task))
    }

    pub fn refresh(&self, task_id: &str) -> Result<Option<WorkflowTask>> {
        let Some(mut task) = self.load(task_id)? else {
            return Ok(None);
        };

        recompute_task(&mut task, true);
        self.save(&task)?;
        Ok(Some(task))
    }

    pub fn append_execution(
        &self,
        task_id: &str,
        trigger: &str,
        mode: &str,
        execution: Value,
    ) -> Result<Option<WorkflowTask>> {
        let Some(mut task) = self.load(task_id)? else {
            return Ok(None);
        };

        task.execution_history.push(ExecutionReceipt {
            recorded_at: now_rfc3339(),
            trigger: trigger.to_owned(),
            mode: mode.to_owned(),
            status: execution["status"].as_str().unwrap_or("unknown").to_owned(),
            executed_count: execution["executed_count"]
                .as_u64()
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or_default(),
            withheld_count: execution["withheld_count"]
                .as_u64()
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or_default(),
            stopped_before_side_effect: execution["stopped_before_side_effect"]
                .as_bool()
                .unwrap_or(false),
            execution,
        });
        recompute_task(&mut task, true);
        self.save(&task)?;
        Ok(Some(task))
    }

    fn allocate_task_id(&self) -> Result<String> {
        for _ in 0..8 {
            let candidate = format!("w:{}", &Uuid::new_v4().simple().to_string()[..8]);
            if !self.task_path(&candidate).exists() {
                return Ok(candidate);
            }
        }

        bail!("failed to allocate a unique workflow capsule id after multiple attempts")
    }

    fn save(&self, task: &WorkflowTask) -> Result<()> {
        self.ensure_tasks_dir()?;
        let final_path = self.task_path(&task.id);
        let temp_path = final_path.with_extension(format!("tmp.{}", Uuid::new_v4().simple()));
        let file = fs::File::create(&temp_path).with_context(|| {
            format!(
                "failed to create temporary workflow capsule file `{}`",
                temp_path.display()
            )
        })?;
        let mut writer = std::io::BufWriter::new(&file);
        serde_json::to_writer_pretty(&mut writer, task)
            .with_context(|| format!("failed to serialize workflow capsule `{}`", task.id))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        file.sync_all()?;
        fs::rename(&temp_path, &final_path).with_context(|| {
            format!(
                "failed to atomically persist workflow capsule `{}` to `{}`",
                task.id,
                final_path.display()
            )
        })?;
        Ok(())
    }

    fn ensure_tasks_dir(&self) -> Result<()> {
        fs::create_dir_all(self.tasks_dir()).with_context(|| {
            format!(
                "failed to create workflow task directory `{}`",
                self.tasks_dir().display()
            )
        })
    }

    fn task_path(&self, task_id: &str) -> PathBuf {
        self.tasks_dir()
            .join(format!("{}.json", task_id.replace(':', "_")))
    }

    fn tasks_dir(&self) -> PathBuf {
        self.root_dir.join("tasks")
    }
}

pub fn validate_binding_entries(entries: &[String]) -> Result<Vec<(String, String)>> {
    if entries.is_empty() {
        bail!("at least one `key=value` binding is required");
    }

    entries
        .iter()
        .map(|entry| {
            let Some((key, value)) = entry.split_once('=') else {
                bail!("binding `{entry}` is missing `=`; expected `key=value`")
            };
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                bail!("binding `{entry}` must include both a non-empty key and value");
            }
            Ok((key.to_owned(), value.to_owned()))
        })
        .collect()
}

pub const fn task_subcommands() -> &'static [&'static str] {
    TASK_SUBCOMMANDS
}

#[must_use]
pub fn effective_bindings(task: &WorkflowTask) -> BTreeMap<String, String> {
    let mut bindings = task.bindings.clone();
    if !bindings.contains_key("payload_json") && !bindings.contains_key("payload_file") {
        if let Some(payload_json) = synthesized_payload_json(&task.compiled) {
            bindings.insert("payload_json".to_owned(), payload_json);
        }
    }
    bindings
}

fn recompute_task(task: &mut WorkflowTask, touch_updated_at: bool) {
    task.compiled = task.request.compile(task.approval.workflow);
    let effective_bindings = effective_bindings(task);
    apply_binding_awareness(&mut task.compiled, &effective_bindings);
    task.unresolved_bindings = unresolved_bindings(&task.compiled, &effective_bindings);
    task.capsule_status = derive_capsule_status(task);
    task.next_actions = build_task_next_actions(task);
    if touch_updated_at {
        task.updated_at = now_rfc3339();
    }
}

fn derive_capsule_status(task: &WorkflowTask) -> String {
    if task.compiled.status != "ready" {
        return task.compiled.status.clone();
    }

    if !task.unresolved_bindings.is_empty() {
        return "needs-bindings".to_owned();
    }

    if let Some(last) = task.last_execution() {
        if last.status == "stopped-on-primitive-error" {
            return "execution-error".to_owned();
        }
        if last.mode == "approve" && last.status == "materialized" {
            return "materialized".to_owned();
        }
        if last.mode == "simulate" && last.status == "simulated" {
            return if task.has_side_effects() {
                "ready-to-approve".to_owned()
            } else {
                "simulated".to_owned()
            };
        }
    }

    if task.has_side_effects() && task.approval.workflow {
        return "approved".to_owned();
    }

    if task.has_side_effects() {
        "ready-to-simulate".to_owned()
    } else {
        "ready".to_owned()
    }
}

fn build_task_next_actions(task: &WorkflowTask) -> Vec<String> {
    let mut actions = Vec::new();

    if task.compiled.status != "ready" {
        actions.extend(task.compiled.next_actions.iter().take(4).cloned());
        if task.compiled.status == "ambiguous" {
            actions.push(format!(
                "Bind a connector explicitly with `fwc task bind {} connector=<id>`.",
                task.id
            ));
        }
        actions.push(format!(
            "Inspect the current capsule state with `fwc task show {}`.",
            task.id
        ));
        return dedup(actions);
    }

    if !task.unresolved_bindings.is_empty() {
        let example_bindings = task
            .unresolved_bindings
            .iter()
            .take(2)
            .map(|name| format!("{name}=..."))
            .collect::<Vec<_>>()
            .join(" ");
        actions.push(format!(
            "Bind the missing values with `fwc task bind {} {}`.",
            task.id, example_bindings
        ));
    }

    if task.execution_history.is_empty() {
        actions.push(format!(
            "Run `fwc task advance {}` to materialize the next safe step.",
            task.id
        ));
    }

    if task.has_side_effects() && !task.approval.workflow {
        actions.push(format!(
            "Approve the capsule with `fwc task approve {}` before `run`.",
            task.id
        ));
    }

    if !task.has_side_effects() || task.approval.workflow {
        actions.push(format!(
            "Run `fwc task run {}` to execute the current capsule workflow.",
            task.id
        ));
    }

    actions.push(format!(
        "Inspect the latest capsule state with `fwc task show {}`.",
        task.id
    ));
    actions.extend(task.compiled.next_actions.iter().take(2).cloned());
    dedup(actions)
}

fn unresolved_bindings(
    compiled: &CompiledIntent,
    bindings: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut unresolved = BTreeSet::new();

    for step in &compiled.steps {
        let mut index = 0;
        while index < step.argv.len() {
            if step.argv[index] == "--file"
                && step
                    .argv
                    .get(index + 1)
                    .is_some_and(|value| value == PAYLOAD_PLACEHOLDER)
                && !bindings.contains_key("payload_file")
                && !bindings.contains_key("payload_json")
            {
                unresolved.insert("payload_file".to_owned());
            }

            if let Some(name) = placeholder_name(&step.argv[index]) {
                unresolved.insert(name.to_owned());
            }
            index += 1;
        }
    }

    unresolved.into_iter().collect()
}

fn apply_binding_awareness(compiled: &mut CompiledIntent, bindings: &BTreeMap<String, String>) {
    if bindings.contains_key("payload_json") || bindings.contains_key("payload_file") {
        compiled
            .missing_information
            .retain(|message| !payload_related_message(message));
    }

    compiled.status = if !compiled.ambiguities.is_empty() {
        "ambiguous".to_owned()
    } else if compiled.chosen_connector.is_some() && compiled.missing_information.is_empty() {
        "ready".to_owned()
    } else {
        "needs-clarification".to_owned()
    };
}

fn payload_related_message(message: &str) -> bool {
    let message = message.to_lowercase();
    message.contains("payload")
        || message.contains("message body")
        || message.contains("comment body")
        || message.contains("issue title")
        || message.contains("content that should be appended")
}

fn synthesized_payload_json(compiled: &CompiledIntent) -> Option<String> {
    let payload = compiled.payload_literal.as_deref()?;
    let body = match (
        compiled.action.verb.as_str(),
        compiled.action.resource.as_deref().unwrap_or("object"),
    ) {
        ("create", "issue") => json!({ "title": payload }),
        ("send", "message") => json!({ "text": payload }),
        ("comment", _) => json!({ "body": payload }),
        ("append", "page") => json!({ "content": payload }),
        _ => json!({ "input": payload }),
    };

    serde_json::to_string(&body).ok()
}

fn dedup(actions: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    actions
        .into_iter()
        .filter(|action| seen.insert(action.clone()))
        .collect()
}

fn default_state_root() -> Result<PathBuf> {
    if let Some(override_dir) = env::var_os("FWC_STATE_DIR") {
        return Ok(PathBuf::from(override_dir));
    }

    #[cfg(test)]
    if let Some(tmpdir) = env::var_os("CARGO_TARGET_TMPDIR") {
        return Ok(PathBuf::from(tmpdir).join(format!("fwc-tests-{}", std::process::id())));
    }

    if let Some(state_home) = env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(state_home).join("fwc"));
    }

    if let Some(home) = env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".local").join("state").join("fwc"));
    }

    env::current_dir()
        .map(|cwd| cwd.join(".fwc-state"))
        .context("failed to derive a default workflow capsule state directory")
}

fn placeholder_name(segment: &str) -> Option<&str> {
    segment.strip_prefix('<')?.strip_suffix('>')
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::{TaskStore, WorkflowRequest, validate_binding_entries};
    use serde_json::json;
    use uuid::Uuid;

    fn store() -> TaskStore {
        TaskStore::at_path(
            std::env::temp_dir().join(format!("fwc-workflow-tests-{}", Uuid::new_v4())),
        )
    }

    #[test]
    fn create_persists_and_reloads_capsule() {
        let store = store();
        let created = store
            .create(WorkflowRequest {
                intent: "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let reloaded = store
            .load(&created.id)
            .expect("load should succeed")
            .expect("task should exist");

        assert_eq!(reloaded.id, created.id);
        assert_eq!(
            reloaded
                .compiled
                .chosen_connector
                .map(|candidate| candidate.id),
            Some("github".to_owned())
        );
        assert_eq!(reloaded.capsule_status, "ready-to-simulate");
    }

    #[test]
    fn bind_updates_overrides_and_unresolved_bindings() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "send a message to a channel".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let rebound = store
            .bind(
                &task.id,
                vec![
                    ("connector".to_owned(), "slack".to_owned()),
                    ("payload_json".to_owned(), "{\"text\":\"hello\"}".to_owned()),
                ],
            )
            .expect("bind should succeed")
            .expect("task should exist");

        assert_eq!(rebound.request.connector_override.as_deref(), Some("slack"));
        assert_eq!(rebound.compiled.status, "ready");
        assert!(rebound.unresolved_bindings.is_empty());
    }

    #[test]
    fn append_execution_updates_capsule_status() {
        let store = store();
        let task = store
            .create(WorkflowRequest {
                intent: "disable the slack connector in z:work".to_owned(),
                connector_override: None,
                zone_override: None,
            })
            .expect("task should be created");

        let updated = store
            .append_execution(
                &task.id,
                "advance",
                "simulate",
                json!({
                    "status": "simulated",
                    "executed_count": 1,
                    "withheld_count": 2,
                    "stopped_before_side_effect": true,
                }),
            )
            .expect("execution receipt should persist")
            .expect("task should exist");

        assert_eq!(updated.capsule_status, "ready-to-approve");
        assert_eq!(updated.execution_history.len(), 1);
    }

    #[test]
    fn binding_validation_rejects_malformed_entries() {
        let error = validate_binding_entries(&["payload_json".to_owned()])
            .expect_err("missing equals sign should fail");
        assert!(error.to_string().contains("expected `key=value`"));
    }
}
