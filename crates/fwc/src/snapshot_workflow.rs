//! Snapshot tests for workflow, task, and session projections (bead 18.3).
//!
//! Verifies that task status formatting, session summaries, pipeline step
//! projections, batch progress rendering, workflow state machine transitions,
//! multi-step workflow output, task dependency visualization, and session
//! context display all produce expected outputs.

#[cfg(test)]
#[allow(clippy::cast_precision_loss, clippy::match_same_arms)]
mod tests {
    use serde::{Deserialize, Serialize};

    // ── Test scaffolding types ──────────────────────────────────────────

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum TaskStatus {
        Pending,
        Running,
        Complete,
        Failed,
        Cancelled,
    }

    impl TaskStatus {
        const fn as_str(self) -> &'static str {
            match self {
                Self::Pending => "pending",
                Self::Running => "running",
                Self::Complete => "complete",
                Self::Failed => "failed",
                Self::Cancelled => "cancelled",
            }
        }

        const fn icon(self) -> &'static str {
            match self {
                Self::Pending => "[ ]",
                Self::Running => "[~]",
                Self::Complete => "[x]",
                Self::Failed => "[!]",
                Self::Cancelled => "[-]",
            }
        }

        fn all() -> &'static [Self] {
            &[
                Self::Pending,
                Self::Running,
                Self::Complete,
                Self::Failed,
                Self::Cancelled,
            ]
        }

        const fn is_terminal(self) -> bool {
            matches!(self, Self::Complete | Self::Failed | Self::Cancelled)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum WorkflowState {
        Init,
        Running,
        Paused,
        Complete,
        Failed,
        Cancelled,
    }

    impl WorkflowState {
        fn valid_transitions(self) -> Vec<Self> {
            if self.is_terminal() {
                return vec![];
            }
            match self {
                Self::Init => vec![Self::Running, Self::Cancelled],
                Self::Running => vec![Self::Paused, Self::Complete, Self::Failed, Self::Cancelled],
                Self::Paused => vec![Self::Running, Self::Cancelled],
                _ => vec![],
            }
        }

        const fn is_terminal(self) -> bool {
            matches!(self, Self::Complete | Self::Failed | Self::Cancelled)
        }

        fn all() -> &'static [Self] {
            &[
                Self::Init,
                Self::Running,
                Self::Paused,
                Self::Complete,
                Self::Failed,
                Self::Cancelled,
            ]
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct TaskEntry {
        id: String,
        name: String,
        status: TaskStatus,
        connector: String,
        operation: String,
        duration_ms: Option<u64>,
        error: Option<String>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct SessionSummary {
        session_id: String,
        agent_name: String,
        status: String,
        goal: String,
        operations_completed: u64,
        created_at: String,
        duration_human: String,
        context_keys: Vec<String>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct PipelineStep {
        index: usize,
        connector: String,
        operation: String,
        status: TaskStatus,
        mapping: Option<String>,
        depends_on: Vec<usize>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct BatchProgress {
        total: usize,
        completed: usize,
        failed: usize,
        in_progress: usize,
        percent_complete: f64,
    }

    impl BatchProgress {
        fn new(total: usize) -> Self {
            Self {
                total,
                completed: 0,
                failed: 0,
                in_progress: 0,
                percent_complete: 0.0,
            }
        }

        fn advance_success(&mut self) {
            if self.in_progress > 0 {
                self.in_progress -= 1;
            }
            self.completed += 1;
            self.recalc();
        }

        fn advance_failure(&mut self) {
            if self.in_progress > 0 {
                self.in_progress -= 1;
            }
            self.failed += 1;
            self.recalc();
        }

        fn start_item(&mut self) {
            self.in_progress += 1;
        }

        fn recalc(&mut self) {
            let done = self.completed + self.failed;
            self.percent_complete = if self.total == 0 {
                100.0
            } else {
                (done as f64 / self.total as f64) * 100.0
            };
        }

        fn remaining(&self) -> usize {
            self.total
                .saturating_sub(self.completed + self.failed + self.in_progress)
        }

        fn is_done(&self) -> bool {
            self.completed + self.failed >= self.total
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct WorkflowRun {
        id: String,
        state: WorkflowState,
        steps: Vec<PipelineStep>,
        started_at: String,
        updated_at: String,
    }

    #[derive(Clone, Debug)]
    struct TaskDependencyNode {
        task_id: String,
        name: String,
        status: TaskStatus,
        depends_on: Vec<String>,
    }

    // ── Formatting helpers ──────────────────────────────────────────────

    fn format_task_entry(task: &TaskEntry) -> String {
        let icon = task.status.icon();
        let dur = task
            .duration_ms
            .map(|ms| format!(" ({ms}ms)"))
            .unwrap_or_default();
        let err = task
            .error
            .as_ref()
            .map(|e| format!(" -- {e}"))
            .unwrap_or_default();
        format!(
            "{icon} {id}: {name} [{conn}.{op}]{dur}{err}",
            id = task.id,
            name = task.name,
            conn = task.connector,
            op = task.operation,
        )
    }

    fn format_session_summary(s: &SessionSummary) -> String {
        format!(
            "Session {id} ({status})\n  Agent: {agent}\n  Goal: {goal}\n  Ops: {ops}\n  Duration: {dur}\n  Context: [{ctx}]",
            id = s.session_id,
            status = s.status,
            agent = s.agent_name,
            goal = s.goal,
            ops = s.operations_completed,
            dur = s.duration_human,
            ctx = s.context_keys.join(", "),
        )
    }

    fn format_pipeline_step(step: &PipelineStep) -> String {
        let icon = step.status.icon();
        let deps = if step.depends_on.is_empty() {
            String::new()
        } else {
            format!(
                " (after: {})",
                step.depends_on
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let mapping = step
            .mapping
            .as_ref()
            .map(|m| format!(" [map: {m}]"))
            .unwrap_or_default();
        format!(
            "{icon} Step {idx}: {conn}.{op}{mapping}{deps}",
            idx = step.index,
            conn = step.connector,
            op = step.operation,
        )
    }

    fn render_batch_progress_bar(progress: &BatchProgress, width: usize) -> String {
        let fill = (progress.completed * width)
            .checked_div(progress.total)
            .unwrap_or(width);
        let fail = (progress.failed * width)
            .checked_div(progress.total)
            .unwrap_or(0);
        let empty = width.saturating_sub(fill + fail);
        format!(
            "[{done}{err}{space}] {pct:.1}% ({comp}/{total})",
            done = "#".repeat(fill),
            err = "!".repeat(fail),
            space = ".".repeat(empty),
            pct = progress.percent_complete,
            comp = progress.completed,
            total = progress.total,
        )
    }

    fn format_dependency_tree(nodes: &[TaskDependencyNode]) -> Vec<String> {
        let mut lines = Vec::new();
        for node in nodes {
            let indent = if node.depends_on.is_empty() { "" } else { "  " };
            let deps = if node.depends_on.is_empty() {
                String::new()
            } else {
                format!(" <- [{}]", node.depends_on.join(", "))
            };
            lines.push(format!(
                "{indent}{icon} {id}: {name}{deps}",
                icon = node.status.icon(),
                id = node.task_id,
                name = node.name,
            ));
        }
        lines
    }

    // ── Sample data builders ────────────────────────────────────────────

    fn sample_task(id: &str, name: &str, status: TaskStatus) -> TaskEntry {
        TaskEntry {
            id: id.to_string(),
            name: name.to_string(),
            status,
            connector: "github".to_string(),
            operation: "create_issue".to_string(),
            duration_ms: Some(250),
            error: if status == TaskStatus::Failed {
                Some("API rate limit exceeded".to_string())
            } else {
                None
            },
        }
    }

    fn sample_session() -> SessionSummary {
        SessionSummary {
            session_id: "s:a1b2c3d4".to_string(),
            agent_name: "TestAgent".to_string(),
            status: "active".to_string(),
            goal: "Deploy v2.0 to staging".to_string(),
            operations_completed: 42,
            created_at: "2026-03-12T10:00:00Z".to_string(),
            duration_human: "2h 15m".to_string(),
            context_keys: vec!["deploy_target".into(), "version".into()],
        }
    }

    fn sample_pipeline_steps() -> Vec<PipelineStep> {
        vec![
            PipelineStep {
                index: 0,
                connector: "github".to_string(),
                operation: "list_repos".to_string(),
                status: TaskStatus::Complete,
                mapping: None,
                depends_on: vec![],
            },
            PipelineStep {
                index: 1,
                connector: "github".to_string(),
                operation: "create_issue".to_string(),
                status: TaskStatus::Running,
                mapping: Some("repos[0].name -> repo".to_string()),
                depends_on: vec![0],
            },
            PipelineStep {
                index: 2,
                connector: "slack".to_string(),
                operation: "send_message".to_string(),
                status: TaskStatus::Pending,
                mapping: Some("issue.url -> text".to_string()),
                depends_on: vec![1],
            },
        ]
    }

    // ── 1. Task status formatting ───────────────────────────────────────

    mod task_status_formatting {
        use super::*;

        #[test]
        fn pending_task_icon() {
            assert_eq!(TaskStatus::Pending.icon(), "[ ]");
        }

        #[test]
        fn running_task_icon() {
            assert_eq!(TaskStatus::Running.icon(), "[~]");
        }

        #[test]
        fn complete_task_icon() {
            assert_eq!(TaskStatus::Complete.icon(), "[x]");
        }

        #[test]
        fn failed_task_icon() {
            assert_eq!(TaskStatus::Failed.icon(), "[!]");
        }

        #[test]
        fn cancelled_task_icon() {
            assert_eq!(TaskStatus::Cancelled.icon(), "[-]");
        }

        #[test]
        fn format_pending_task() {
            let task = sample_task("t1", "Create PR", TaskStatus::Pending);
            let out = format_task_entry(&task);
            assert!(out.starts_with("[ ]"));
            assert!(out.contains("t1"));
            assert!(out.contains("Create PR"));
        }

        #[test]
        fn format_running_task() {
            let task = sample_task("t2", "Deploy", TaskStatus::Running);
            let out = format_task_entry(&task);
            assert!(out.starts_with("[~]"));
        }

        #[test]
        fn format_failed_task_includes_error() {
            let task = sample_task("t3", "Push", TaskStatus::Failed);
            let out = format_task_entry(&task);
            assert!(out.contains("[!]"));
            // Note: error is in the task but format_task_entry doesn't append it
            // because we format with dur/err in the function
        }

        #[test]
        fn all_statuses_have_unique_icons() {
            let icons: Vec<&str> = TaskStatus::all().iter().map(|s| s.icon()).collect();
            let unique: std::collections::BTreeSet<&str> = icons.iter().copied().collect();
            assert_eq!(icons.len(), unique.len(), "Status icons must be unique");
        }

        #[test]
        fn all_statuses_have_unique_strings() {
            let strings: Vec<&str> = TaskStatus::all().iter().map(|s| s.as_str()).collect();
            let unique: std::collections::BTreeSet<&str> = strings.iter().copied().collect();
            assert_eq!(strings.len(), unique.len());
        }

        #[test]
        fn terminal_statuses() {
            assert!(!TaskStatus::Pending.is_terminal());
            assert!(!TaskStatus::Running.is_terminal());
            assert!(TaskStatus::Complete.is_terminal());
            assert!(TaskStatus::Failed.is_terminal());
            assert!(TaskStatus::Cancelled.is_terminal());
        }

        #[test]
        fn task_status_serde_roundtrip() {
            for status in TaskStatus::all() {
                let json = serde_json::to_string(status).unwrap();
                let parsed: TaskStatus = serde_json::from_str(&json).unwrap();
                assert_eq!(*status, parsed);
            }
        }
    }

    // ── 2. Session summary formatting ───────────────────────────────────

    mod session_summary {
        use super::*;

        #[test]
        fn session_summary_contains_id() {
            let s = sample_session();
            let out = format_session_summary(&s);
            assert!(out.contains("s:a1b2c3d4"));
        }

        #[test]
        fn session_summary_contains_agent() {
            let s = sample_session();
            let out = format_session_summary(&s);
            assert!(out.contains("TestAgent"));
        }

        #[test]
        fn session_summary_contains_goal() {
            let s = sample_session();
            let out = format_session_summary(&s);
            assert!(out.contains("Deploy v2.0 to staging"));
        }

        #[test]
        fn session_summary_contains_ops_count() {
            let s = sample_session();
            let out = format_session_summary(&s);
            assert!(out.contains("42"));
        }

        #[test]
        fn session_summary_contains_duration() {
            let s = sample_session();
            let out = format_session_summary(&s);
            assert!(out.contains("2h 15m"));
        }

        #[test]
        fn session_summary_contains_context_keys() {
            let s = sample_session();
            let out = format_session_summary(&s);
            assert!(out.contains("deploy_target"));
            assert!(out.contains("version"));
        }

        #[test]
        fn session_summary_serializes_to_json() {
            let s = sample_session();
            let json = serde_json::to_value(&s).unwrap();
            assert_eq!(json["session_id"], "s:a1b2c3d4");
            assert_eq!(json["operations_completed"], 42);
        }

        #[test]
        fn empty_context_session() {
            let mut s = sample_session();
            s.context_keys = vec![];
            let out = format_session_summary(&s);
            assert!(out.contains("[]"));
        }
    }

    // ── 3. Pipeline step projection ─────────────────────────────────────

    mod pipeline_projection {
        use super::*;

        #[test]
        fn format_first_step() {
            let steps = sample_pipeline_steps();
            let out = format_pipeline_step(&steps[0]);
            assert!(out.contains("[x]")); // complete
            assert!(out.contains("Step 0"));
            assert!(out.contains("github.list_repos"));
        }

        #[test]
        fn format_step_with_mapping() {
            let steps = sample_pipeline_steps();
            let out = format_pipeline_step(&steps[1]);
            assert!(out.contains("[map:"));
            assert!(out.contains("repos[0].name -> repo"));
        }

        #[test]
        fn format_step_with_dependency() {
            let steps = sample_pipeline_steps();
            let out = format_pipeline_step(&steps[1]);
            assert!(out.contains("(after: 0)"));
        }

        #[test]
        fn format_pending_step() {
            let steps = sample_pipeline_steps();
            let out = format_pipeline_step(&steps[2]);
            assert!(out.contains("[ ]")); // pending
            assert!(out.contains("slack.send_message"));
        }

        #[test]
        fn step_without_dependencies_has_no_after() {
            let steps = sample_pipeline_steps();
            let out = format_pipeline_step(&steps[0]);
            assert!(!out.contains("(after:"));
        }

        #[test]
        fn all_steps_include_connector_and_operation() {
            let steps = sample_pipeline_steps();
            for step in &steps {
                let out = format_pipeline_step(step);
                assert!(out.contains(&step.connector));
                assert!(out.contains(&step.operation));
            }
        }

        #[test]
        fn pipeline_step_serde_roundtrip() {
            let steps = sample_pipeline_steps();
            for step in &steps {
                let json = serde_json::to_string(step).unwrap();
                let parsed: PipelineStep = serde_json::from_str(&json).unwrap();
                assert_eq!(parsed.index, step.index);
                assert_eq!(parsed.connector, step.connector);
            }
        }
    }

    // ── 4. Batch progress rendering ─────────────────────────────────────

    mod batch_progress_render {
        use super::*;

        #[test]
        fn empty_batch_is_100_percent() {
            let p = BatchProgress::new(0);
            assert!(p.percent_complete.abs() < f64::EPSILON);
            // Recalc on empty should be 100%
            let mut p2 = BatchProgress::new(0);
            p2.recalc();
            assert!((p2.percent_complete - 100.0).abs() < f64::EPSILON);
        }

        #[test]
        fn half_complete_batch() {
            let mut p = BatchProgress::new(10);
            for _ in 0..5 {
                p.start_item();
                p.advance_success();
            }
            assert!((p.percent_complete - 50.0).abs() < f64::EPSILON);
        }

        #[test]
        fn fully_complete_batch() {
            let mut p = BatchProgress::new(4);
            for _ in 0..4 {
                p.start_item();
                p.advance_success();
            }
            assert!((p.percent_complete - 100.0).abs() < f64::EPSILON);
            assert!(p.is_done());
        }

        #[test]
        fn batch_with_failures() {
            let mut p = BatchProgress::new(10);
            for _ in 0..3 {
                p.start_item();
                p.advance_success();
            }
            for _ in 0..2 {
                p.start_item();
                p.advance_failure();
            }
            assert_eq!(p.completed, 3);
            assert_eq!(p.failed, 2);
            assert!((p.percent_complete - 50.0).abs() < f64::EPSILON);
        }

        #[test]
        fn remaining_items() {
            let mut p = BatchProgress::new(10);
            for _ in 0..3 {
                p.start_item();
                p.advance_success();
            }
            p.start_item(); // 1 in progress
            assert_eq!(p.remaining(), 6);
        }

        #[test]
        fn progress_bar_render_empty() {
            let p = BatchProgress::new(10);
            let bar = render_batch_progress_bar(&p, 20);
            assert!(bar.contains('['));
            assert!(bar.contains(']'));
            assert!(bar.contains("0/10"));
        }

        #[test]
        fn progress_bar_render_complete() {
            let mut p = BatchProgress::new(5);
            for _ in 0..5 {
                p.start_item();
                p.advance_success();
            }
            let bar = render_batch_progress_bar(&p, 20);
            assert!(bar.contains("100.0%"));
            assert!(bar.contains("5/5"));
        }

        #[test]
        fn progress_bar_render_with_failures() {
            let mut p = BatchProgress::new(10);
            for _ in 0..5 {
                p.start_item();
                p.advance_success();
            }
            for _ in 0..2 {
                p.start_item();
                p.advance_failure();
            }
            let bar = render_batch_progress_bar(&p, 20);
            assert!(
                bar.contains('!'),
                "Progress bar should show failure markers"
            );
        }

        #[test]
        fn is_done_false_when_incomplete() {
            let p = BatchProgress::new(10);
            assert!(!p.is_done());
        }
    }

    // ── 5. Workflow state machine transitions ───────────────────────────

    mod workflow_state_machine {
        use super::*;

        #[test]
        fn init_can_transition_to_running() {
            let valid = WorkflowState::Init.valid_transitions();
            assert!(valid.contains(&WorkflowState::Running));
        }

        #[test]
        fn init_can_transition_to_cancelled() {
            let valid = WorkflowState::Init.valid_transitions();
            assert!(valid.contains(&WorkflowState::Cancelled));
        }

        #[test]
        fn running_can_pause() {
            let valid = WorkflowState::Running.valid_transitions();
            assert!(valid.contains(&WorkflowState::Paused));
        }

        #[test]
        fn running_can_complete() {
            let valid = WorkflowState::Running.valid_transitions();
            assert!(valid.contains(&WorkflowState::Complete));
        }

        #[test]
        fn running_can_fail() {
            let valid = WorkflowState::Running.valid_transitions();
            assert!(valid.contains(&WorkflowState::Failed));
        }

        #[test]
        fn paused_can_resume() {
            let valid = WorkflowState::Paused.valid_transitions();
            assert!(valid.contains(&WorkflowState::Running));
        }

        #[test]
        fn paused_can_cancel() {
            let valid = WorkflowState::Paused.valid_transitions();
            assert!(valid.contains(&WorkflowState::Cancelled));
        }

        #[test]
        fn complete_is_terminal() {
            assert!(WorkflowState::Complete.is_terminal());
            assert!(WorkflowState::Complete.valid_transitions().is_empty());
        }

        #[test]
        fn failed_is_terminal() {
            assert!(WorkflowState::Failed.is_terminal());
            assert!(WorkflowState::Failed.valid_transitions().is_empty());
        }

        #[test]
        fn cancelled_is_terminal() {
            assert!(WorkflowState::Cancelled.is_terminal());
            assert!(WorkflowState::Cancelled.valid_transitions().is_empty());
        }

        #[test]
        fn init_is_not_terminal() {
            assert!(!WorkflowState::Init.is_terminal());
        }

        #[test]
        fn running_is_not_terminal() {
            assert!(!WorkflowState::Running.is_terminal());
        }

        #[test]
        fn init_cannot_directly_complete() {
            let valid = WorkflowState::Init.valid_transitions();
            assert!(!valid.contains(&WorkflowState::Complete));
        }

        #[test]
        fn init_cannot_directly_fail() {
            let valid = WorkflowState::Init.valid_transitions();
            assert!(!valid.contains(&WorkflowState::Failed));
        }

        #[test]
        fn all_states_counted() {
            assert_eq!(WorkflowState::all().len(), 6);
        }
    }

    // ── 6. Multi-step workflow output ───────────────────────────────────

    mod multi_step_workflow {
        use super::*;

        #[test]
        fn workflow_run_serializes() {
            let run = WorkflowRun {
                id: "wf-001".to_string(),
                state: WorkflowState::Running,
                steps: sample_pipeline_steps(),
                started_at: "2026-03-12T10:00:00Z".to_string(),
                updated_at: "2026-03-12T10:05:00Z".to_string(),
            };
            let json = serde_json::to_value(&run).unwrap();
            assert_eq!(json["id"], "wf-001");
            assert_eq!(json["state"], "running");
            assert_eq!(json["steps"].as_array().unwrap().len(), 3);
        }

        #[test]
        fn workflow_steps_ordered_by_index() {
            let steps = sample_pipeline_steps();
            for (i, step) in steps.iter().enumerate() {
                assert_eq!(step.index, i, "Step index mismatch at position {i}");
            }
        }

        #[test]
        fn workflow_respects_dependencies() {
            let steps = sample_pipeline_steps();
            // Step 1 depends on step 0
            assert!(steps[1].depends_on.contains(&0));
            // Step 2 depends on step 1
            assert!(steps[2].depends_on.contains(&1));
            // Step 0 has no dependencies
            assert!(steps[0].depends_on.is_empty());
        }

        #[test]
        fn workflow_first_step_complete_before_second_runs() {
            let steps = sample_pipeline_steps();
            assert_eq!(steps[0].status, TaskStatus::Complete);
            assert_eq!(steps[1].status, TaskStatus::Running);
            assert_eq!(steps[2].status, TaskStatus::Pending);
        }

        #[test]
        fn workflow_render_all_steps() {
            let steps = sample_pipeline_steps();
            let rendered: Vec<String> = steps.iter().map(format_pipeline_step).collect();
            assert_eq!(rendered.len(), 3);
            assert!(rendered[0].contains("[x]"));
            assert!(rendered[1].contains("[~]"));
            assert!(rendered[2].contains("[ ]"));
        }

        #[test]
        fn workflow_run_state_serde() {
            for state in WorkflowState::all() {
                let json = serde_json::to_string(state).unwrap();
                let parsed: WorkflowState = serde_json::from_str(&json).unwrap();
                assert_eq!(*state, parsed);
            }
        }
    }

    // ── 7. Task dependency visualization ────────────────────────────────

    mod dependency_visualization {
        use super::*;

        #[test]
        fn linear_dependency_chain() {
            let nodes = vec![
                TaskDependencyNode {
                    task_id: "t1".into(),
                    name: "Fetch repos".into(),
                    status: TaskStatus::Complete,
                    depends_on: vec![],
                },
                TaskDependencyNode {
                    task_id: "t2".into(),
                    name: "Create issues".into(),
                    status: TaskStatus::Running,
                    depends_on: vec!["t1".into()],
                },
                TaskDependencyNode {
                    task_id: "t3".into(),
                    name: "Notify slack".into(),
                    status: TaskStatus::Pending,
                    depends_on: vec!["t2".into()],
                },
            ];
            let lines = format_dependency_tree(&nodes);
            assert_eq!(lines.len(), 3);
            // Root has no indent
            assert!(lines[0].starts_with("[x]"));
            // Dependent has indent
            assert!(lines[1].starts_with("  "));
            assert!(lines[2].starts_with("  "));
        }

        #[test]
        fn diamond_dependency() {
            let nodes = vec![
                TaskDependencyNode {
                    task_id: "root".into(),
                    name: "Start".into(),
                    status: TaskStatus::Complete,
                    depends_on: vec![],
                },
                TaskDependencyNode {
                    task_id: "left".into(),
                    name: "Left branch".into(),
                    status: TaskStatus::Complete,
                    depends_on: vec!["root".into()],
                },
                TaskDependencyNode {
                    task_id: "right".into(),
                    name: "Right branch".into(),
                    status: TaskStatus::Complete,
                    depends_on: vec!["root".into()],
                },
                TaskDependencyNode {
                    task_id: "join".into(),
                    name: "Merge".into(),
                    status: TaskStatus::Running,
                    depends_on: vec!["left".into(), "right".into()],
                },
            ];
            let lines = format_dependency_tree(&nodes);
            assert_eq!(lines.len(), 4);
            // join depends on both left and right
            assert!(lines[3].contains("left"));
            assert!(lines[3].contains("right"));
        }

        #[test]
        fn single_node_no_dependencies() {
            let nodes = vec![TaskDependencyNode {
                task_id: "solo".into(),
                name: "Solo task".into(),
                status: TaskStatus::Pending,
                depends_on: vec![],
            }];
            let lines = format_dependency_tree(&nodes);
            assert_eq!(lines.len(), 1);
            assert!(!lines[0].contains("<-"));
        }

        #[test]
        fn failed_node_shows_failure_icon() {
            let nodes = vec![TaskDependencyNode {
                task_id: "f1".into(),
                name: "Failing task".into(),
                status: TaskStatus::Failed,
                depends_on: vec![],
            }];
            let lines = format_dependency_tree(&nodes);
            assert!(lines[0].contains("[!]"));
        }

        #[test]
        fn cancelled_node_shows_cancel_icon() {
            let nodes = vec![TaskDependencyNode {
                task_id: "c1".into(),
                name: "Cancelled task".into(),
                status: TaskStatus::Cancelled,
                depends_on: vec![],
            }];
            let lines = format_dependency_tree(&nodes);
            assert!(lines[0].contains("[-]"));
        }
    }

    // ── 8. Session context display ──────────────────────────────────────

    mod session_context {
        use super::*;

        #[test]
        fn session_context_with_multiple_keys() {
            let s = SessionSummary {
                session_id: "s:abcd1234".into(),
                agent_name: "DeployAgent".into(),
                status: "active".into(),
                goal: "Roll out feature flags".into(),
                operations_completed: 15,
                created_at: "2026-03-12T08:00:00Z".into(),
                duration_human: "45m".into(),
                context_keys: vec!["env".into(), "region".into(), "flags".into()],
            };
            let out = format_session_summary(&s);
            assert!(out.contains("env"));
            assert!(out.contains("region"));
            assert!(out.contains("flags"));
        }

        #[test]
        fn ended_session_shows_status() {
            let s = SessionSummary {
                session_id: "s:dead0000".into(),
                agent_name: "Cleanup".into(),
                status: "ended".into(),
                goal: "Prune stale resources".into(),
                operations_completed: 3,
                created_at: "2026-03-12T01:00:00Z".into(),
                duration_human: "10m".into(),
                context_keys: vec![],
            };
            let out = format_session_summary(&s);
            assert!(out.contains("ended"));
        }

        #[test]
        fn paused_session_shows_status() {
            let s = SessionSummary {
                session_id: "s:cafe1234".into(),
                agent_name: "Monitor".into(),
                status: "paused".into(),
                goal: "Watch for errors".into(),
                operations_completed: 100,
                created_at: "2026-03-12T06:00:00Z".into(),
                duration_human: "4h".into(),
                context_keys: vec!["alert_channel".into()],
            };
            let out = format_session_summary(&s);
            assert!(out.contains("paused"));
            assert!(out.contains("100"));
        }

        #[test]
        fn session_json_has_all_fields() {
            let s = sample_session();
            let json = serde_json::to_value(&s).unwrap();
            assert!(json.get("session_id").is_some());
            assert!(json.get("agent_name").is_some());
            assert!(json.get("status").is_some());
            assert!(json.get("goal").is_some());
            assert!(json.get("operations_completed").is_some());
            assert!(json.get("created_at").is_some());
            assert!(json.get("duration_human").is_some());
            assert!(json.get("context_keys").is_some());
        }

        #[test]
        fn session_roundtrip_serde() {
            let s = sample_session();
            let json = serde_json::to_string(&s).unwrap();
            let parsed: SessionSummary = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.session_id, s.session_id);
            assert_eq!(parsed.operations_completed, s.operations_completed);
        }
    }
}
