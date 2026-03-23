//! Apple Reminders process client based on `osascript`.

use std::process::Command;

use serde_json::{Value, json};

use crate::error::{AppleRemindersError, AppleRemindersResult};
use crate::types::AppleRemindersConfig;

const LIST_LISTS_SCRIPT: &str = r#"
tell application "Reminders"
  set outputLines to {}
  repeat with theList in lists
    set end of outputLines to ((id of theList as text) & tab & (name of theList as text))
  end repeat
  return outputLines as text
end tell
"#;

const LIST_REMINDERS_SCRIPT: &str = r#"
on run argv
  set requestedList to ""
  if (count of argv) ≥ 1 then set requestedList to item 1 of argv
  set outputLines to {}
  tell application "Reminders"
    repeat with theList in lists
      if requestedList is "" or (name of theList as text) is requestedList then
        repeat with theReminder in reminders of theList
          set dueText to ""
          if due date of theReminder is not missing value then set dueText to (due date of theReminder as text)
          set end of outputLines to ((id of theReminder as text) & tab & (name of theReminder as text) & tab & (name of theList as text) & tab & ((completed of theReminder) as text) & tab & dueText)
        end repeat
      end if
    end repeat
  end tell
  return outputLines as text
end run
"#;

const CREATE_REMINDER_SCRIPT: &str = r#"
on run argv
  set reminderTitle to item 1 of argv
  set requestedList to item 2 of argv
  tell application "Reminders"
    if requestedList is "" then
      set targetList to first list
    else
      set targetList to list requestedList
    end if
    set createdReminder to make new reminder at end of reminders of targetList with properties {name:reminderTitle}
    return (id of createdReminder as text) & tab & (name of createdReminder as text) & tab & (name of targetList as text)
  end tell
end run
"#;

const COMPLETE_REMINDER_SCRIPT: &str = r#"
on run argv
  set reminderId to item 1 of argv
  tell application "Reminders"
    repeat with theList in lists
      repeat with theReminder in reminders of theList
        if (id of theReminder as text) is reminderId then
          set completed of theReminder to true
          return (id of theReminder as text) & tab & (name of theReminder as text) & tab & "true"
        end if
      end repeat
    end repeat
  end tell
  error "Reminder not found"
end run
"#;

#[derive(Debug, Clone)]
pub struct ScriptInvocation {
    pub script: &'static str,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AppleRemindersClient {
    osascript_path: String,
    default_list: Option<String>,
}

impl AppleRemindersClient {
    pub fn from_config(config: &AppleRemindersConfig) -> AppleRemindersResult<Self> {
        Ok(Self {
            osascript_path: config.osascript_path.clone(),
            default_list: config.default_list.clone(),
        })
    }

    fn ensure_supported() -> AppleRemindersResult<()> {
        if std::env::consts::OS != "macos" {
            return Err(AppleRemindersError::UnsupportedPlatform(
                "Apple Reminders connector requires macOS".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn list_lists_invocation(&self) -> ScriptInvocation {
        ScriptInvocation {
            script: LIST_LISTS_SCRIPT,
            args: Vec::new(),
        }
    }

    #[must_use]
    pub fn list_reminders_invocation(&self, list_name: Option<&str>) -> ScriptInvocation {
        ScriptInvocation {
            script: LIST_REMINDERS_SCRIPT,
            args: vec![list_name.or(self.default_list.as_deref()).unwrap_or("").to_string()],
        }
    }

    #[must_use]
    pub fn create_reminder_invocation(&self, title: &str, list_name: Option<&str>) -> ScriptInvocation {
        ScriptInvocation {
            script: CREATE_REMINDER_SCRIPT,
            args: vec![
                title.to_string(),
                list_name.or(self.default_list.as_deref()).unwrap_or("").to_string(),
            ],
        }
    }

    #[must_use]
    pub fn complete_reminder_invocation(&self, reminder_id: &str) -> ScriptInvocation {
        ScriptInvocation {
            script: COMPLETE_REMINDER_SCRIPT,
            args: vec![reminder_id.to_string()],
        }
    }

    fn run_invocation(&self, invocation: ScriptInvocation) -> AppleRemindersResult<String> {
        Self::ensure_supported()?;
        let mut command = Command::new(&self.osascript_path);
        command.arg("-e").arg(invocation.script);
        if !invocation.args.is_empty() {
            command.arg("--");
            for arg in invocation.args {
                command.arg(arg);
            }
        }
        let output = command
            .output()
            .map_err(|error| AppleRemindersError::Process(error.to_string()))?;
        if !output.status.success() {
            return Err(AppleRemindersError::Process(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub fn list_lists(&self) -> AppleRemindersResult<Value> {
        let raw = self.run_invocation(self.list_lists_invocation())?;
        let lists: Vec<Value> = raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| {
                let mut parts = line.split('\t');
                Some(json!({
                    "id": parts.next()?,
                    "name": parts.next()?,
                }))
            })
            .collect();
        Ok(json!({ "lists": lists }))
    }

    pub fn list_reminders(&self, list_name: Option<&str>) -> AppleRemindersResult<Value> {
        let raw = self.run_invocation(self.list_reminders_invocation(list_name))?;
        let reminders: Vec<Value> = raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| {
                let mut parts = line.split('\t');
                Some(json!({
                    "id": parts.next()?,
                    "title": parts.next()?,
                    "list": parts.next()?,
                    "completed": parts.next()? == "true",
                    "due": parts.next().unwrap_or(""),
                }))
            })
            .collect();
        Ok(json!({ "reminders": reminders }))
    }

    pub fn create_reminder(&self, title: &str, list_name: Option<&str>) -> AppleRemindersResult<Value> {
        if title.trim().is_empty() {
            return Err(AppleRemindersError::Config("title must not be empty".into()));
        }
        let raw = self.run_invocation(self.create_reminder_invocation(title, list_name))?;
        let mut parts = raw.split('\t');
        Ok(json!({
            "id": parts.next().ok_or_else(|| AppleRemindersError::Parse("Missing reminder id".into()))?,
            "title": parts.next().ok_or_else(|| AppleRemindersError::Parse("Missing reminder title".into()))?,
            "list": parts.next().ok_or_else(|| AppleRemindersError::Parse("Missing reminder list".into()))?,
        }))
    }

    pub fn complete_reminder(&self, reminder_id: &str) -> AppleRemindersResult<Value> {
        if reminder_id.trim().is_empty() {
            return Err(AppleRemindersError::Config("reminder_id must not be empty".into()));
        }
        let raw = self.run_invocation(self.complete_reminder_invocation(reminder_id))?;
        let mut parts = raw.split('\t');
        Ok(json!({
            "id": parts.next().ok_or_else(|| AppleRemindersError::Parse("Missing reminder id".into()))?,
            "title": parts.next().ok_or_else(|| AppleRemindersError::Parse("Missing reminder title".into()))?,
            "completed": parts.next().unwrap_or("false") == "true",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_reminders_invocation_uses_default_list() {
        let client = AppleRemindersClient::from_config(&AppleRemindersConfig {
            default_list: Some("Personal".into()),
            osascript_path: "/usr/bin/osascript".into(),
        })
        .expect("client should build");
        let invocation = client.list_reminders_invocation(None);
        assert_eq!(invocation.args, vec!["Personal"]);
    }

    #[test]
    fn list_lists_invocation_has_no_args() {
        let client = AppleRemindersClient::from_config(&AppleRemindersConfig {
            default_list: None,
            osascript_path: "/usr/bin/osascript".into(),
        })
        .expect("client should build");
        let invocation = client.list_lists_invocation();
        assert!(invocation.args.is_empty());
    }
}

