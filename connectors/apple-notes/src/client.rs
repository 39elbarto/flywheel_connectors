//! Apple Notes process client based on `osascript`.

use std::process::Command;

use serde_json::{Value, json};

use crate::error::{AppleNotesError, AppleNotesResult};
use crate::types::AppleNotesConfig;

const LIST_NOTES_SCRIPT: &str = r#"
on run argv
  set requestedFolder to ""
  if (count of argv) ≥ 1 then set requestedFolder to item 1 of argv
  set outputLines to {}
  tell application "Notes"
    repeat with theAccount in accounts
      repeat with theFolder in folders of theAccount
        if requestedFolder is "" or (name of theFolder as text) is requestedFolder then
          repeat with theNote in notes of theFolder
            set end of outputLines to ((id of theNote as text) & tab & (name of theNote as text) & tab & (name of theFolder as text))
          end repeat
        end if
      end repeat
    end repeat
  end tell
  return outputLines as text
end run
"#;

const SEARCH_NOTES_SCRIPT: &str = r#"
on run argv
  set queryText to item 1 of argv
  set outputLines to {}
  tell application "Notes"
    repeat with theAccount in accounts
      repeat with theFolder in folders of theAccount
        repeat with theNote in notes of theFolder
          set noteName to (name of theNote as text)
          set noteBody to (body of theNote as text)
          if noteName contains queryText or noteBody contains queryText then
            set end of outputLines to ((id of theNote as text) & tab & noteName & tab & (name of theFolder as text))
          end if
        end repeat
      end repeat
    end repeat
  end tell
  return outputLines as text
end run
"#;

const GET_NOTE_SCRIPT: &str = r#"
on run argv
  set noteId to item 1 of argv
  tell application "Notes"
    repeat with theAccount in accounts
      repeat with theFolder in folders of theAccount
        repeat with theNote in notes of theFolder
          if (id of theNote as text) is noteId then
            return (id of theNote as text) & linefeed & (name of theNote as text) & linefeed & (name of theFolder as text) & linefeed & (body of theNote as text)
          end if
        end repeat
      end repeat
    end repeat
  end tell
  error "Note not found"
end run
"#;

const CREATE_NOTE_SCRIPT: &str = r#"
on run argv
  set noteTitle to item 1 of argv
  set noteBody to item 2 of argv
  set requestedFolder to ""
  if (count of argv) ≥ 3 then set requestedFolder to item 3 of argv
  tell application "Notes"
    set targetAccount to first account
    if requestedFolder is "" then
      set targetFolder to first folder of targetAccount
    else
      set targetFolder to folder requestedFolder of targetAccount
    end if
    set createdNote to make new note at targetFolder with properties {name:noteTitle, body:noteBody}
    return (id of createdNote as text) & tab & (name of createdNote as text) & tab & (name of targetFolder as text)
  end tell
end run
"#;

#[derive(Debug, Clone)]
pub struct ScriptInvocation {
    pub script: &'static str,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AppleNotesClient {
    osascript_path: String,
    default_folder: Option<String>,
}

impl AppleNotesClient {
    pub fn from_config(config: &AppleNotesConfig) -> AppleNotesResult<Self> {
        Ok(Self {
            osascript_path: config.osascript_path.clone(),
            default_folder: config.default_folder.clone(),
        })
    }

    fn ensure_supported() -> AppleNotesResult<()> {
        if std::env::consts::OS != "macos" {
            return Err(AppleNotesError::UnsupportedPlatform(
                "Apple Notes connector requires macOS".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn list_notes_invocation(&self, folder: Option<&str>) -> ScriptInvocation {
        ScriptInvocation {
            script: LIST_NOTES_SCRIPT,
            args: vec![
                folder
                    .or(self.default_folder.as_deref())
                    .unwrap_or("")
                    .to_string(),
            ],
        }
    }

    #[must_use]
    pub fn search_notes_invocation(&self, query: &str) -> ScriptInvocation {
        ScriptInvocation {
            script: SEARCH_NOTES_SCRIPT,
            args: vec![query.to_string()],
        }
    }

    #[must_use]
    pub fn get_note_invocation(&self, note_id: &str) -> ScriptInvocation {
        ScriptInvocation {
            script: GET_NOTE_SCRIPT,
            args: vec![note_id.to_string()],
        }
    }

    #[must_use]
    pub fn create_note_invocation(
        &self,
        title: &str,
        body: &str,
        folder: Option<&str>,
    ) -> ScriptInvocation {
        ScriptInvocation {
            script: CREATE_NOTE_SCRIPT,
            args: vec![
                title.to_string(),
                body.to_string(),
                folder
                    .or(self.default_folder.as_deref())
                    .unwrap_or("")
                    .to_string(),
            ],
        }
    }

    fn run_invocation(&self, invocation: ScriptInvocation) -> AppleNotesResult<String> {
        Self::ensure_supported()?;
        let mut command = Command::new(&self.osascript_path);
        command.arg("-e").arg(invocation.script).arg("--");
        for arg in invocation.args {
            command.arg(arg);
        }
        let output = command
            .output()
            .map_err(|error| AppleNotesError::Process(error.to_string()))?;
        if !output.status.success() {
            return Err(AppleNotesError::Process(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn parse_note_summaries(raw: &str) -> Value {
        let notes: Vec<Value> = raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| {
                let mut parts = line.split('\t');
                Some(json!({
                    "id": parts.next()?,
                    "title": parts.next()?,
                    "folder": parts.next()?,
                }))
            })
            .collect();
        json!({ "notes": notes })
    }

    pub fn list_notes(&self, folder: Option<&str>) -> AppleNotesResult<Value> {
        let raw = self.run_invocation(self.list_notes_invocation(folder))?;
        Ok(Self::parse_note_summaries(&raw))
    }

    pub fn search_notes(&self, query: &str) -> AppleNotesResult<Value> {
        if query.trim().is_empty() {
            return Err(AppleNotesError::Config("query must not be empty".into()));
        }
        let raw = self.run_invocation(self.search_notes_invocation(query))?;
        Ok(Self::parse_note_summaries(&raw))
    }

    pub fn get_note(&self, note_id: &str) -> AppleNotesResult<Value> {
        if note_id.trim().is_empty() {
            return Err(AppleNotesError::Config("note_id must not be empty".into()));
        }
        let raw = self.run_invocation(self.get_note_invocation(note_id))?;
        let mut parts = raw.splitn(4, '\n');
        let id = parts
            .next()
            .ok_or_else(|| AppleNotesError::Parse("Missing note id".into()))?;
        let title = parts
            .next()
            .ok_or_else(|| AppleNotesError::Parse("Missing note title".into()))?;
        let folder = parts
            .next()
            .ok_or_else(|| AppleNotesError::Parse("Missing note folder".into()))?;
        let body = parts.next().unwrap_or("");
        Ok(json!({
            "id": id,
            "title": title,
            "folder": folder,
            "body": body,
        }))
    }

    pub fn create_note(
        &self,
        title: &str,
        body: &str,
        folder: Option<&str>,
    ) -> AppleNotesResult<Value> {
        if title.trim().is_empty() {
            return Err(AppleNotesError::Config("title must not be empty".into()));
        }
        let raw = self.run_invocation(self.create_note_invocation(title, body, folder))?;
        let mut parts = raw.split('\t');
        Ok(json!({
            "id": parts.next().ok_or_else(|| AppleNotesError::Parse("Missing note id".into()))?,
            "title": parts.next().ok_or_else(|| AppleNotesError::Parse("Missing note title".into()))?,
            "folder": parts.next().ok_or_else(|| AppleNotesError::Parse("Missing note folder".into()))?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_invocation_uses_default_folder_when_present() {
        let client = AppleNotesClient::from_config(&AppleNotesConfig {
            default_folder: Some("Inbox".into()),
            osascript_path: "/usr/bin/osascript".into(),
        })
        .expect("client should build");
        let invocation = client.list_notes_invocation(None);
        assert_eq!(invocation.args, vec!["Inbox"]);
    }

    #[test]
    fn get_note_parses_multiline_body() {
        let value = AppleNotesClient::parse_note_summaries("id-1\tTitle\tInbox\n");
        assert_eq!(value["notes"][0]["id"], "id-1");
        assert_eq!(value["notes"][0]["title"], "Title");
    }
}
