//! Bounded Google Forms API v1 request types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Info {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuizSettings {
    pub is_quiz: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FormSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiz_settings: Option<QuizSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_collection_type: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Location {
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Request {
    UpdateFormInfo(UpdateFormInfoRequest),
    UpdateSettings(UpdateSettingsRequest),
    CreateItem(CreateItemRequest),
    MoveItem(MoveItemRequest),
    DeleteItem(DeleteItemRequest),
    UpdateItem(UpdateItemRequest),
}

impl Request {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::UpdateFormInfo(_) => "updateFormInfo",
            Self::UpdateSettings(_) => "updateSettings",
            Self::CreateItem(_) => "createItem",
            Self::MoveItem(_) => "moveItem",
            Self::DeleteItem(_) => "deleteItem",
            Self::UpdateItem(_) => "updateItem",
        }
    }

    #[must_use]
    pub fn is_destructive(&self) -> bool {
        match self {
            Self::DeleteItem(_) | Self::MoveItem(_) => true,
            Self::UpdateSettings(request) => request
                .settings
                .quiz_settings
                .as_ref()
                .is_some_and(|settings| !settings.is_quiz),
            Self::UpdateItem(request) => request.update_mask.split(',').any(|field| {
                matches!(
                    field.trim(),
                    "questionItem.question.grading" | "questionGroupItem.questions.grading"
                )
            }),
            Self::UpdateFormInfo(_) | Self::CreateItem(_) => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateFormInfoRequest {
    pub info: Info,
    pub update_mask: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateSettingsRequest {
    pub settings: FormSettings,
    pub update_mask: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateItemRequest {
    pub item: serde_json::Value,
    pub location: Location,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MoveItemRequest {
    pub original_location: Location,
    pub new_location: Location,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteItemRequest {
    pub location: Location,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateItemRequest {
    pub item: serde_json::Value,
    pub location: Location,
    pub update_mask: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishSettings {
    pub publish_state: PublishState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishState {
    pub is_published: bool,
    pub is_accepting_responses: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateResponse {
    #[serde(default)]
    pub form: Option<serde_json::Value>,
    #[serde(default)]
    pub replies: Vec<serde_json::Value>,
    #[serde(default)]
    pub write_control: Option<serde_json::Value>,
}
