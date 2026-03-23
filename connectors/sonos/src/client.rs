//! `Sonos` `SOAP` client.

use regex::Regex;
use serde_json::{Value, json};

use crate::error::{SonosError, SonosResult};
use crate::types::SonosConfig;

const AV_TRANSPORT_SERVICE: &str = "urn:schemas-upnp-org:service:AVTransport:1";
const RENDERING_CONTROL_SERVICE: &str = "urn:schemas-upnp-org:service:RenderingControl:1";

#[derive(Debug, Clone)]
pub struct SonosClient {
    client: reqwest::Client,
    device_url: String,
}

impl SonosClient {
    pub fn from_config(config: &SonosConfig) -> SonosResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.request_timeout_ms))
            .danger_accept_invalid_certs(config.allow_insecure_ssl)
            .build()?;
        Ok(Self {
            client,
            device_url: config.normalized_device_url(),
        })
    }

    #[must_use]
    pub fn device_url(&self) -> &str {
        &self.device_url
    }

    async fn soap_action(
        &self,
        service_path: &str,
        service_type: &str,
        action: &str,
        body: &str,
    ) -> SonosResult<String> {
        let envelope = format!(
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{action} xmlns:u="{service_type}">{body}</u:{action}></s:Body></s:Envelope>"#
        );
        let response = self
            .client
            .post(format!("{}{}", self.device_url, service_path))
            .header("SOAPACTION", format!("\"{service_type}#{action}\""))
            .header("CONTENT-TYPE", "text/xml; charset=\"utf-8\"")
            .body(envelope)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(SonosError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(body)
    }

    fn capture(xml: &str, tag: &str) -> Option<String> {
        let pattern = format!(r"<{}>([^<]+)</{}>", regex::escape(tag), regex::escape(tag));
        let regex = Regex::new(&pattern).ok()?;
        regex
            .captures(xml)
            .and_then(|captures| captures.get(1))
            .map(|value| value.as_str().to_string())
    }

    pub async fn health(&self) -> SonosResult<Value> {
        let response = self
            .client
            .get(format!("{}/xml/device_description.xml", self.device_url))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(SonosError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(json!({
            "status": "ok",
            "friendly_name": Self::capture(&body, "friendlyName"),
            "model_name": Self::capture(&body, "modelName"),
            "device_url": self.device_url,
        }))
    }

    pub async fn get_status(&self) -> SonosResult<Value> {
        let transport = self
            .soap_action(
                "/MediaRenderer/AVTransport/Control",
                AV_TRANSPORT_SERVICE,
                "GetTransportInfo",
                "<InstanceID>0</InstanceID>",
            )
            .await?;
        let volume = self
            .soap_action(
                "/MediaRenderer/RenderingControl/Control",
                RENDERING_CONTROL_SERVICE,
                "GetVolume",
                "<InstanceID>0</InstanceID><Channel>Master</Channel>",
            )
            .await?;
        Ok(json!({
            "transport_state": Self::capture(&transport, "CurrentTransportState"),
            "transport_status": Self::capture(&transport, "CurrentTransportStatus"),
            "volume": Self::capture(&volume, "CurrentVolume")
                .and_then(|value| value.parse::<u8>().ok()),
        }))
    }

    pub async fn play(&self) -> SonosResult<Value> {
        self.soap_action(
            "/MediaRenderer/AVTransport/Control",
            AV_TRANSPORT_SERVICE,
            "Play",
            "<InstanceID>0</InstanceID><Speed>1</Speed>",
        )
        .await?;
        Ok(json!({ "status": "ok", "action": "play" }))
    }

    pub async fn pause(&self) -> SonosResult<Value> {
        self.soap_action(
            "/MediaRenderer/AVTransport/Control",
            AV_TRANSPORT_SERVICE,
            "Pause",
            "<InstanceID>0</InstanceID>",
        )
        .await?;
        Ok(json!({ "status": "ok", "action": "pause" }))
    }

    pub async fn next(&self) -> SonosResult<Value> {
        self.soap_action(
            "/MediaRenderer/AVTransport/Control",
            AV_TRANSPORT_SERVICE,
            "Next",
            "<InstanceID>0</InstanceID>",
        )
        .await?;
        Ok(json!({ "status": "ok", "action": "next" }))
    }

    pub async fn previous(&self) -> SonosResult<Value> {
        self.soap_action(
            "/MediaRenderer/AVTransport/Control",
            AV_TRANSPORT_SERVICE,
            "Previous",
            "<InstanceID>0</InstanceID>",
        )
        .await?;
        Ok(json!({ "status": "ok", "action": "previous" }))
    }

    pub async fn set_volume(&self, volume: u8) -> SonosResult<Value> {
        self
            .soap_action(
                "/MediaRenderer/RenderingControl/Control",
                RENDERING_CONTROL_SERVICE,
                "SetVolume",
                &format!(
                    "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>{volume}</DesiredVolume>"
                ),
            )
            .await?;
        Ok(json!({ "status": "ok", "volume": volume }))
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[fcp_async_core::runtime::test]
    async fn play_uses_avtransport_soap_action() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/MediaRenderer/AVTransport/Control"))
            .and(header(
                "soapaction",
                "\"urn:schemas-upnp-org:service:AVTransport:1#Play\"",
            ))
            .and(body_string_contains("<u:Play"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;

        let config = SonosConfig::from_value(serde_json::json!({
            "device_url": server.uri()
        }))
        .expect("config should parse");
        let client = SonosClient::from_config(&config).expect("client should build");
        let result = client.play().await.expect("play should succeed");
        assert_eq!(result["action"], "play");
    }

    #[test]
    fn capture_extracts_xml_tag_values() {
        assert_eq!(
            SonosClient::capture(
                "<root><CurrentVolume>18</CurrentVolume></root>",
                "CurrentVolume"
            ),
            Some("18".into())
        );
    }
}
