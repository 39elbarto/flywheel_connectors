//! Generic `IMAP`/`SMTP` client helpers.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use mailparse::{DispositionType, MailHeaderMap, ParsedMail};
use native_tls::{TlsConnector, TlsStream};
use serde_json::{Value, json};

use crate::error::{EmailGenericError, EmailGenericResult};
use crate::types::{
    EmailAttachmentCandidate, EmailGenericConfig, EmailInboundMessage, EmailSeenUidCache,
};

const MAX_IMAP_LITERAL_BYTES: usize = 1_048_576;

enum ImapStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl Read for ImapStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for ImapStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

impl ImapStream {
    fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.shutdown(Shutdown::Both),
            Self::Tls(stream) => stream.get_mut().shutdown(Shutdown::Both),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmailGenericClient {
    config: EmailGenericConfig,
}

impl EmailGenericClient {
    pub fn from_config(config: &EmailGenericConfig) -> EmailGenericResult<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    const fn imap_timeout(&self) -> Duration {
        Duration::from_millis(self.config.request_timeout_ms)
    }

    /// Quote a value for inclusion in an IMAP command as an RFC 3501
    /// `quoted` string.
    ///
    /// RFC 3501 Section 4.3 prohibits CR (`\r`), LF (`\n`), and NUL inside the
    /// `quoted` production; those bytes are protocol terminators and
    /// have no legal escape sequence. A permissive server that
    /// tokenizes bytes before validating quoting could otherwise be
    /// driven into running attacker-controlled commands embedded in the
    /// supposed quoted value (CRLF injection). Reject those bytes
    /// fail-closed rather than emit a malformed quoted string.
    fn quote_imap(value: &str) -> EmailGenericResult<String> {
        for &byte in value.as_bytes() {
            if matches!(byte, b'\r' | b'\n' | 0) {
                return Err(EmailGenericError::Config(
                    "IMAP argument must not contain CR, LF, or NUL bytes".into(),
                ));
            }
        }
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        Ok(format!("\"{escaped}\""))
    }

    fn connect_imap(&self) -> EmailGenericResult<BufReader<ImapStream>> {
        let address = format!("{}:{}", self.config.imap.host, self.config.imap.port);
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(self.imap_timeout()))?;
        stream.set_write_timeout(Some(self.imap_timeout()))?;
        if self.config.imap.tls {
            let tls = TlsConnector::new()?
                .connect(&self.config.imap.host, stream)
                .map_err(|error| match error {
                    native_tls::HandshakeError::Failure(error) => EmailGenericError::Tls(error),
                    native_tls::HandshakeError::WouldBlock(_) => {
                        EmailGenericError::Imap("IMAP TLS handshake would block".into())
                    }
                })?;
            Ok(BufReader::new(ImapStream::Tls(tls)))
        } else {
            Ok(BufReader::new(ImapStream::Plain(stream)))
        }
    }

    fn read_line(reader: &mut BufReader<ImapStream>) -> EmailGenericResult<String> {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        Ok(line)
    }

    fn run_imap_command(
        reader: &mut BufReader<ImapStream>,
        tag: &str,
        command: &str,
    ) -> EmailGenericResult<Vec<String>> {
        reader
            .get_mut()
            .write_all(format!("{tag} {command}\r\n").as_bytes())?;
        reader.get_mut().flush()?;
        let mut lines = Vec::new();
        loop {
            let line = Self::read_line(reader)?;
            if line.is_empty() {
                return Err(EmailGenericError::Imap(
                    "Unexpected EOF from IMAP server".into(),
                ));
            }
            let trimmed = line.trim_end().to_string();
            let done = trimmed.starts_with(&format!("{tag} "));
            lines.push(trimmed);
            if done {
                break;
            }
        }
        Ok(lines)
    }

    fn run_imap_fetch_literal(
        reader: &mut BufReader<ImapStream>,
        tag: &str,
        command: &str,
    ) -> EmailGenericResult<Vec<u8>> {
        reader
            .get_mut()
            .write_all(format!("{tag} {command}\r\n").as_bytes())?;
        reader.get_mut().flush()?;
        let mut literal = None;
        loop {
            let line = Self::read_line(reader)?;
            if line.is_empty() {
                return Err(EmailGenericError::Imap(
                    "Unexpected EOF from IMAP server".into(),
                ));
            }
            let trimmed = line.trim_end();
            if let Some(len) = Self::parse_imap_literal_len(trimmed)? {
                if len > MAX_IMAP_LITERAL_BYTES {
                    return Err(EmailGenericError::Imap(format!(
                        "IMAP FETCH literal exceeds {MAX_IMAP_LITERAL_BYTES} byte limit"
                    )));
                }
                let mut body = vec![0_u8; len];
                reader.read_exact(&mut body)?;
                literal = Some(body);
                continue;
            }
            if trimmed.starts_with(&format!("{tag} ")) {
                if !trimmed.contains(" OK") {
                    return Err(EmailGenericError::Imap(trimmed.to_owned()));
                }
                return literal.ok_or_else(|| {
                    EmailGenericError::Imap("IMAP FETCH did not include an RFC822 literal".into())
                });
            }
        }
    }

    fn parse_imap_literal_len(line: &str) -> EmailGenericResult<Option<usize>> {
        let Some(start) = line.rfind('{') else {
            return Ok(None);
        };
        if !line.ends_with('}') {
            return Ok(None);
        }
        line[start + 1..line.len() - 1]
            .parse::<usize>()
            .map(Some)
            .map_err(|error| {
                EmailGenericError::Imap(format!("Invalid IMAP literal length: {error}"))
            })
    }

    fn imap_login_and_read<F, T>(&self, f: F) -> EmailGenericResult<T>
    where
        F: FnOnce(&mut BufReader<ImapStream>) -> EmailGenericResult<T>,
    {
        let mut reader = self.connect_imap()?;
        let greeting = Self::read_line(&mut reader)?;
        if !greeting.starts_with('*') {
            return Err(EmailGenericError::Imap("Invalid IMAP greeting".into()));
        }
        let login = format!(
            "LOGIN {} {}",
            Self::quote_imap(&self.config.imap.username)?,
            Self::quote_imap(&self.config.imap.password)?
        );
        let login_lines = Self::run_imap_command(&mut reader, "a1", &login)?;
        if !login_lines.last().is_some_and(|line| line.contains(" OK")) {
            return Err(EmailGenericError::Imap(login_lines.join("\n")));
        }
        let result = f(&mut reader)?;
        let _ = Self::run_imap_command(&mut reader, "az", "LOGOUT");
        let _ = reader.get_mut().shutdown();
        Ok(result)
    }

    fn parse_mailboxes(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .filter_map(|line| {
                if !line.starts_with("* LIST") {
                    return None;
                }
                line.rsplit('"')
                    .nth(1)
                    .map(std::string::ToString::to_string)
            })
            .collect()
    }

    fn parse_search_uids(lines: &[String]) -> Vec<u32> {
        lines
            .iter()
            .find_map(|line| line.strip_prefix("* SEARCH "))
            .map(|payload| {
                payload
                    .split_whitespace()
                    .filter_map(|part| part.parse::<u32>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn health(&self) -> EmailGenericResult<Value> {
        let mailboxes = self.list_mailboxes()?;
        Ok(json!({
            "status": "ok",
            "imap_host": self.config.imap.host,
            "smtp_host": self.config.smtp.host,
            "mailbox_count": mailboxes["mailboxes"].as_array().map_or(0, Vec::len),
        }))
    }

    pub fn list_mailboxes(&self) -> EmailGenericResult<Value> {
        self.imap_login_and_read(|reader| {
            let lines = Self::run_imap_command(reader, "a2", "LIST \"\" \"*\"")?;
            if !lines.last().is_some_and(|line| line.contains(" OK")) {
                return Err(EmailGenericError::Imap(lines.join("\n")));
            }
            Ok(json!({ "mailboxes": Self::parse_mailboxes(&lines) }))
        })
    }

    pub fn search_messages(&self, mailbox: &str, query: &str) -> EmailGenericResult<Value> {
        if mailbox.trim().is_empty() || query.trim().is_empty() {
            return Err(EmailGenericError::Config(
                "mailbox and query must not be empty".into(),
            ));
        }
        self.imap_login_and_read(|reader| {
            let select = format!("SELECT {}", Self::quote_imap(mailbox)?);
            let select_lines = Self::run_imap_command(reader, "a2", &select)?;
            if !select_lines.last().is_some_and(|line| line.contains(" OK")) {
                return Err(EmailGenericError::Imap(select_lines.join("\n")));
            }
            let search = format!("UID SEARCH TEXT {}", Self::quote_imap(query)?);
            let lines = Self::run_imap_command(reader, "a3", &search)?;
            if !lines.last().is_some_and(|line| line.contains(" OK")) {
                return Err(EmailGenericError::Imap(lines.join("\n")));
            }
            Ok(json!({
                "mailbox": mailbox,
                "query": query,
                "uids": Self::parse_search_uids(&lines),
            }))
        })
    }

    pub fn fetch_unseen_inbound_messages(
        &self,
        mailbox: &str,
        seen_uids: &mut EmailSeenUidCache,
    ) -> EmailGenericResult<Vec<EmailInboundMessage>> {
        if mailbox.trim().is_empty() {
            return Err(EmailGenericError::Config(
                "mailbox must not be empty".into(),
            ));
        }
        self.imap_login_and_read(|reader| {
            let select = format!("SELECT {}", Self::quote_imap(mailbox)?);
            let select_lines = Self::run_imap_command(reader, "a2", &select)?;
            if !select_lines.last().is_some_and(|line| line.contains(" OK")) {
                return Err(EmailGenericError::Imap(select_lines.join("\n")));
            }
            let search_lines = Self::run_imap_command(reader, "a3", "UID SEARCH UNSEEN")?;
            if !search_lines.last().is_some_and(|line| line.contains(" OK")) {
                return Err(EmailGenericError::Imap(search_lines.join("\n")));
            }

            let mut messages = Vec::new();
            for uid in Self::parse_search_uids(&search_lines) {
                let uid = uid.to_string();
                if seen_uids.contains(&uid) {
                    continue;
                }
                let fetch = format!("UID FETCH {uid} (RFC822)");
                let raw = Self::run_imap_fetch_literal(reader, &format!("f{uid}"), &fetch)?;
                let message = Self::parse_inbound_message(uid.clone(), &raw)?;
                seen_uids.observe(uid);
                messages.push(message);
            }
            Ok(messages)
        })
    }

    pub fn parse_inbound_message(
        uid: impl Into<String>,
        raw: &[u8],
    ) -> EmailGenericResult<EmailInboundMessage> {
        let parsed = mailparse::parse_mail(raw).map_err(|error| Self::mail_parse_error(&error))?;
        let sender = parsed
            .headers
            .get_first_value("From")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| EmailGenericError::Imap("RFC822 message is missing From".into()))?;
        let headers = parsed
            .headers
            .iter()
            .map(|header| (header.get_key(), header.get_value()))
            .collect::<Vec<_>>();
        Ok(EmailInboundMessage {
            uid: uid.into(),
            sender,
            headers,
            subject: parsed
                .headers
                .get_first_value("Subject")
                .unwrap_or_default(),
            body: Self::extract_text_body(&parsed)?,
            message_id: parsed.headers.get_first_value("Message-ID"),
            in_reply_to: parsed.headers.get_first_value("In-Reply-To"),
            references: parsed.headers.get_first_value("References"),
            attachments: Self::extract_attachments(&parsed)?,
        })
    }

    fn mail_parse_error(error: &mailparse::MailParseError) -> EmailGenericError {
        EmailGenericError::Imap(format!("Failed to parse RFC822 message: {error}"))
    }

    fn extract_text_body(parsed: &ParsedMail<'_>) -> EmailGenericResult<String> {
        if let Some(body) = Self::find_body_part(parsed, "text/plain")? {
            return Ok(body);
        }
        if let Some(body) = Self::find_body_part(parsed, "text/html")? {
            return Ok(Self::strip_html_tags(&body));
        }
        Ok(String::new())
    }

    fn find_body_part(
        part: &ParsedMail<'_>,
        media_type: &str,
    ) -> EmailGenericResult<Option<String>> {
        if part.subparts.is_empty()
            && part.ctype.mimetype.eq_ignore_ascii_case(media_type)
            && Self::part_filename(part).is_none()
            && !matches!(
                part.get_content_disposition().disposition,
                DispositionType::Attachment
            )
        {
            return part
                .get_body()
                .map(Some)
                .map_err(|error| Self::mail_parse_error(&error));
        }
        for subpart in &part.subparts {
            if let Some(body) = Self::find_body_part(subpart, media_type)? {
                return Ok(Some(body));
            }
        }
        Ok(None)
    }

    fn extract_attachments(
        parsed: &ParsedMail<'_>,
    ) -> EmailGenericResult<Vec<EmailAttachmentCandidate>> {
        let mut attachments = Vec::new();
        for part in parsed.parts() {
            let Some(filename) = Self::part_filename(part) else {
                continue;
            };
            let size_bytes = part
                .get_body_raw()
                .map_err(|error| Self::mail_parse_error(&error))?
                .len();
            attachments.push(EmailAttachmentCandidate {
                filename,
                media_type: part.ctype.mimetype.clone(),
                size_bytes,
            });
        }
        Ok(attachments)
    }

    fn part_filename(part: &ParsedMail<'_>) -> Option<String> {
        let disposition = part.get_content_disposition();
        disposition
            .params
            .get("filename")
            .or_else(|| part.ctype.params.get("name"))
            .filter(|value| !value.trim().is_empty())
            .cloned()
    }

    fn strip_html_tags(html: &str) -> String {
        let mut text = String::new();
        let mut in_tag = false;
        for ch in html.chars() {
            match ch {
                '<' => in_tag = true,
                '>' => in_tag = false,
                _ if !in_tag => text.push(ch),
                _ => {}
            }
        }
        text.replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
    }

    pub fn send_message(
        &self,
        to: &[String],
        subject: &str,
        body: &str,
        cc: &[String],
    ) -> EmailGenericResult<Value> {
        if to.is_empty() {
            return Err(EmailGenericError::Config(
                "at least one recipient is required".into(),
            ));
        }
        let from = Mailbox::new(
            self.config.smtp.from_name.clone(),
            self.config
                .smtp
                .from_address
                .parse::<lettre::Address>()
                .map_err(|error| EmailGenericError::Address(error.to_string()))?,
        );
        let mut builder = Message::builder().from(from).subject(subject);
        for recipient in to {
            builder = builder.to(recipient
                .parse::<Mailbox>()
                .map_err(|error| EmailGenericError::Address(error.to_string()))?);
        }
        for recipient in cc {
            builder = builder.cc(recipient
                .parse::<Mailbox>()
                .map_err(|error| EmailGenericError::Address(error.to_string()))?);
        }
        let message = builder
            .body(body.to_string())
            .map_err(|error| EmailGenericError::Smtp(error.to_string()))?;
        let credentials = Credentials::new(
            self.config.smtp.username.clone(),
            self.config.smtp.password.clone(),
        );
        let mailer = if self.config.smtp.starttls {
            SmtpTransport::relay(&self.config.smtp.host)
                .map_err(|error| EmailGenericError::Smtp(error.to_string()))?
                .port(self.config.smtp.port)
                .credentials(credentials)
                .build()
        } else {
            SmtpTransport::builder_dangerous(&self.config.smtp.host)
                .port(self.config.smtp.port)
                .credentials(credentials)
                .build()
        };
        mailer
            .send(&message)
            .map_err(|error| EmailGenericError::Smtp(error.to_string()))?;
        Ok(json!({
            "status": "sent",
            "to": to,
            "cc": cc,
            "subject": subject,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> EmailGenericConfig {
        EmailGenericConfig::from_value(serde_json::json!({
            "imap": {
                "host": "imap.example.com",
                "username": "user@example.com",
                "password": "secret"
            },
            "smtp": {
                "host": "smtp.example.com",
                "username": "user@example.com",
                "password": "secret",
                "from_address": "user@example.com"
            }
        }))
        .expect("config should parse")
    }

    #[test]
    fn parse_mailboxes_extracts_last_quoted_token() {
        let mailboxes = EmailGenericClient::parse_mailboxes(&[
            "* LIST (\\HasNoChildren) \"/\" \"INBOX\"".into(),
            "a2 OK LIST completed".into(),
        ]);
        assert_eq!(mailboxes, vec!["INBOX"]);
    }

    #[test]
    fn parse_search_uids_extracts_uid_list() {
        let uids = EmailGenericClient::parse_search_uids(&[
            "* SEARCH 2 5 8".into(),
            "a3 OK SEARCH completed".into(),
        ]);
        assert_eq!(uids, vec![2, 5, 8]);
    }

    #[test]
    fn quote_imap_escapes_backslashes_and_quotes() {
        let _ = config();
        assert_eq!(
            EmailGenericClient::quote_imap("ab\\\"cd").unwrap(),
            "\"ab\\\\\\\"cd\""
        );
    }

    /// RFC 3501 Section 4.3 forbids CR, LF, and NUL inside a `quoted` IMAP
    /// string. A permissive server that tokenizes bytes before
    /// validating quoting could let an attacker who controls the
    /// `mailbox` or `query` argument inject extra IMAP commands via
    /// `\r\n<command>`. The fail-closed variant rejects those bytes.
    #[test]
    fn quote_imap_rejects_crlf_and_nul() {
        for inject in [
            "INBOX\r\na999 LOGOUT",
            "INBOX\nfoo",
            "INBOX\rfoo",
            "INBOX\0LOGOUT",
        ] {
            let err =
                EmailGenericClient::quote_imap(inject).expect_err("CR/LF/NUL must be rejected");
            assert!(
                matches!(err, EmailGenericError::Config(_)),
                "unexpected error variant for {inject:?}: {err:?}"
            );
        }
    }

    #[test]
    fn quote_imap_accepts_non_control_characters() {
        assert!(EmailGenericClient::quote_imap("INBOX").is_ok());
        assert!(EmailGenericClient::quote_imap("Important/Travel").is_ok());
        assert!(EmailGenericClient::quote_imap("Special Folder").is_ok());
    }

    #[test]
    fn parse_imap_literal_len_accepts_fetch_literal_marker() {
        assert_eq!(
            EmailGenericClient::parse_imap_literal_len("* 1 FETCH (RFC822 {42}").unwrap(),
            Some(42)
        );
        assert_eq!(
            EmailGenericClient::parse_imap_literal_len("* SEARCH 2 5 8").unwrap(),
            None
        );
    }

    #[test]
    fn parse_inbound_message_extracts_headers_body_and_attachment_metadata() {
        let raw = concat!(
            "From: Human <human@example.com>\r\n",
            "Subject: =?utf-8?Q?Deploy_ready?=\r\n",
            "Message-ID: <msg-1@example.com>\r\n",
            "In-Reply-To: <parent@example.com>\r\n",
            "References: <root@example.com> <parent@example.com>\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "green\r\n",
            "--b\r\n",
            "Content-Type: application/pdf; name=\"plan.pdf\"\r\n",
            "Content-Disposition: attachment; filename=\"plan.pdf\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "cGxhbg==\r\n",
            "--b--\r\n",
        );
        let message = EmailGenericClient::parse_inbound_message("99", raw.as_bytes()).unwrap();
        assert_eq!(message.uid, "99");
        assert_eq!(message.sender, "Human <human@example.com>");
        assert_eq!(message.subject, "Deploy ready");
        assert_eq!(message.body.trim(), "green");
        assert_eq!(message.message_id.as_deref(), Some("<msg-1@example.com>"));
        assert_eq!(message.attachments.len(), 1);
        assert_eq!(message.attachments[0].filename, "plan.pdf");
        assert_eq!(message.attachments[0].media_type, "application/pdf");
        assert_eq!(message.attachments[0].size_bytes, 4);
    }

    #[test]
    fn parse_inbound_message_prefers_plain_text_over_html() {
        let raw = concat!(
            "From: human@example.com\r\n",
            "Subject: Body choice\r\n",
            "Content-Type: multipart/alternative; boundary=\"alt\"\r\n",
            "\r\n",
            "--alt\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<p>html</p>\r\n",
            "--alt\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "plain\r\n",
            "--alt--\r\n",
        );
        let message = EmailGenericClient::parse_inbound_message("7", raw.as_bytes()).unwrap();
        assert_eq!(message.body.trim(), "plain");
    }
}
