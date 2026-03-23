//! Generic IMAP/SMTP client helpers.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use native_tls::{TlsConnector, TlsStream};
use serde_json::{Value, json};

use crate::error::{EmailGenericError, EmailGenericResult};
use crate::types::EmailGenericConfig;

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

    fn imap_timeout(&self) -> Duration {
        Duration::from_millis(self.config.request_timeout_ms)
    }

    fn quote_imap(value: &str) -> String {
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
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
                return Err(EmailGenericError::Imap("Unexpected EOF from IMAP server".into()));
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

    fn imap_login_and_read<F, T>(&self, f: F) -> EmailGenericResult<T>
    where
        F: FnOnce(&mut BufReader<ImapStream>) -> EmailGenericResult<T>,
    {
        let mut reader = self.connect_imap()?;
        let greeting = Self::read_line(&mut reader)?;
        if !greeting.starts_with("*") {
            return Err(EmailGenericError::Imap("Invalid IMAP greeting".into()));
        }
        let login = format!(
            "LOGIN {} {}",
            Self::quote_imap(&self.config.imap.username),
            Self::quote_imap(&self.config.imap.password)
        );
        let login_lines = Self::run_imap_command(&mut reader, "a1", &login)?;
        if !login_lines
            .last()
            .is_some_and(|line| line.contains(" OK"))
        {
            return Err(EmailGenericError::Imap(login_lines.join("\n")));
        }
        let result = f(&mut reader)?;
        let _ = Self::run_imap_command(&mut reader, "az", "LOGOUT");
        Ok(result)
    }

    fn parse_mailboxes(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .filter_map(|line| {
                if !line.starts_with("* LIST") {
                    return None;
                }
                line.rsplit('"').nth(1).map(std::string::ToString::to_string)
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
            let select = format!("SELECT {}", Self::quote_imap(mailbox));
            let select_lines = Self::run_imap_command(reader, "a2", &select)?;
            if !select_lines.last().is_some_and(|line| line.contains(" OK")) {
                return Err(EmailGenericError::Imap(select_lines.join("\n")));
            }
            let search = format!("UID SEARCH TEXT {}", Self::quote_imap(query));
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
            builder = builder.to(
                recipient
                    .parse::<Mailbox>()
                    .map_err(|error| EmailGenericError::Address(error.to_string()))?,
            );
        }
        for recipient in cc {
            builder = builder.cc(
                recipient
                    .parse::<Mailbox>()
                    .map_err(|error| EmailGenericError::Address(error.to_string()))?,
            );
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
            EmailGenericClient::quote_imap("ab\\\"cd"),
            "\"ab\\\\\\\"cd\""
        );
    }
}
