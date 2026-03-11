//! Deprecated `fcp` shim.
//!
//! The canonical Flywheel connectors CLI is `fwc`. This binary exists only as
//! a hard-stop migration notice so the repository does not expose two
//! competing CLI implementations.

#![deny(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

const DEPRECATION_EXIT_CODE: u8 = 2;

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let suggested = suggested_fwc_command(&args);

    let mut stderr = io::stderr().lock();
    let _ = writeln!(
        stderr,
        concat!(
            "fcp has been retired. The only canonical Flywheel connectors CLI is `fwc`.\n\n",
            "Run instead:\n",
            "  {suggested}\n\n",
            "Common migrations:\n",
            "  fcp context ...   -> fwc context ...\n",
            "  fcp connector ... -> fwc list/show/ops/schema/examples/status/invoke/simulate\n",
            "  fcp doctor        -> fwc status / fwc context current / fwc show <connector>\n",
            "  fcp policy        -> fwc simulate\n\n",
            "`fcp` no longer performs real work and will not simulate or proxy command execution."
        ),
        suggested = suggested
    );

    ExitCode::from(DEPRECATION_EXIT_CODE)
}

fn suggested_fwc_command(args: &[String]) -> String {
    if args.is_empty() {
        return "fwc --help".to_owned();
    }

    format!(
        "fwc {}",
        args.iter()
            .map(|arg| shell_quote(arg))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn shell_quote(arg: &str) -> String {
    if arg
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '='))
    {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggested_command_defaults_to_help() {
        assert_eq!(suggested_fwc_command(&[]), "fwc --help");
    }

    #[test]
    fn suggested_command_quotes_complex_args() {
        let args = vec![
            "context".to_owned(),
            "create".to_owned(),
            "prod env".to_owned(),
        ];
        assert_eq!(
            suggested_fwc_command(&args),
            "fwc context create 'prod env'"
        );
    }
}
