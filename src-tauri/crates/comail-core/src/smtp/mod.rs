//! SMTP sending via lettre, with password or XOAUTH2 auth.

use crate::error::{CoreError, Result};
use crate::models::AccountConfig;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

pub enum SmtpAuth {
    Password(String),
    XOAuth2(String),
}

fn build_transport(
    cfg: &AccountConfig,
    auth: &SmtpAuth,
) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
    use lettre::transport::smtp::client::{Tls, TlsParameters};

    let mut builder = if cfg.smtp_port == 465 {
        // Implicit TLS
        AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)
            .map_err(|e| CoreError::Smtp(e.to_string()))?
            .port(cfg.smtp_port)
    } else {
        // STARTTLS (587 and friends)
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)
            .map_err(|e| CoreError::Smtp(e.to_string()))?
            .port(cfg.smtp_port)
    };

    if crate::imap::tls_insecure() {
        let params = TlsParameters::builder(cfg.smtp_host.clone())
            .dangerous_accept_invalid_certs(true)
            .dangerous_accept_invalid_hostnames(true)
            .build()
            .map_err(|e| CoreError::Smtp(e.to_string()))?;
        builder = if cfg.smtp_port == 465 {
            builder.tls(Tls::Wrapper(params))
        } else {
            builder.tls(Tls::Required(params))
        };
    }

    let builder = match auth {
        SmtpAuth::Password(pw) => builder
            .credentials(Credentials::new(cfg.username.clone(), pw.clone()))
            .authentication(vec![Mechanism::Plain, Mechanism::Login]),
        SmtpAuth::XOAuth2(token) => builder
            .credentials(Credentials::new(cfg.username.clone(), token.clone()))
            .authentication(vec![Mechanism::Xoauth2]),
    };

    Ok(builder.build())
}

/// Send a fully built RFC 5322 message.
pub async fn send_raw(
    cfg: &AccountConfig,
    auth: &SmtpAuth,
    from: &str,
    recipients: &[String],
    raw: &[u8],
) -> Result<()> {
    use lettre::address::Envelope;
    let from_addr = from
        .parse()
        .map_err(|e| CoreError::Smtp(format!("bad from address: {e}")))?;
    let mut tos = Vec::with_capacity(recipients.len());
    for r in recipients {
        tos.push(
            r.parse()
                .map_err(|e| CoreError::Smtp(format!("bad recipient {r}: {e}")))?,
        );
    }
    let envelope =
        Envelope::new(Some(from_addr), tos).map_err(|e| CoreError::Smtp(e.to_string()))?;

    let transport = build_transport(cfg, auth)?;
    tracing::debug!(
        host = %cfg.smtp_host,
        port = cfg.smtp_port,
        auth = match auth {
            SmtpAuth::Password(_) => "password",
            SmtpAuth::XOAuth2(_) => "xoauth2",
        },
        bytes = raw.len(),
        recipients = recipients.len(),
        "smtp send_raw: connecting to relay",
    );
    transport.send_raw(&envelope, raw).await.map_err(|e| {
        let code = e.status().map(u16::from);
        let message = e.to_string();
        if definitely_not_accepted(code, e.is_tls(), e.is_client(), &message) {
            classify_send_error(code, message)
        } else {
            CoreError::SmtpUncertain(message)
        }
    })?;
    Ok(())
}

/// Only evidence from before DATA or an explicit rejection permits safe retry.
///
/// In lettre 0.11: a reply code means the server answered a command with a
/// 4xx/5xx; TLS and `Kind::Connection` ("Connection error") errors arise while
/// connecting or upgrading; `Kind::Client` errors (no compatible AUTH
/// mechanism, STARTTLS/SMTPUTF8/8BITMIME unsupported) are raised by the client
/// before MAIL FROM. `Kind::Network`/`Response` can occur after DATA, so they
/// stay uncertain.
fn definitely_not_accepted(
    code: Option<u16>,
    is_tls: bool,
    is_client: bool,
    display: &str,
) -> bool {
    code.is_some() || is_tls || is_client || display.starts_with("Connection error")
}

// A temporary 454 (including 4.7.0) must remain retryable: reauthentication
// cannot repair a server-side temporary authentication failure.
//
// Non-auth replies are prefixed with their reply code: lettre's Display reads
// "permanent error (550): …", and the queue's `is_smtp_permanent` decides
// whether to stop retrying by looking for a leading 5xx code.
fn classify_send_error(code: Option<u16>, message: String) -> CoreError {
    match code {
        Some(530 | 534 | 535) => CoreError::Auth(format!("smtp auth: {message}")),
        Some(code) => CoreError::Smtp(format!("{code} {message}")),
        None => CoreError::Smtp(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_auth_reply_codes_require_reauthentication() {
        for code in [530, 534, 535] {
            assert!(matches!(
                classify_send_error(Some(code), "rejected".into()),
                CoreError::Auth(_)
            ));
        }
        for code in [None, Some(454), Some(450), Some(550), Some(554)] {
            assert!(matches!(
                classify_send_error(code, "auth host 535 unavailable".into()),
                CoreError::Smtp(_)
            ));
        }
    }

    #[test]
    fn non_auth_replies_lead_with_their_code() {
        match classify_send_error(Some(550), "permanent error (550): no such user".into()) {
            CoreError::Smtp(msg) => assert!(msg.starts_with("550 "), "{msg}"),
            other => panic!("expected Smtp, got {other:?}"),
        }
        match classify_send_error(None, "network error: timed out".into()) {
            CoreError::Smtp(msg) => assert_eq!(msg, "network error: timed out"),
            other => panic!("expected Smtp, got {other:?}"),
        }
    }
}

/// Cheap connectivity/auth probe used by test_connection.
pub async fn test_connection(cfg: &AccountConfig, auth: &SmtpAuth) -> Result<()> {
    let transport = build_transport(cfg, auth)?;
    let ok = transport
        .test_connection()
        .await
        .map_err(|e| CoreError::Smtp(e.to_string()))?;
    if ok {
        Ok(())
    } else {
        Err(CoreError::Smtp("connection test failed".into()))
    }
}

#[cfg(test)]
mod acceptance_tests {
    use super::*;
    #[test]
    fn transport_failures_require_positive_pre_acceptance_evidence() {
        // (reply code, is_tls, is_client, lettre Display, expected "definitely not accepted")
        let cases: &[(Option<u16>, bool, bool, &str, bool)] = &[
            // Explicit server replies, including a rejection of the final ".".
            (
                Some(550),
                false,
                false,
                "permanent error (550): no such user",
                true,
            ),
            (
                Some(421),
                false,
                false,
                "transient error (421): try again later",
                true,
            ),
            (
                Some(535),
                false,
                false,
                "permanent error (535): bad credentials",
                true,
            ),
            // Connect / TLS-upgrade stage.
            (
                None,
                false,
                false,
                "Connection error: connection refused",
                true,
            ),
            (
                None,
                true,
                false,
                "tls error: invalid peer certificate",
                true,
            ),
            // Client-side refusals before MAIL FROM.
            (
                None,
                false,
                true,
                "internal client error: No compatible authentication mechanism was found",
                true,
            ),
            // Anything that can happen after DATA stays uncertain.
            (
                None,
                false,
                false,
                "network error: connection reset by peer",
                false,
            ),
            (None, false, false, "network error: timed out", false),
            (
                None,
                false,
                false,
                "response error: incomplete response",
                false,
            ),
            (None, false, false, "transport has been shut down", false),
            // "Connection error" must be the lettre kind prefix, not any substring.
            (
                None,
                false,
                false,
                "network error: Connection error mid-stream",
                false,
            ),
        ];
        for &(code, tls, client, display, expected) in cases {
            assert_eq!(
                definitely_not_accepted(code, tls, client, display),
                expected,
                "{display}"
            );
        }
    }
}
