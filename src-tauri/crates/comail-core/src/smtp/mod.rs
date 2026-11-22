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
    transport
        .send_raw(&envelope, raw)
        .await
        .map_err(classify_send_error)?;
    Ok(())
}

/// SMTP reply codes that genuinely mean the authentication step failed.
/// 454 is the transient auth failure (RFC 4954), 534/535 credential and
/// mechanism rejections. 530 is deliberately absent: it can also mean
/// "STARTTLS first", so its text is checked instead.
const AUTH_REPLY_CODES: &[u16] = &[454, 534, 535];

/// Enhanced status codes (RFC 5248) that mean the credentials themselves are
/// the problem. Policy and delivery rejections share the x.7.x space - 5.7.1
/// "not authorized", 5.7.20+ DKIM/SPF/DMARC failures - and must stay plain
/// SMTP errors so a poisoned send can fail terminally instead of pausing the
/// queue for re-auth forever.
const AUTH_ENHANCED_CODES: &[&str] = &["4.7.0", "5.7.8", "5.7.9", "5.7.11", "5.7.12"];

/// `msg` contains `code` as a standalone x.y.z token (not a substring of a
/// longer number like "5.7.80").
fn contains_enhanced_code(msg: &str, code: &str) -> bool {
    let edge = |c: char| c.is_ascii_digit() || c == '.';
    msg.match_indices(code)
        .any(|(i, _)| !msg[..i].ends_with(edge) && !msg[i + code.len()..].starts_with(edge))
}

/// Whether this send error means "re-authenticate". `status` is lettre's
/// parsed reply code; `client_side` marks errors raised by the client-side
/// auth step itself (no shared mechanism, bad challenge) rather than by a
/// server reply.
fn is_auth_failure(status: Option<u16>, msg: &str, client_side: bool) -> bool {
    if let Some(code) = status {
        if AUTH_REPLY_CODES.contains(&code) {
            return true;
        }
        if code == 530 {
            return msg.to_lowercase().contains("auth");
        }
        return AUTH_ENHANCED_CODES
            .iter()
            .any(|c| contains_enhanced_code(msg, c));
    }
    client_side && {
        let msg = msg.to_lowercase();
        msg.contains("auth") || msg.contains("challenge")
    }
}

/// Map a lettre send error to a core error. Only genuine authentication
/// failures become `CoreError::Auth`, which pauses the mutation queue for
/// re-auth; relay rejections, policy 5xx and network errors stay
/// `CoreError::Smtp` and follow the normal transient/permanent handling.
fn classify_send_error(e: lettre::transport::smtp::Error) -> CoreError {
    let msg = e.to_string();
    if is_auth_failure(
        e.status().map(u16::from),
        &msg,
        e.is_client() || e.is_response(),
    ) {
        CoreError::Auth(format!("smtp auth: {msg}"))
    } else {
        CoreError::Smtp(msg)
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
mod tests {
    use super::*;

    #[test]
    fn enhanced_code_matching_needs_token_edges() {
        assert!(contains_enhanced_code("535 5.7.8 bad creds", "5.7.8"));
        assert!(contains_enhanced_code("(5.7.8)", "5.7.8"));
        assert!(!contains_enhanced_code("5.7.80", "5.7.8"));
        assert!(!contains_enhanced_code("15.7.8", "5.7.8"));
        assert!(!contains_enhanced_code("4.7.0.1", "4.7.0"));
        assert!(!contains_enhanced_code("", "5.7.8"));
    }

    #[test]
    fn genuine_auth_failures_are_auth() {
        // (reply code, lettre Display text, client-side flag)
        let cases: &[(Option<u16>, &str, bool)] = &[
            (
                Some(535),
                "permanent error (535): 5.7.8 Username and Password not accepted",
                false,
            ),
            (
                Some(535),
                "permanent error (535): authentication failed",
                false,
            ),
            (
                Some(534),
                "permanent error (534): 5.7.9 mechanism too weak",
                false,
            ),
            (
                Some(454),
                "transient error (454): 4.7.0 Temporary authentication failure",
                false,
            ),
            (
                Some(530),
                "permanent error (530): 5.7.0 Authentication Required",
                false,
            ),
            (
                Some(530),
                "permanent error (530): SMTP authentication is required",
                false,
            ),
            // Enhanced code overrides an unusual reply code.
            (
                Some(550),
                "permanent error (550): 5.7.8 Authentication credentials invalid",
                false,
            ),
            // Client-side auth step errors (XOAUTH2 failure, no mechanism).
            (
                None,
                "internal client error: No compatible authentication mechanism was found",
                true,
            ),
            (
                None,
                "internal client error: This mechanism does not expect a challenge",
                true,
            ),
            (None, "response error: Could not read auth challenge", true),
        ];
        for (status, msg, client_side) in cases {
            assert!(
                is_auth_failure(*status, msg, *client_side),
                "expected auth: {msg}"
            );
        }
    }

    #[test]
    fn rejections_and_network_errors_stay_smtp() {
        let cases: &[(Option<u16>, &str, bool)] = &[
            // The false positives the old substring check produced.
            (
                Some(550),
                "permanent error (550): 5.7.1 ... not authorized",
                false,
            ),
            (
                Some(550),
                "permanent error (550): Unauthorized relay",
                false,
            ),
            (
                Some(550),
                "permanent error (550): 5.7.26 DMARC authentication failed",
                false,
            ),
            (
                Some(550),
                "permanent error (550): 5.7.1 Message rejected due to auth policy",
                false,
            ),
            // 530 demanding STARTTLS, not credentials.
            (
                Some(530),
                "permanent error (530): 5.7.0 Must issue a STARTTLS command first",
                false,
            ),
            // Other 5xx and transient non-auth replies.
            (
                Some(553),
                "permanent error (553): 5.1.3 bad recipient address",
                false,
            ),
            (
                Some(554),
                "permanent error (554): transaction failed",
                false,
            ),
            (Some(421), "transient error (421): try again later", false),
            (Some(451), "transient error (451): local error", false),
            // Non-response lettre errors carry no reply code.
            (None, "network error: connection refused", false),
            (None, "Connection error: closed", false),
            (None, "tls error: certificate expired", false),
            (None, "response error: SMTP response line too long", true),
            (None, "internal client error: envelope rejected", true),
        ];
        for (status, msg, client_side) in cases {
            assert!(
                !is_auth_failure(*status, msg, *client_side),
                "expected smtp: {msg}"
            );
        }
    }
}
