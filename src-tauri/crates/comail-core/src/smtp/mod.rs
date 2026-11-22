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

/// SMTP reply codes that genuinely mean the credentials are wrong or must
/// be refreshed (RFC 4954): 454 temporary authentication failure, 534
/// mechanism too weak / credentials refused, 535 authentication failed.
/// Each is only issued in response to AUTH.
const AUTH_REPLY_CODES: &[u16] = &[454, 534, 535];

/// Reply codes RFC 4954 reserves for the AUTH exchange itself, where the
/// code alone is the whole verdict and any enhanced code in the text is
/// decoration: 432 (password transition needed - a protocol step the
/// client performs, not something re-entering a password fixes), 454, 530
/// (auth only when its text says so; providers also use it for "STARTTLS
/// first"), 534, 535, and 538 (encryption required for the mechanism - a
/// transport policy no re-login resolves, so it must surface as a normal,
/// terminal SMTP failure rather than pausing the queue for re-auth).
const AUTH_STEP_CODES: &[u16] = &[432, 454, 530, 534, 535, 538];

/// Enhanced status codes (RFC 3463/5248) that mean the credentials
/// themselves: 5.7.8 credentials invalid, 5.7.9 mechanism too weak, 5.7.11
/// authentication required, 5.7.12 password transition needed. They are only
/// honoured on 5xx replies - on 4xx the x.7.x space means rate limiting and
/// greylisting (421 4.7.0 "try again later" at Gmail/Yahoo, 4.7.1 greylist),
/// not bad credentials. Excluded from the list entirely: 5.7.1 policy /
/// "not authorized" / relay denied, 5.7.13 account disabled (retrying the
/// password cannot help), and 5.7.20+ SPF/DKIM/DMARC failures - all of which
/// must stay plain SMTP errors so the queue can fail them terminally instead
/// of pausing for re-auth forever.
const AUTH_ENHANCED_CODES: &[&str] = &["5.7.8", "5.7.9", "5.7.11", "5.7.12"];

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
        // An AUTH-exchange code is its own verdict; its enhanced code is
        // decoration. 530 only counts when the text actually says auth.
        if AUTH_STEP_CODES.contains(&code) {
            return code == 530 && msg.to_lowercase().contains("auth");
        }
        // Credential-class enhanced codes are only honoured on permanent
        // (5xx) rejections; a 4xx transient with an x.7.x code is rate
        // limiting or greylisting, which is retried, not re-authed.
        return code >= 500
            && AUTH_ENHANCED_CODES
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
            // 535 is the generic AUTH rejection; the enhanced code varies by
            // provider but the reply code already decides.
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
            // Exchange "Authentication unsuccessful".
            (
                Some(535),
                "permanent error (535): 5.7.3 Authentication unsuccessful",
                false,
            ),
            // Outlook "basic auth is disabled" - still an AUTH rejection.
            (
                Some(535),
                "permanent error (535): 5.7.139 Authentication unsuccessful, basic authentication is disabled",
                false,
            ),
            // 534: RFC 4954 mechanism-too-weak / credentials refused.
            (
                Some(534),
                "permanent error (534): 5.7.9 mechanism too weak",
                false,
            ),
            // Gmail "please log in via your web browser": needs interactive
            // re-auth, delivered under 534.
            (
                Some(534),
                "permanent error (534): 5.7.14 Please log in via your web browser and then try again",
                false,
            ),
            // 454: RFC 4954 transient authentication failure.
            (
                Some(454),
                "transient error (454): 4.7.0 Temporary authentication failure",
                false,
            ),
            // 530 "Authentication required" - text confirms it means AUTH.
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
            // Credential-class enhanced code on a 5xx reject decides even
            // when the reply code is not an AUTH code.
            (
                Some(550),
                "permanent error (550): 5.7.8 Authentication credentials invalid",
                false,
            ),
            (
                Some(554),
                "permanent error (554): 5.7.9 authentication mechanism too weak",
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
            // Rate limiting / greylisting on 4xx: the x.7.x enhanced code is
            // NOT credential-class on a transient reply - this is the F1
            // false positive.
            (
                Some(421),
                "transient error (421): 4.7.0 Try again later",
                false,
            ),
            (
                Some(421),
                "transient error (421): 4.3.2 service not available",
                false,
            ),
            (
                Some(450),
                "transient error (450): 4.7.1 Greylisted, try again later",
                false,
            ),
            (
                Some(451),
                "transient error (451): 4.7.1 Greylisting in action",
                false,
            ),
            (
                Some(452),
                "transient error (452): 4.5.3 too many recipients",
                false,
            ),
            // Policy/relay/DMARC rejections share x.7.x but are not auth.
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
            (
                Some(554),
                "permanent error (554): 5.7.1 delivery not authorized, message refused",
                false,
            ),
            // Other 5xx delivery failures.
            (
                Some(552),
                "permanent error (552): 5.3.4 Message exceeds fixed size limit",
                false,
            ),
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
            // 530 demanding STARTTLS, not credentials.
            (
                Some(530),
                "permanent error (530): 5.7.0 Must issue a STARTTLS command first",
                false,
            ),
            // 432/538 are AUTH-step replies that re-auth cannot resolve:
            // 432 asks for a password transition (a client-side protocol
            // step), 538 demands encryption for the mechanism. Both stay
            // normal SMTP failures even when their text carries a
            // credential-class enhanced code.
            (
                Some(432),
                "transient error (432): 4.7.12 A password transition is needed",
                false,
            ),
            (
                Some(538),
                "permanent error (538): 5.7.11 Encryption required for requested authentication mechanism",
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

    /// A bare-bones SMTP responder: greets, accepts EHLO, and answers every
    /// MAIL FROM with `reply`. `send_raw` against it produces the lettre
    /// `Error` the classifier really sees on the wire - parsed reply code
    /// and lettre's own Display text included.
    async fn lettre_error_for(reply: &'static str) -> lettre::transport::smtp::Error {
        use lettre::address::Envelope;
        use lettre::transport::smtp::client::Tls;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let (reader, mut writer) = socket.split();
            if writer.write_all(b"220 test ESMTP\r\n").await.is_err() {
                return;
            }
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let verb = line
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_uppercase();
                let answer = match verb.as_str() {
                    "EHLO" | "HELO" => "250 OK\r\n",
                    "RSET" | "QUIT" | "NOOP" => "221 Bye\r\n",
                    _ => reply,
                };
                if writer.write_all(answer.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
            .port(port)
            .tls(Tls::None)
            .build();
        let envelope = Envelope::new(
            Some("a@test.dev".parse().unwrap()),
            vec!["b@test.dev".parse().unwrap()],
        )
        .unwrap();
        transport
            .send_raw(
                &envelope,
                b"From: a@test.dev\r\nTo: b@test.dev\r\n\r\nhi\r\n",
            )
            .await
            .expect_err("the scripted reply always fails the send")
    }

    #[tokio::test]
    async fn classifier_sees_real_lettre_reply_errors() {
        // Real lettre Errors produced on the wire, not hand-built (code,
        // text) pairs - this also exercises lettre's Display, which the
        // queue's permanence check reads.
        let cases: &[(&str, bool, &str)] = &[
            (
                "535 5.7.8 Authentication credentials invalid\r\n",
                true,
                "credential rejection is Auth",
            ),
            (
                "421 4.7.0 Try again later\r\n",
                false,
                "4xx rate limit is not auth",
            ),
            (
                "552 5.3.4 Message exceeds fixed size limit\r\n",
                false,
                "5xx size rejection is not auth",
            ),
            (
                "530 5.7.0 Must issue a STARTTLS command first\r\n",
                false,
                "530 STARTTLS demand is not auth",
            ),
        ];
        for &(reply, expect_auth, why) in cases {
            let error = lettre_error_for(reply).await;
            assert!(
                error.status().is_some(),
                "lettre must parse the reply code: {reply}"
            );
            let mapped = classify_send_error(error);
            assert_eq!(
                matches!(mapped, CoreError::Auth(_)),
                expect_auth,
                "{why}: {reply}"
            );
        }
    }
}
