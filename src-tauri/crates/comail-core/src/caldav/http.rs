//! Thin HTTP layer for WebDAV verbs. The `Transport` trait is the seam that
//! makes discovery/sync/push unit-testable against canned responses.

use crate::error::{CoreError, Result};

#[derive(Debug, Clone)]
pub enum DavAuth {
    Bearer(String),
    Basic(String, String),
}

#[derive(Debug, Clone, Default)]
pub struct DavResponse {
    pub status: u16,
    pub etag: Option<String>,
    pub body: String,
}

impl DavResponse {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Body type assumed for DAV requests whose caller does not name one
/// (PROPFIND/REPORT bodies are XML). PUTs of iCalendar data pass their own
/// Content-Type through `extra`.
pub(crate) const XML_CONTENT_TYPE: &str = "application/xml; charset=utf-8";

/// True when `extra` already names a Content-Type. Header names are
/// case-insensitive, and `RequestBuilder::header` appends rather than
/// replaces, so the default must be skipped or two Content-Type lines go out.
fn has_content_type(extra: &[(&str, &str)]) -> bool {
    extra
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
}

/// One WebDAV request. `depth` adds a Depth header when Some; `extra` carries
/// conditional headers (If-Match / If-None-Match) and an optional
/// Content-Type overriding [`XML_CONTENT_TYPE`].
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn request(
        &self,
        method: &str,
        url: &str,
        depth: Option<&str>,
        extra: &[(&str, &str)],
        body: Option<String>,
    ) -> Result<DavResponse>;
}

pub struct HttpTransport {
    client: reqwest::Client,
    auth: DavAuth,
}

impl HttpTransport {
    pub fn new(auth: DavAuth) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("comail-caldav/0.1")
            .timeout(std::time::Duration::from_secs(45))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| CoreError::CalDav(format!("http client: {e}")))?;
        Ok(Self { client, auth })
    }
}

#[async_trait::async_trait]
impl Transport for HttpTransport {
    async fn request(
        &self,
        method: &str,
        url: &str,
        depth: Option<&str>,
        extra: &[(&str, &str)],
        body: Option<String>,
    ) -> Result<DavResponse> {
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| CoreError::CalDav(format!("bad method {method}")))?;
        let mut req = self.client.request(method, url);
        req = match &self.auth {
            DavAuth::Bearer(token) => req.bearer_auth(token),
            DavAuth::Basic(user, pass) => req.basic_auth(user, Some(pass)),
        };
        if let Some(d) = depth {
            req = req.header("Depth", d);
        }
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        if let Some(b) = body {
            if !has_content_type(extra) {
                req = req.header("Content-Type", XML_CONTENT_TYPE);
            }
            req = req.body(b);
        }
        let resp = req.send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                CoreError::Offline
            } else {
                CoreError::CalDav(format!("request: {e}"))
            }
        })?;
        let status = resp.status().as_u16();
        if status == 401 {
            return Err(CoreError::NeedsReauth);
        }
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = resp
            .text()
            .await
            .map_err(|e| CoreError::CalDav(format!("body: {e}")))?;
        Ok(DavResponse { status, etag, body })
    }
}

/// Canned-response transport for tests: pops responses in order and records
/// every request it saw.
#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
pub struct MockTransport {
    pub responses: std::sync::Mutex<std::collections::VecDeque<DavResponse>>,
    pub seen: std::sync::Mutex<Vec<(String, String, Option<String>)>>, // (method, url, body)
    pub headers_seen: std::sync::Mutex<Vec<HashMap<String, String>>>,
}

#[cfg(test)]
impl MockTransport {
    pub fn new(responses: Vec<DavResponse>) -> Self {
        Self {
            responses: std::sync::Mutex::new(responses.into()),
            seen: std::sync::Mutex::new(Vec::new()),
            headers_seen: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl Transport for MockTransport {
    async fn request(
        &self,
        method: &str,
        url: &str,
        depth: Option<&str>,
        extra: &[(&str, &str)],
        body: Option<String>,
    ) -> Result<DavResponse> {
        let mut headers: HashMap<String, String> = extra
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if let Some(d) = depth {
            headers.insert("Depth".into(), d.to_string());
        }
        // Mirror HttpTransport: the XML default applies only when the caller
        // did not name a Content-Type, so tests see the effective headers.
        if body.is_some() && !has_content_type(extra) {
            headers.insert("Content-Type".into(), XML_CONTENT_TYPE.to_string());
        }
        self.seen
            .lock()
            .unwrap()
            .push((method.to_string(), url.to_string(), body));
        self.headers_seen.lock().unwrap().push(headers);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| CoreError::CalDav("mock transport exhausted".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_content_type_is_detected_case_insensitively() {
        assert!(!has_content_type(&[]));
        assert!(!has_content_type(&[("If-Match", "\"e0\"")]));
        assert!(has_content_type(&[("Content-Type", "text/calendar")]));
        assert!(has_content_type(&[("content-type", "text/calendar")]));
        assert!(has_content_type(&[("CONTENT-TYPE", "text/calendar")]));
    }

    #[tokio::test]
    async fn xml_default_applies_to_report_but_caller_type_wins() {
        let ok = || DavResponse {
            status: 207,
            etag: None,
            body: String::new(),
        };
        let t = MockTransport::new(vec![ok(), ok()]);
        // REPORT with a body and no caller type: the XML default shows up.
        t.request(
            "REPORT",
            "http://x/cal/",
            Some("1"),
            &[],
            Some("<x/>".into()),
        )
        .await
        .unwrap();
        // A caller-supplied Content-Type (any case) is not shadowed.
        t.request(
            "PUT",
            "http://x/cal/e.ics",
            None,
            &[("content-type", "text/calendar; charset=utf-8")],
            Some("BEGIN:VCALENDAR".into()),
        )
        .await
        .unwrap();
        let headers = t.headers_seen.lock().unwrap();
        assert_eq!(
            headers[0].get("Content-Type").map(String::as_str),
            Some("application/xml; charset=utf-8")
        );
        assert_eq!(
            headers[1].get("content-type").map(String::as_str),
            Some("text/calendar; charset=utf-8")
        );
        assert!(
            !headers[1].contains_key("Content-Type"),
            "no second Content-Type was appended"
        );
    }
}
