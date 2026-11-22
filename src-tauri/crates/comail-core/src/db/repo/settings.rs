use crate::error::Result;
use crate::models::Settings;
use rusqlite::{Connection, OptionalExtension, params};

/// JSON keys of the retired inline client-secret fields. Rows written before
/// the secrets moved to the OS keyring still carry them; `set` keeps them
/// alive (see below) until the startup migration has moved them across.
pub const GOOGLE_CLIENT_SECRET_KEY: &str = "googleClientSecret";
pub const MS_CLIENT_SECRET_KEY: &str = "msClientSecret";

const LEGACY_SECRET_KEYS: [&str; 2] = [GOOGLE_CLIENT_SECRET_KEY, MS_CLIENT_SECRET_KEY];

fn row_json(conn: &Connection) -> Result<Option<serde_json::Value>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM app_settings WHERE key = 'settings'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.and_then(|s| serde_json::from_str(&s).ok()))
}

pub fn get(conn: &Connection) -> Result<Settings> {
    let json: Option<String> = conn
        .query_row(
            "SELECT value FROM app_settings WHERE key = 'settings'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let mut settings: Settings = json
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
    // Fold any legacy plain-text signatures into the rich model. Migrated data is
    // persisted on the next `set()`.
    settings.migrate_signatures();
    settings.migrate_themes();
    Ok(settings)
}

/// Legacy inline client secrets are the last copy standing when the keyring
/// migration has not run or keeps failing (locked keychain, headless box):
/// `set` must keep them in the row. `skip_serializing` drops them from the
/// outgoing JSON, so they are re-added here — the incoming value wins, else
/// the previously stored one survives.
fn keep_legacy_secret_keys(
    conn: &Connection,
    settings: &Settings,
    json: &mut serde_json::Value,
) -> Result<()> {
    let Some(obj) = json.as_object_mut() else {
        return Ok(());
    };
    let stored = row_json(conn)?;
    for (key, incoming) in [
        (
            GOOGLE_CLIENT_SECRET_KEY,
            settings.google_client_secret.trim(),
        ),
        (MS_CLIENT_SECRET_KEY, settings.ms_client_secret.trim()),
    ] {
        let keep = if !incoming.is_empty() {
            Some(incoming.to_string())
        } else {
            stored
                .as_ref()
                .and_then(|v| v.get(key))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        if let Some(secret) = keep {
            obj.insert(key.to_string(), serde_json::Value::String(secret));
        }
    }
    Ok(())
}

pub fn set(conn: &Connection, settings: &Settings) -> Result<()> {
    let mut json = serde_json::to_value(settings)?;
    keep_legacy_secret_keys(conn, settings, &mut json)?;
    conn.execute(
        "INSERT INTO app_settings (key, value) VALUES ('settings', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![serde_json::to_string(&json)?],
    )?;
    Ok(())
}

/// Drop one retired inline-secret key from the stored row, keeping every
/// other key verbatim (including ones a newer schema might add). Only called
/// once the value is verified in the OS keyring — or when the user clears it.
/// Returns whether the key was present.
pub fn strip_legacy_secret_key(conn: &Connection, key: &str) -> Result<bool> {
    if !LEGACY_SECRET_KEYS.contains(&key) {
        return Ok(false);
    }
    let Some(mut json) = row_json(conn)? else {
        return Ok(false);
    };
    let removed = json
        .as_object_mut()
        .map(|obj| obj.remove(key).is_some())
        .unwrap_or(false);
    if removed {
        conn.execute(
            "UPDATE app_settings SET value = ?1 WHERE key = 'settings'",
            params![serde_json::to_string(&json)?],
        )?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::testutil;

    #[test]
    fn defaults_when_unset_and_roundtrip() {
        let c = testutil::conn();
        let d = get(&c).unwrap();
        assert!(d.notifications_enabled);
        assert!(d.auto_advance);
        assert!(d.auto_labels_enabled);
        assert_eq!(d.calendar_week_start, "monday");
        assert_eq!(d.inbox_ui, "classic");
        assert!(d.show_sender_photos);
        assert_eq!(d.accent_color, "violet");
        assert_eq!(d.font_family, "");

        let mut s = d.clone();
        s.theme = "carbon".into();
        s.calendar_week_start = "sunday".into();
        s.inbox_ui = "avatar".into();
        s.show_sender_photos = false;
        s.notifications_enabled = false;
        s.signature_list.push(crate::models::Signature {
            id: "a".into(),
            account_id: 1,
            name: "Work".into(),
            html: "<b>Dean</b>".into(),
        });
        s.signature_defaults.insert(
            "1".into(),
            crate::models::SignatureDefaults {
                new_id: Some("a".into()),
                reply_id: None,
            },
        );
        s.ai_automation_rules.push(crate::models::AiAutomationRule {
            id: "invoice".into(),
            name: "Invoices".into(),
            source_prompt: "For vendor invoices, move to Important".into(),
            instruction: "It is a vendor invoice".into(),
            enabled: true,
            condition: None,
            min_confidence: None,
            actions: vec![crate::models::AiAutomationAction {
                kind: "route_to".into(),
                value: "important".into(),
            }],
        });
        set(&c, &s).unwrap();

        let back = get(&c).unwrap();
        assert_eq!(back.theme, "carbon");
        assert_eq!(back.calendar_week_start, "sunday");
        assert_eq!(back.inbox_ui, "avatar");
        assert!(!back.show_sender_photos);
        assert!(!back.notifications_enabled);
        assert_eq!(back.signature_list.len(), 1);
        assert_eq!(back.signature_list[0].html, "<b>Dean</b>");
        assert_eq!(back.ai_automation_rules, s.ai_automation_rules);
        assert_eq!(
            back.signature_defaults
                .get("1")
                .and_then(|d| d.new_id.as_deref()),
            Some("a")
        );
    }

    /// A legacy plain-text `signatures` blob is folded into the rich model on
    /// read: one named signature per account, set as both new and reply default.
    #[test]
    fn legacy_signatures_migrate_on_read() {
        let c = testutil::conn();
        c.execute(
            "INSERT INTO app_settings (key, value) VALUES ('settings',
             '{\"theme\":\"snow\",\"undoSendSeconds\":10,\"loadRemoteImages\":false,\"signatures\":{\"1\":\"Best,\\nDean\"}}')",
            [],
        )
        .unwrap();
        let s = get(&c).unwrap();
        assert!(s.signatures.is_empty(), "legacy field cleared after fold");
        assert_eq!(s.signature_list.len(), 1);
        let sig = &s.signature_list[0];
        assert_eq!(sig.account_id, 1);
        assert_eq!(sig.html, "Best,<br>Dean");
        let def = s.signature_defaults.get("1").unwrap();
        assert_eq!(def.new_id.as_deref(), Some(sig.id.as_str()));
        assert_eq!(def.reply_id.as_deref(), Some(sig.id.as_str()));
    }

    /// The retired "holiday" theme reads back as Snow, globally and per account.
    #[test]
    fn holiday_theme_migrates_to_snow() {
        let c = testutil::conn();
        c.execute(
            "INSERT INTO app_settings (key, value) VALUES ('settings',
             '{\"theme\":\"holiday\",\"undoSendSeconds\":10,\"loadRemoteImages\":false,\"accountThemes\":{\"1\":\"holiday\",\"2\":\"carbon\"}}')",
            [],
        )
        .unwrap();
        let s = get(&c).unwrap();
        assert_eq!(s.theme, "snow");
        assert_eq!(s.account_themes.get("1").map(String::as_str), Some("snow"));
        assert_eq!(
            s.account_themes.get("2").map(String::as_str),
            Some("carbon")
        );
        assert_eq!(s.accent_color, "violet");
    }

    /// Blobs written before new fields existed must deserialize with defaults.
    #[test]
    fn old_blob_gets_field_defaults() {
        let c = testutil::conn();
        c.execute(
            "INSERT INTO app_settings (key, value) VALUES ('settings',
             '{\"theme\":\"snow\",\"undoSendSeconds\":20,\"loadRemoteImages\":true}')",
            [],
        )
        .unwrap();
        let s = get(&c).unwrap();
        assert_eq!(s.theme, "snow");
        assert_eq!(s.undo_send_seconds, 20);
        assert!(s.load_remote_images);
        assert_eq!(s.calendar_week_start, "monday");
        assert_eq!(s.inbox_ui, "classic");
        assert!(s.show_sender_photos);
        // serde defaults for everything added since
        assert!(s.notifications_enabled);
        assert!(s.auto_advance);
        assert!(s.auto_labels_enabled);
        assert!(s.ai_automation_rules.is_empty());
        assert!(s.signatures.is_empty());
        assert!(s.ai_zero_retention);
        assert!(s.ai_quick_replies);
    }

    /// Rows written before secrets moved to the keyring still deserialize:
    /// the inline values land in the retired fields for the migration.
    #[test]
    fn legacy_client_secrets_deserialize_but_never_serialize() {
        let c = testutil::conn();
        c.execute(
            "INSERT INTO app_settings (key, value) VALUES ('settings',
             '{\"theme\":\"snow\",\"undoSendSeconds\":10,\"loadRemoteImages\":true,
               \"googleClientSecret\":\"g-secret\",\"msClientSecret\":\"ms-secret\"}')",
            [],
        )
        .unwrap();
        let s = get(&c).unwrap();
        assert_eq!(s.google_client_secret, "g-secret");
        assert_eq!(s.ms_client_secret, "ms-secret");
        let out = serde_json::to_string(&s).unwrap();
        assert!(!out.contains("g-secret"));
        assert!(!out.contains("ms-secret"));
        assert!(!out.contains("googleClientSecret"));
        assert!(!out.contains("msClientSecret"));
    }

    /// Any settings write (not just the migration) must keep an unmigrated
    /// inline secret in the row: while the keyring is unavailable it is the
    /// only copy sign-in can still use.
    #[test]
    fn set_preserves_unmigrated_legacy_secrets() {
        let c = testutil::conn();
        c.execute(
            "INSERT INTO app_settings (key, value) VALUES ('settings',
             '{\"theme\":\"snow\",\"undoSendSeconds\":10,\"loadRemoteImages\":true,
               \"googleClientSecret\":\"g-secret\",\"msClientSecret\":\"ms-secret\"}')",
            [],
        )
        .unwrap();
        // A whole-object write from a client that no longer knows the fields.
        let mut s = get(&c).unwrap();
        s.theme = "carbon".into();
        s.google_client_secret.clear();
        s.ms_client_secret.clear();
        set(&c, &s).unwrap();
        let raw: String = c
            .query_row(
                "SELECT value FROM app_settings WHERE key = 'settings'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(json["googleClientSecret"], "g-secret");
        assert_eq!(json["msClientSecret"], "ms-secret");
        // And get() keeps exposing them to the migration.
        assert_eq!(get(&c).unwrap().google_client_secret, "g-secret");
    }

    /// A write that still carries an inline value (pre-keyring client while
    /// the keyring was unavailable) stores that newer value, not a stale one.
    #[test]
    fn set_keeps_incoming_inline_secret() {
        let c = testutil::conn();
        let s = Settings {
            google_client_secret: "fresh-secret".into(),
            ..Settings::default()
        };
        set(&c, &s).unwrap();
        let raw: String = c
            .query_row(
                "SELECT value FROM app_settings WHERE key = 'settings'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(json["googleClientSecret"], "fresh-secret");
        assert!(json.get("msClientSecret").is_none());
    }

    /// Once the keyring holds the value, strip drops only the secret keys and
    /// leaves the rest of the row byte-identical.
    #[test]
    fn strip_removes_secret_keys_and_keeps_the_rest() {
        let c = testutil::conn();
        c.execute(
            "INSERT INTO app_settings (key, value) VALUES ('settings',
             '{\"theme\":\"snow\",\"googleClientSecret\":\"g-secret\",
               \"msClientSecret\":\"ms-secret\",\"futureKey\":{\"x\":1}}')",
            [],
        )
        .unwrap();
        assert!(strip_legacy_secret_key(&c, GOOGLE_CLIENT_SECRET_KEY).unwrap());
        let raw: String = c
            .query_row(
                "SELECT value FROM app_settings WHERE key = 'settings'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(json.get("googleClientSecret").is_none());
        assert_eq!(json["msClientSecret"], "ms-secret");
        assert_eq!(json["theme"], "snow");
        assert_eq!(json["futureKey"], serde_json::json!({"x": 1}));
        // Second strip is a no-op; unrelated keys are refused.
        assert!(!strip_legacy_secret_key(&c, GOOGLE_CLIENT_SECRET_KEY).unwrap());
        assert!(!strip_legacy_secret_key(&c, "theme").unwrap());
    }
}
