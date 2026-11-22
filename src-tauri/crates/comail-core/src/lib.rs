//! comail-core: all email logic, no Tauri dependency. The host embeds `Core`,
//! calls its async methods, and forwards `CoreEvent`s to the UI.

pub mod accounts;
pub mod addr;
pub mod ai;
pub mod autolabel;
pub mod avatars;
pub mod caldav;
pub mod calendar;
pub mod carddav;
pub mod config;
pub mod db;
pub mod embed;
pub mod error;
pub mod events;
pub mod graph;
pub mod graphcal;
pub mod imap;
pub mod mcp;
pub mod mime;
pub mod models;
pub mod netguard;
pub mod oauth;
pub mod otp;
pub mod preview;
pub mod provider;
pub mod quarantine;
pub mod queue;
pub mod route;
pub mod scheduler;
pub mod search;
pub mod smtp;
pub mod sync;
pub mod trash;
pub mod unsubscribe;

use crate::accounts::credentials::{self, Slot};
use crate::config::Paths;
use crate::db::Db;
use crate::db::repo;
use crate::embed::Embedder;
use crate::error::{CoreError, Result};
use crate::events::{CoreEvent, EventBus};
use crate::models::*;
use crate::oauth::tokens::TokenProvider;
use crate::sync::engine::{AccountHandle, SyncCmd, SyncCtx, spawn_account};
use rusqlite::OptionalExtension;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

pub use crate::db::repo::notifications::{NotificationOutboxItem, RoutedTab};

/// An AI feature, each routed to a configurable model tier.

/// The AI that answers typed questions for one feature, best first. See
/// [`Core::deciders`].
struct Deciders {
    decision: Vec<ai::decisions::DecisionConfig>,
    chat: Option<ai::AiConfig>,
    min_confidence: f64,
}

impl Deciders {
    fn any(&self) -> bool {
        !self.decision.is_empty() || self.chat.is_some()
    }

    /// Yes/no checks `(id, instruction, min confidence)`; returns the ids that
    /// held. Each decision endpoint is tried in order, then the chat model. An
    /// error means every configured answerer failed (retry later); with none
    /// configured, nothing holds.
    async fn checks(
        &self,
        facts: &route::ThreadFacts,
        checks: &[(String, String, f64)],
    ) -> Result<HashSet<String>> {
        if checks.is_empty() || !self.any() {
            return Ok(HashSet::new());
        }
        let state = route::decision_state(&facts.from_addr, &facts.subject, &facts.snippet);
        let questions: Vec<(String, ai::decisions::Question)> = checks
            .iter()
            .map(|(id, instr, _)| (id.clone(), route::check_question(instr)))
            .collect();
        let mut last_err = None;
        for cfg in &self.decision {
            match ai::decisions::decide(cfg, &state, &questions).await {
                Ok(answers) => {
                    return Ok(checks
                        .iter()
                        .filter(|(id, _, min)| answers.get(id).is_some_and(|a| a.yes(*min)))
                        .map(|(id, _, _)| id.clone())
                        .collect());
                }
                Err(e) => {
                    tracing::warn!("decision provider {} failed: {e}", cfg.provider);
                    last_err = Some(e);
                }
            }
        }
        if let Some(cfg) = &self.chat {
            let pairs: Vec<(String, String)> = checks
                .iter()
                .map(|(id, instr, _)| (id.clone(), instr.clone()))
                .collect();
            let (msgs, schema) =
                route::predicate_prompt(&pairs, &facts.from_addr, &facts.subject, &facts.snippet);
            match ai::chat_structured(cfg, msgs, "checks", schema).await {
                Ok(out) => match route::parse_predicates(&out) {
                    Some(yes) => return Ok(yes),
                    None => last_err = Some(CoreError::Other("ai checks: unreadable reply".into())),
                },
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| CoreError::Other("ai checks: no answer".into())))
    }

    /// The category keyword for an email (`None` = no category).
    async fn category(
        &self,
        facts: &route::ThreadFacts,
        prompt: &str,
        catalog: &[route::CategoryDef],
    ) -> Result<Option<String>> {
        let state = route::decision_state(&facts.from_addr, &facts.subject, &facts.snippet);
        let question = route::category_question(prompt, catalog);
        let mut last_err = None;
        for cfg in &self.decision {
            match ai::decisions::decide(cfg, &state, &[("category".into(), question.clone())]).await
            {
                Ok(answers) => {
                    return Ok(answers.get("category").and_then(|a| {
                        route::category_from_answer(a, self.min_confidence, catalog)
                    }));
                }
                Err(e) => {
                    tracing::warn!("decision provider {} failed: {e}", cfg.provider);
                    last_err = Some(e);
                }
            }
        }
        if let Some(cfg) = &self.chat {
            let msgs = route::category_prompt_for(
                prompt,
                catalog,
                &facts.from_addr,
                &facts.subject,
                &facts.snippet,
            );
            match ai::chat(cfg, msgs).await {
                Ok(out) => return Ok(route::parse_category_for(&out, catalog)),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| CoreError::Other("ai category: no answer".into())))
    }
}

#[derive(Clone, Copy)]
enum Scenario {
    /// Ask-your-inbox agentic Q&A.
    Ask,
    /// Drafting / rewriting replies.
    Draft,
    /// Thread summaries.
    Summarize,
    /// Learning the user's writing voice.
    Voice,
    /// Palette natural-language commands (tiny prompt, latency-sensitive).
    Command,
    /// One-tap quick-reply chips (tiny output, latency-sensitive).
    QuickReply,
    /// Sorting incoming mail into categories at sync (short prompt, per-email).
    Categorize,
}

impl Scenario {
    fn as_str(self) -> &'static str {
        match self {
            Scenario::Ask => "ask",
            Scenario::Draft => "draft",
            Scenario::Summarize => "summarize",
            Scenario::Voice => "voice",
            Scenario::Command => "command",
            Scenario::QuickReply => "quick_reply",
            Scenario::Categorize => "automation",
        }
    }
}

/// Resolve the model id a scenario should use: its configured tier's model, or
/// the legacy single `ai_model` when that tier is left blank.
fn resolve_ai_model(settings: &Settings, scenario: Scenario) -> String {
    let tier = match scenario {
        Scenario::Ask => settings.ai_tier_ask.as_str(),
        Scenario::Draft => settings.ai_tier_draft.as_str(),
        Scenario::Summarize => settings.ai_tier_summarize.as_str(),
        Scenario::Voice => settings.ai_tier_voice.as_str(),
        Scenario::Categorize => settings.ai_tier_categorize.as_str(),
        // Palette parsing and reply chips want the fastest model available.
        Scenario::Command | Scenario::QuickReply => "instant",
    };
    let picked = match tier {
        "instant" => &settings.ai_model_instant,
        "cheap" => &settings.ai_model_cheap,
        "intelligent" => &settings.ai_model_intelligent,
        _ => &settings.ai_model,
    };
    if picked.trim().is_empty() {
        settings.ai_model.clone()
    } else {
        picked.clone()
    }
}

#[derive(Clone)]
pub struct Core {
    pub db: Db,
    pub bus: EventBus,
    paths: Arc<Paths>,
    tokens: TokenProvider,
    handles: Arc<RwLock<HashMap<i64, AccountHandle>>>,
    cal_handles: Arc<RwLock<HashMap<i64, caldav::task::CalTaskHandle>>>,
    /// Read-only CardDAV contact sync tasks, one per connected account.
    contacts_handles: Arc<RwLock<HashMap<i64, carddav::task::ContactsTaskHandle>>>,
    /// Per-attachment single-flight locks. Concurrent preview/open/save calls
    /// share one remote fetch and cannot race the same `.download.part` file.
    attachment_locks:
        Arc<tokio::sync::Mutex<HashMap<i64, std::sync::Weak<tokio::sync::Mutex<()>>>>>,
    /// Serializes account creation against removal: SQLite recycles INTEGER
    /// PRIMARY KEY values, so an add must wait for a remove's post-commit
    /// file deletion before it can land on a recycled id.
    account_lifecycle: Arc<tokio::sync::Mutex<()>>,
    embed: Arc<embed::EmbedState>,
    /// Fired by `cancel_oauth` to abort a pending browser sign-in (the
    /// loopback wait otherwise blocks the UI until its 5-minute timeout).
    oauth_cancel: Arc<tokio::sync::Notify>,
    /// Fired by `notify_ui_ready` once the frontend has finished its startup
    /// show (the first-run intro). Account actors wait for this before
    /// touching OAuth tokens, so the OS keyring prompt never lands on top of
    /// the intro. A timeout fallback keeps tray-only/headless syncing alive.
    ui_ready: Arc<tokio::sync::Notify>,
    /// Serializes AI routing passes so the background router and an inline
    /// re-sort never classify the same 'pending' threads twice.
    ai_router_lock: Arc<tokio::sync::Mutex<()>>,
    /// Local MCP server for AI clients (see `mcp`).
    mcp: Arc<mcp::McpManager>,
}

impl Core {
    pub async fn start(paths: Paths) -> Result<Core> {
        paths.ensure()?;
        let db = Db::open(&paths.db_file())?;
        // Consume migration/discovery repair evidence before actors can GC action history.
        let repaired = db.write(trash::repair_legacy_trash_intent).await?;
        if repaired > 0 {
            tracing::info!(
                messages = repaired,
                "restored legacy Trash intent into canonical Trash"
            );
        }
        let bus = EventBus::new();
        let core = Core {
            db,
            bus,
            paths: Arc::new(paths),
            tokens: TokenProvider::new(),
            handles: Arc::new(RwLock::new(HashMap::new())),
            cal_handles: Arc::new(RwLock::new(HashMap::new())),
            contacts_handles: Arc::new(RwLock::new(HashMap::new())),
            attachment_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            account_lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            embed: Arc::new(embed::EmbedState::new()),
            oauth_cancel: Arc::new(tokio::sync::Notify::new()),
            ui_ready: Arc::new(tokio::sync::Notify::new()),
            ai_router_lock: Arc::new(tokio::sync::Mutex::new(())),
            mcp: Arc::new(mcp::McpManager::default()),
        };

        // Make saved OAuth app registrations available before any actor
        // needs a token refresh.
        let settings = core.db.read(|conn| repo::settings::get(conn)).await?;
        apply_oauth_settings(&settings);

        // Recover any actions orphaned mid-flight by a previous crash/kill, so a
        // send that was executing when the app died retries instead of sticking
        // on "Sending…" forever.
        match core
            .db
            .write(|conn| repo::actions::recover_inflight(conn))
            .await
        {
            Ok(n) if n > 0 => tracing::info!("recovered {n} orphaned in-flight action(s)"),
            _ => {}
        }
        // Reclaim staged draft attachments whose rows are gone (crashed saves,
        // pre-fix deletes/sends). The one-hour grace keeps an in-flight save's
        // not-yet-committed staging safe.
        match sweep_draft_attachment_staging(
            &core.db,
            &core.paths.draft_attachments_dir(),
            std::time::Duration::from_secs(60 * 60),
        )
        .await
        {
            Ok(n) if n > 0 => {
                tracing::info!("swept {n} unreferenced draft-attachment dir(s)")
            }
            Err(error) => tracing::warn!(%error, "draft-attachment sweep failed"),
            _ => {}
        }
        match core
            .db
            .write(|conn| {
                Ok(conn.execute(
                    "UPDATE messages SET body_state = 'none' WHERE body_state = 'fetching'",
                    [],
                )?)
            })
            .await
        {
            Ok(n) if n > 0 => tracing::info!("recovered {n} orphaned content fetch(es)"),
            _ => {}
        }
        match core
            .db
            .write(repo::messages::requeue_misdecoded_bodies)
            .await
        {
            Ok(ids) if !ids.is_empty() => tracing::info!(
                count = ids.len(),
                "requeued cached bodies with undecoded MIME transfer encoding"
            ),
            Err(error) => tracing::warn!(
                %error,
                "could not scan cached bodies for MIME transfer-encoding recovery"
            ),
            _ => {}
        }
        match core
            .db
            .write(repo::messages::repair_escaped_html_snippets)
            .await
        {
            Ok(ids) if !ids.is_empty() => {
                tracing::info!(count = ids.len(), "repaired cached HTML message previews")
            }
            Err(error) => tracing::warn!(
                %error,
                "could not repair cached HTML message previews"
            ),
            _ => {}
        }

        // Spawn actors for existing accounts - but only after the frontend
        // reports ready (notify_ui_ready). Actors immediately load OAuth
        // tokens from the OS keyring, and on a launch that plays the intro
        // that prompt must land after the show, not on top of it. The timeout
        // fallback keeps sync alive if no frontend ever reports in (tray-only
        // or a hung webview).
        {
            let core = core.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = core.ui_ready.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                }
                // Resume account removals interrupted mid-flight (crash/kill
                // between the durable marker and the delete commit, or a
                // repair that failed and kept its marker) - strictly before
                // listing configs, so a marked account never starts syncing
                // again. This runs in the deferred task, not inline in
                // start(), so a large interrupted removal does not hold the
                // Tauri setup blocking the first window; marked accounts are
                // already hidden from accounts::list. On success
                // remove_account clears the marker itself; on failure its
                // error path already repaired the index, and we do NOT call
                // restore_account_tasks here - the spawn loop below picks the
                // account back up (a still-marked account is filtered out of
                // list_configs and stays idle for the next start's resume).
                for account_id in core
                    .db
                    .read(|conn| repo::accounts::removal_markers(conn))
                    .await
                    .unwrap_or_default()
                {
                    let exists = core
                        .db
                        .read(move |conn| Ok(repo::accounts::get(conn, account_id)?.is_some()))
                        .await
                        .unwrap_or(false);
                    if !exists {
                        // Marker without an account row cannot happen (it is
                        // cleared in the same commit as the delete) - sweep
                        // it anyway.
                        let _ = core
                            .db
                            .write(move |conn| repo::accounts::unmark_removing(conn, account_id))
                            .await;
                        continue;
                    }
                    match core.remove_account_inner(account_id, false).await {
                        Ok(()) => {
                            tracing::info!(account_id, "resumed interrupted account removal")
                        }
                        Err(error) => tracing::warn!(
                            account_id,
                            %error,
                            "resumed account removal failed; account stays usable, marker kept"
                        ),
                    }
                }
                sweep_removal_tombstones(&core.paths).await;
                let configs = match core
                    .db
                    .read(|conn| repo::accounts::list_configs(conn))
                    .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("listing accounts for startup sync: {e}");
                        return;
                    }
                };
                for cfg in configs {
                    core.spawn_actor(cfg).await;
                }
                // Calendar sync tasks for accounts with a connected CalDAV server.
                if let Ok(cal_accounts) = core.db.read(|conn| repo::caldav::all_configs(conn)).await
                {
                    for cfg in cal_accounts {
                        core.spawn_cal_task(cfg.account_id).await;
                    }
                }
                // Contact sync tasks for accounts with a connected CardDAV server.
                if let Ok(card_accounts) =
                    core.db.read(|conn| repo::carddav::all_configs(conn)).await
                {
                    for cfg in card_accounts {
                        core.spawn_contacts_task(cfg.account_id).await;
                    }
                }
            });
        }

        scheduler::spawn(
            core.db.clone(),
            core.bus.clone(),
            core.handles.clone(),
            core.cal_handles.clone(),
        );

        // Make the bundled default model available for offline first run, then
        // start the background embedding worker.
        core.provision_bundled_model().await;
        embed::worker::spawn(core.db.clone(), core.embed.clone(), core.paths.clone());

        // One-shot routing backfill: on a fresh 007 install or an upgrade to the
        // 014 routing column, resolve every existing thread's tab once. Guarded
        // by a marker row so it never repeats (preserved across reroute_all).
        {
            let c = core.clone();
            tokio::spawn(async move {
                let (marker, threads, auto) =
                    c.db.read(|conn| {
                        let s = repo::settings::get(conn)?;
                        let marker: i64 = conn.query_row(
                            "SELECT COUNT(*) FROM route_cache
                             WHERE sender_domain = '__routing_backfill__'",
                            [],
                            |r| r.get(0),
                        )?;
                        let threads: i64 =
                            conn.query_row("SELECT COUNT(*) FROM threads", [], |r| r.get(0))?;
                        Ok((marker, threads, s.auto_labels_enabled))
                    })
                    .await
                    .unwrap_or((1, 0, false));
                if marker == 0 {
                    if auto && threads > 0 {
                        match c.resort(false).await {
                            Ok(n) => tracing::info!("routing backfill resolved {n} threads"),
                            Err(e) => tracing::warn!("routing backfill failed: {e}"),
                        }
                    }
                    let _ =
                        c.db.write(|conn| {
                            conn.execute(
                                "INSERT OR REPLACE INTO route_cache (sender_domain, route_key)
                                 VALUES ('__routing_backfill__', '1')",
                                [],
                            )?;
                            Ok(())
                        })
                        .await;
                }
            });
        }

        // Background AI router: drains threads marked 'pending' into a category
        // whenever mail changes. Decoupled from sync so LLM latency never blocks
        // the sync loop.
        {
            let c = core.clone();
            tokio::spawn(async move { c.ai_router_loop().await });
        }

        // MCP server for AI clients, when the user turned it on.
        if let Err(e) = core.mcp_apply_settings().await {
            tracing::warn!("mcp: start failed: {e}");
        }

        Ok(core)
    }

    /// Long-lived loop: on every mail change, drain the AI routing queue in
    /// bounded batches. Serial (one broadcast receiver), so batches never
    /// overlap; the self-emitted refresh settles after one empty pass.
    async fn ai_router_loop(&self) {
        use tokio::sync::broadcast::error::RecvError;
        let mut rx = self.bus.subscribe();
        // Consecutive failed passes; drives an exponential pause (5s doubling,
        // capped at 10 min) so an unreachable model or exhausted quota isn't
        // hammered on every mail change.
        let mut failures: u32 = 0;
        loop {
            match rx.recv().await {
                Ok(CoreEvent::MailUpdated { .. }) => loop {
                    // Automations first: a matching rule's route_to then wins
                    // over the category the classifier would pick.
                    let automated = self.run_automations(50).await;
                    let classified = self.classify_pending(50).await;
                    let progressed =
                        matches!(automated, Ok(n) if n > 0) || matches!(classified, Ok(n) if n > 0);
                    if progressed {
                        failures = 0;
                        continue;
                    }
                    let Some(e) = automated.err().or(classified.err()) else {
                        break;
                    };
                    failures = failures.saturating_add(1);
                    let wait = std::time::Duration::from_secs((5u64 << failures.min(7)).min(600));
                    tracing::warn!("ai routing pass failed, pausing {wait:?}: {e}");
                    tokio::time::sleep(wait).await;
                    // Events that piled up while paused are stale.
                    rx = rx.resubscribe();
                    break;
                },
                Ok(_) => {}
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            }
        }
    }

    /// Copy the installer-bundled default model into the data dir if it isn't
    /// there yet, so semantic search works with no network on first launch.
    /// Best-effort: if the resource is missing (e.g. dev builds), the worker
    /// falls back to downloading on demand.
    async fn provision_bundled_model(&self) {
        let models_dir = self.paths.models_dir();
        let spec = embed::spec_or_default(embed::DEFAULT_MODEL);
        if embed::model_present(&models_dir, spec.key) {
            return;
        }
        if let Some(src) = bundled_model_dir(spec.key) {
            let dst = embed::model_dir(&models_dir, spec.key);
            if let Err(e) = copy_model_files(&src, &dst).await {
                tracing::warn!("bundled model copy failed: {e}");
            }
        }
    }

    fn sync_ctx(&self) -> SyncCtx {
        SyncCtx {
            db: self.db.clone(),
            bus: self.bus.clone(),
            paths: self.paths.clone(),
            tokens: self.tokens.clone(),
        }
    }

    async fn spawn_actor(&self, cfg: AccountConfig) {
        let handle = spawn_account(self.sync_ctx(), cfg);
        // A respawn stops whatever the previous task set was still doing;
        // Shutdown takes the same stop path account removal uses.
        if let Some(old) = self.handles.write().await.insert(handle.account_id, handle) {
            old.send(SyncCmd::Shutdown);
        }
    }

    async fn spawn_cal_task(&self, account_id: i64) {
        let handle = caldav::task::spawn(
            self.db.clone(),
            self.bus.clone(),
            self.tokens.clone(),
            account_id,
        );
        self.cal_handles.write().await.insert(account_id, handle);
    }

    async fn spawn_contacts_task(&self, account_id: i64) {
        let handle = carddav::task::spawn(self.db.clone(), self.bus.clone(), account_id);
        self.contacts_handles
            .write()
            .await
            .insert(account_id, handle);
    }

    async fn nudge_contacts(&self, account_id: Option<i64>) {
        let handles = self.contacts_handles.read().await;
        match account_id {
            Some(id) => {
                if let Some(h) = handles.get(&id) {
                    h.nudge();
                }
            }
            None => {
                for h in handles.values() {
                    h.nudge();
                }
            }
        }
    }

    async fn nudge_cal(&self, account_id: Option<i64>) {
        let handles = self.cal_handles.read().await;
        match account_id {
            Some(id) => {
                if let Some(h) = handles.get(&id) {
                    h.nudge();
                }
            }
            None => {
                for h in handles.values() {
                    h.nudge();
                }
            }
        }
    }

    async fn nudge(&self, account_id: Option<i64>, cmd_for: impl Fn() -> SyncCmd) {
        let handles = self.handles.read().await;
        match account_id {
            Some(id) => {
                if let Some(h) = handles.get(&id) {
                    h.send(cmd_for());
                }
            }
            None => {
                for h in handles.values() {
                    h.send(cmd_for());
                }
            }
        }
    }

    // ---------- accounts ----------

    pub async fn list_accounts(&self) -> Result<Vec<Account>> {
        self.db.read(|conn| repo::accounts::list(conn)).await
    }

    pub async fn test_connection(&self, args: &AddPasswordAccountArgs) -> ConnectionTestResult {
        let creds = imap::ImapCredentials::Password {
            user: args.username.clone(),
            password: args.password.clone(),
        };
        match imap::connect(&args.imap_host, args.imap_port, creds).await {
            Ok(session) => {
                imap::logout(session).await;
                ConnectionTestResult {
                    ok: true,
                    error: None,
                }
            }
            Err(e) => ConnectionTestResult {
                ok: false,
                error: Some(e.to_ipc_json()),
            },
        }
    }

    pub async fn add_account_password(&self, args: AddPasswordAccountArgs) -> Result<Account> {
        // Verify credentials before storing anything.
        let probe = self.test_connection(&args).await;
        if !probe.ok {
            return Err(CoreError::Auth(
                probe.error.unwrap_or_else(|| "connection failed".into()),
            ));
        }

        let a = args.clone();
        // The insert may land on a recycled id; it must wait for a removal of
        // the previous owner to finish deleting its files.
        let _lifecycle = self.account_lifecycle.lock().await;
        let id = self
            .db
            .write(move |conn| {
                repo::accounts::insert(
                    conn,
                    &repo::accounts::NewAccount {
                        email: &a.email,
                        display_name: a.display_name.as_deref(),
                        provider: Provider::Imap,
                        auth_kind: AuthKind::Password,
                        username: &a.username,
                        imap_host: &a.imap_host,
                        imap_port: a.imap_port,
                        smtp_host: &a.smtp_host,
                        smtp_port: a.smtp_port,
                    },
                )
            })
            .await?;

        credentials::store_async(id, Slot::Password, args.password.clone()).await?;

        let cfg = self
            .db
            .read(move |conn| repo::accounts::get_config(conn, id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))?;
        self.spawn_actor(cfg).await;

        self.db
            .read(move |conn| repo::accounts::get(conn, id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))
    }

    /// Abort any sign-in currently waiting on the browser redirect.
    pub fn cancel_oauth(&self) {
        tracing::info!("oauth: sign-in cancelled by user");
        self.oauth_cancel.notify_waiters();
    }

    /// The frontend calls this once its startup show (the first-run intro) is
    /// out of the way - or immediately when there is no show. Releases the
    /// deferred account-actor spawn in [`Core::start`], which is what first
    /// touches the OS keyring. `notify_one` stores a permit, so the order of
    /// caller vs. waiter never matters.
    pub fn notify_ui_ready(&self) {
        self.ui_ready.notify_one();
    }

    pub async fn start_oauth(
        &self,
        provider: Provider,
        open_url: impl FnOnce(String) + Send,
    ) -> Result<Account> {
        // Microsoft: fold the Teams (Graph) scope into the sign-in consent so
        // no second browser prompt is needed the first time a user creates a
        // meeting. The code is still redeemed for the mail resource only (see
        // `flow::authorize_with`); the multi-resource refresh token covers
        // Graph, redeemed on demand by `access_token_for_scope`.
        let consent_extra: &[&str] = match provider {
            Provider::Microsoft => &[
                oauth::providers::MS_ONLINE_MEETINGS_SCOPE,
                oauth::providers::MS_CALENDARS_SCOPE,
            ],
            _ => &[],
        };
        let outcome = tokio::select! {
            r = oauth::flow::authorize_with(provider, consent_extra, None, open_url) => r?,
            _ = self.oauth_cancel.notified() => {
                return Err(CoreError::Auth("sign-in cancelled".into()));
            }
        };
        let servers = match provider {
            Provider::Gmail => &accounts::providers::GMAIL,
            Provider::Microsoft => &accounts::providers::MICROSOFT,
            Provider::Imap => return Err(CoreError::Auth("not an oauth provider".into())),
        };

        let email = outcome.email.clone();
        let name = outcome.name.clone();
        // Same recycled-id guard as add_account_password.
        let _lifecycle = self.account_lifecycle.lock().await;
        let id = self
            .db
            .write(move |conn| {
                repo::accounts::insert(
                    conn,
                    &repo::accounts::NewAccount {
                        email: &email,
                        display_name: name.as_deref(),
                        provider,
                        auth_kind: AuthKind::Oauth2,
                        username: &email,
                        imap_host: servers.imap_host,
                        imap_port: servers.imap_port,
                        smtp_host: servers.smtp_host,
                        smtp_port: servers.smtp_port,
                    },
                )
            })
            .await?;

        self.tokens
            .store_initial(
                id,
                outcome.access_token,
                outcome.expires_in,
                outcome.refresh_token,
            )
            .await?;

        let cfg = self
            .db
            .read(move |conn| repo::accounts::get_config(conn, id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))?;
        self.spawn_actor(cfg).await;

        self.db
            .read(move |conn| repo::accounts::get(conn, id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))
    }

    /// Re-run the OAuth consent for an existing account whose refresh token was
    /// revoked/expired (state `needs_reauth`) and swap in fresh tokens in place.
    /// Unlike `start_oauth` this never inserts a row: it updates the existing
    /// account's credentials and nudges its (paused) actor to reconnect.
    pub async fn reauth_account(
        &self,
        account_id: i64,
        open_url: impl FnOnce(String) + Send,
    ) -> Result<Account> {
        let account = self
            .db
            .read(move |conn| repo::accounts::get(conn, account_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))?;
        // Only OAuth mailboxes reauth through the browser; password/IMAP
        // accounts recover by re-entering credentials in the account editor.
        let consent_extra: &[&str] = match account.provider {
            Provider::Microsoft => &[oauth::providers::MS_ONLINE_MEETINGS_SCOPE],
            Provider::Gmail => &[],
            Provider::Imap => return Err(CoreError::Auth("not an oauth provider".into())),
        };
        let outcome = tokio::select! {
            // Hint the provider at the account being repaired so the browser
            // preselects it instead of silently reusing whatever session is
            // active (which then fails the email match below).
            r = oauth::flow::authorize_with(account.provider, consent_extra, Some(&account.email), open_url) => r?,
            _ = self.oauth_cancel.notified() => {
                return Err(CoreError::Auth("sign-in cancelled".into()));
            }
        };
        // Refuse to graft another mailbox's tokens onto this account. Signing in
        // as a different address is "add account", not "reauth".
        if !outcome.email.eq_ignore_ascii_case(&account.email) {
            return Err(CoreError::Auth(format!(
                "signed in as {} but this account is {}",
                outcome.email, account.email
            )));
        }

        self.tokens
            .store_initial(
                account_id,
                outcome.access_token,
                outcome.expires_in,
                outcome.refresh_token,
            )
            .await?;

        // Accounts added before sign-in asked for the profile name have no
        // sender name; fill it in, but never overwrite one the user set.
        if account.display_name.is_none()
            && let Some(name) = outcome.name
        {
            self.db
                .write(move |conn| repo::accounts::set_display_name(conn, account_id, Some(&name)))
                .await?;
        }

        // Clear needs_reauth and wake the actor. The reauth pause loop retries
        // its connect on the next SyncNow; if no actor is live (e.g. reauth
        // right after launch), spawn one so the fresh tokens take effect.
        self.db
            .write(move |conn| repo::accounts::set_sync_state(conn, account_id, "idle"))
            .await?;
        let has_handle = self.handles.read().await.contains_key(&account_id);
        if has_handle {
            if let Some(handle) = self.handles.read().await.get(&account_id) {
                handle.send(SyncCmd::SyncNow { complete: None });
            }
        } else {
            let cfg = self
                .db
                .read(move |conn| repo::accounts::get_config(conn, account_id))
                .await?
                .ok_or_else(|| CoreError::NotFound("account".into()))?;
            self.spawn_actor(cfg).await;
        }

        self.db
            .read(move |conn| repo::accounts::get(conn, account_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))
    }

    /// Set the sender name used in the From: header (blank clears it, so mail
    /// goes out as the bare address). Sends read it fresh, so it applies to
    /// the next message without restarting the account's actor.
    pub async fn set_account_display_name(&self, account_id: i64, name: &str) -> Result<Account> {
        let name = name.trim();
        if name.chars().count() > repo::accounts::DISPLAY_NAME_MAX_CHARS {
            return Err(CoreError::Other(format!(
                "sender name is longer than {} characters",
                repo::accounts::DISPLAY_NAME_MAX_CHARS
            )));
        }
        if name.chars().any(char::is_control) {
            return Err(CoreError::Other(
                "sender name has a line break or control character".into(),
            ));
        }
        let name = (!name.is_empty()).then(|| name.to_string());
        self.db
            .write(move |conn| {
                repo::accounts::set_display_name(conn, account_id, name.as_deref())?;
                repo::accounts::get(conn, account_id)
            })
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))
    }

    pub async fn remove_account(&self, account_id: i64) -> Result<()> {
        self.remove_account_inner(account_id, true).await
    }

    /// `restore_on_failure`: on a pre-commit error the repair runs either way,
    /// but the task set is only restarted when `true`. Start-up passes `false`
    /// because the account spawn loop that follows resumes the account itself.
    async fn remove_account_inner(&self, account_id: i64, restore_on_failure: bool) -> Result<()> {
        // Detach every per-account entry point first so nothing new can be
        // scheduled for this id while teardown runs. (attachment_locks is
        // keyed by attachment id, not account id - nothing to evict here.)
        let handle = self.handles.write().await.remove(&account_id);
        let cal = self.cal_handles.write().await.remove(&account_id);
        let contacts = self.contacts_handles.write().await.remove(&account_id);

        // Ask the sync actor for a clean IMAP logout; Shutdown also fires the
        // shared stop flag every other task observes at its await points.
        // Then wait - bounded - and abort whatever is still parked in a
        // network call (except the mutation worker, which must settle its
        // in-flight action rather than be cancelled mid-command).
        if let Some(h) = &handle {
            h.send(SyncCmd::Shutdown);
        }
        let deadline = tokio::time::Instant::now() + REMOVE_ACCOUNT_STOP_TIMEOUT;
        if let Some(h) = &handle {
            h.stop_tasks(deadline).await;
        }
        if let Some(h) = &cal {
            h.stop_tasks(deadline).await;
        }
        if let Some(h) = &contacts {
            h.stop_tasks(deadline).await;
        }

        // Everything up to the delete commit is reversible: on any failure,
        // repair the index, put the task set back exactly the way startup
        // would, and leave the account usable - and the removal retryable.
        let removal = async {
            // Durable marker BEFORE the first destructive step. The FTS
            // sweep commits per batch below, so without a marker a crash or
            // a rollback would leave the account's search index silently
            // half-destroyed. With it: a failed removal repairs the index
            // before clearing the marker, and a killed one is resumed at
            // start-up (Core::start reads removal_markers before spawning
            // any account task). `list` hides marked accounts meanwhile.
            self.db
                .write(move |conn| repo::accounts::mark_removing(conn, account_id))
                .await?;

            // Writer-thread barrier: a task aborted inside `db.write` may
            // already have queued its closure. The writer runs jobs FIFO, so
            // this no-op returning proves every straggler write landed -
            // before the delete, where the cascade still erases it - and none
            // can sneak in behind it to be attributed to a recycled id.
            self.removal_barrier().await?;

            // Pre-commit FTS sweep in many small transactions. Inside one
            // transaction the batching buys nothing - the writer is held for
            // the whole delete either way (measured: 21 s for 100k messages
            // in a debug build). Split per batch, other writer jobs interleave
            // between `db.write` calls and the UI stays responsive. The
            // marker above is what makes committed batches safe: any failure
            // from here on re-indexes what was swept.
            loop {
                let swept = self
                    .db
                    .write(move |conn| repo::accounts::sweep_fts_batch(conn, account_id))
                    .await?;
                if swept < repo::accounts::FTS_DELETE_BATCH as usize {
                    break;
                }
            }

            // The id-recycle window: SQLite hands a freed INTEGER PRIMARY
            // KEY to the next inserted account, so from the commit until the
            // account's directories are renamed aside, account creation must
            // not run. Task teardown and the sweep stay outside the lock -
            // while the account row still exists an added account simply
            // gets a different id - which keeps the hold to the measured
            // ~1.6 s cascade + a few renames instead of the whole teardown.
            let _lifecycle = self.account_lifecycle.lock().await;
            let (staged, message_ids) = self
                .db
                .write(move |conn| {
                    let tx = conn.transaction()?;
                    // Unwind address-book names before the cascade drops the cards.
                    repo::carddav::delete_config(&tx, account_id)?;
                    // The account cascade drops draft_attachments rows; collect
                    // their staged paths first so the files can go with them.
                    let staged: Vec<String> = {
                        let mut stmt = tx.prepare(
                            "SELECT da.file_path FROM draft_attachments da
                         JOIN messages m ON m.id = da.draft_id
                         WHERE m.account_id = ?1",
                        )?;
                        stmt.query_map(rusqlite::params![account_id], |r| r.get::<_, String>(0))?
                            .collect::<rusqlite::Result<Vec<_>>>()?
                    };
                    // The account's message ids, for evicting its vectors from
                    // the in-memory index after commit (it is not FK-covered).
                    let message_ids: Vec<i64> = {
                        let mut stmt =
                            tx.prepare("SELECT id FROM messages WHERE account_id = ?1")?;
                        stmt.query_map(rusqlite::params![account_id], |r| r.get::<_, i64>(0))?
                            .collect::<rusqlite::Result<Vec<_>>>()?
                    };
                    repo::accounts::delete(&tx, account_id)?;
                    // Marker clears in the same commit: it can never point
                    // at a successfully deleted account, and a rolled-back
                    // removal keeps it for the repair/resume paths.
                    repo::accounts::unmark_removing(&tx, account_id)?;
                    #[cfg(test)]
                    if REMOVE_FAIL_TX.swap(false, std::sync::atomic::Ordering::SeqCst) {
                        return Err(CoreError::Other("injected delete failure".into()));
                    }
                    tx.commit()?;
                    Ok((staged, message_ids))
                })
                .await?;
            // Rename the account's directories to unique tombstones while the
            // lifecycle lock is still held - milliseconds of work - so the
            // slow recursive deletes below can run AFTER the lock is released
            // without a recycled account id ever seeing its fresh dirs
            // deleted. Staged draft dirs get the same treatment because
            // message ids (and with them `d{id}` staging dir names) recycle
            // the same way. Leftover tombstones are swept at start-up.
            let tombstones = self.tombstone_account_dirs(account_id, &staged).await;
            #[cfg(test)]
            if REMOVE_PAUSE_FOR_ADD.swap(false, std::sync::atomic::Ordering::SeqCst) {
                REMOVE_RESUME_GATE.notified().await;
            }
            // Every step keyed by the account id (or by recyclable message
            // ids) finishes while the lock is still held: the commit ran
            // already, so these are final, and a queued add that recycles the
            // id can only run after this section - it can never lose its own
            // credentials or vectors to a stale cleanup.
            // Credential deletion and token-cache clearing happen atomically
            // under the account's refresh lock: a grant still in flight
            // completes first and its writes are erased by the purge, and a
            // grant queued behind it finds no refresh token - no rotated
            // token can be written back into the keyring and no cache entry
            // resurrected for a removed account.
            self.tokens.purge(account_id).await;
            // The persisted vectors cascaded with the messages; evict the
            // account's copies from the in-memory index too, before any
            // recycled message id can be repopulated.
            if !message_ids.is_empty() {
                let removed: std::collections::HashSet<i64> = message_ids.iter().copied().collect();
                self.embed
                    .index
                    .write()
                    .await
                    .retain(|mid| !removed.contains(&mid));
            }
            // `_lifecycle` drops here: only work on names that cannot be
            // reused (the tombstoned directories) runs after the release.
            Ok(tombstones)
        }
        .await;
        let tombstones = match removal {
            Ok(out) => out,
            Err(error) => {
                // Pre-commit failure or a rolled-back transaction: the
                // account row and all of its data are intact, and credentials
                // have NOT been purged - that only happens past the commit.
                // First rebuild every FTS row the sweep removed - a surviving
                // account must never keep a silently broken search index -
                // then restart the task set so the account keeps working and
                // a retried removal sees a normal state. If repair itself
                // fails the marker stays set: the account is still usable,
                // and the next start-up resumes the removal the user asked
                // for.
                if let Err(repair_error) = self.repair_search_index(account_id).await {
                    tracing::warn!(
                        account_id,
                        error = %repair_error,
                        "rolled-back removal could not rebuild the search index; \
                         marker kept so start-up finishes the removal"
                    );
                }
                if restore_on_failure {
                    self.restore_account_tasks(account_id).await;
                }
                return Err(error);
            }
        };

        // Point of no return passed; only work on names that cannot be
        // reused (the tombstoned directories) runs past this point - the
        // lock is already released, so account adds proceed while the slow
        // recursive deletes drain.
        for dir in tombstones {
            let _ = tokio::fs::remove_dir_all(dir).await;
        }
        Ok(())
    }

    /// Rename every on-disk directory belonging to the account to a unique
    /// sibling tombstone (`<name>.removing-<account>-<nanos>`) and return the
    /// tombstone paths for deletion by the caller. Runs under the lifecycle
    /// lock after the delete commit: renaming is O(1) per dir, so an added
    /// account that recycles the id creates fresh dirs untouched by the slow
    /// `remove_dir_all` of these tombstones afterwards.
    async fn tombstone_account_dirs(
        &self,
        account_id: i64,
        staged_paths: &[String],
    ) -> Vec<std::path::PathBuf> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let token = format!("{account_id}-{nanos}");
        let mut out = Vec::new();
        for dir in [
            self.paths.mail_dir(account_id),
            self.paths.attachments_dir(account_id),
        ] {
            if let Some(t) = tombstone_dir(&dir, &token).await {
                out.push(t);
            }
        }
        // Staged draft attachments: confine to the staging root exactly like
        // remove_staged_draft_files, then tombstone each per-draft directory
        // (`d{id}`) - message ids recycle, so a later draft could own one.
        let root = self.paths.draft_attachments_dir();
        if let Ok(root) = tokio::fs::canonicalize(&root).await {
            let mut dirs = std::collections::HashSet::new();
            for path in staged_paths {
                let Ok(canon) = tokio::fs::canonicalize(path).await else {
                    continue;
                };
                if !canon.starts_with(&root) {
                    tracing::warn!(
                        path,
                        "refusing to remove attachment outside draft staging area"
                    );
                    continue;
                }
                if let Some(dir) = canon.parent()
                    && dir != root
                    && dir.starts_with(&root)
                {
                    dirs.insert(dir.to_path_buf());
                }
            }
            for dir in dirs {
                if let Some(t) = tombstone_dir(&dir, &token).await {
                    out.push(t);
                }
            }
        }
        out
    }

    /// Rebuild every `messages_fts` row the pre-commit sweep removed - the
    /// repair half of the durable removal marker. Batched like the sweep so
    /// the writer stays responsive; on success the marker is cleared, on
    /// failure it stays set for the start-up resume.
    async fn repair_search_index(&self, account_id: i64) -> Result<()> {
        loop {
            let n = self
                .db
                .write(move |conn| {
                    repo::search::reindex_missing_batch(
                        conn,
                        account_id,
                        repo::accounts::FTS_DELETE_BATCH,
                    )
                })
                .await?;
            if n < repo::accounts::FTS_DELETE_BATCH as usize {
                break;
            }
        }
        self.db
            .write(move |conn| repo::accounts::unmark_removing(conn, account_id))
            .await
    }

    /// One no-op job on the single writer thread; see the barrier comment at
    /// the call site in `remove_account`.
    async fn removal_barrier(&self) -> Result<()> {
        #[cfg(test)]
        if REMOVE_FAIL_BARRIER.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(CoreError::Other("injected barrier failure".into()));
        }
        self.db.write(|_| Ok(())).await
    }

    /// Restart the task set `remove_account` detached, for the rollback path:
    /// the sync actor plus the calendar and contacts tasks when their config
    /// rows still exist - the same selection startup makes (list_configs +
    /// all_configs rows), per account.
    async fn restore_account_tasks(&self, account_id: i64) {
        if let Ok(Some(cfg)) = self
            .db
            .read(move |conn| repo::accounts::get_config(conn, account_id))
            .await
        {
            self.spawn_actor(cfg).await;
        }
        if self
            .db
            .read(move |conn| repo::caldav::get_config(conn, account_id))
            .await
            .ok()
            .flatten()
            .is_some_and(|cfg| cfg.enabled)
        {
            self.spawn_cal_task(account_id).await;
        }
        if self
            .db
            .read(move |conn| repo::carddav::get_config(conn, account_id))
            .await
            .ok()
            .flatten()
            .is_some_and(|cfg| cfg.enabled)
        {
            self.spawn_contacts_task(account_id).await;
        }
    }

    /// Account sync handle, if the account's tasks are running. Test hook for
    /// asserting the shared task set is actually finished after removal.
    #[doc(hidden)]
    pub async fn debug_handle(&self, account_id: i64) -> Option<AccountHandle> {
        self.handles.read().await.get(&account_id).cloned()
    }

    /// Shared embedding state; test hook so integration tests can push into
    /// and inspect the live vector index without loading a model.
    #[doc(hidden)]
    pub fn embed_state(&self) -> Arc<embed::EmbedState> {
        self.embed.clone()
    }

    pub async fn sync_now(&self, account_id: Option<i64>) -> Result<()> {
        let receivers = {
            let handles = self.handles.read().await;
            match account_id {
                Some(id) => handles
                    .get(&id)
                    .map(|handle| vec![handle.sync_now()])
                    .ok_or_else(|| CoreError::NotFound(format!("account {id}")))?,
                None => handles.values().map(AccountHandle::sync_now).collect(),
            }
        };
        await_sync_passes(receivers, SYNC_NOW_TIMEOUT).await
    }

    pub async fn get_sync_status(&self) -> Result<Vec<SyncStatus>> {
        let accounts = self.db.read(|conn| repo::accounts::list(conn)).await?;
        let mut statuses = Vec::with_capacity(accounts.len());
        for account in accounts {
            statuses.push(sync::engine::status_for_account(&self.db, account.id).await?);
        }
        Ok(statuses)
    }

    // ---------- reading ----------

    pub async fn list_threads(
        &self,
        view: View,
        split_id: Option<i64>,
        account_id: Option<i64>,
        label_id: Option<i64>,
        folder_id: Option<i64>,
        cursor: Option<i64>,
        limit: i64,
    ) -> Result<ThreadPage> {
        use repo::threads::TabFilter;
        // A category label filters to its single resolved tab; a manual label is
        // a cross-cutting filter. Split conventions: -1 = Important, -2 = Other,
        // positive ids = custom split tabs.
        let tab = if let Some(lid) = label_id {
            let is_auto = self
                .db
                .read(move |conn| Ok(repo::labels::get(conn, lid)?.map(|l| l.is_auto)))
                .await?
                .unwrap_or(false);
            Some(if is_auto {
                TabFilter::AutoLabel(lid)
            } else {
                TabFilter::ManualLabel(lid)
            })
        } else {
            match split_id {
                Some(-1) => Some(TabFilter::Important),
                Some(-2) => Some(TabFilter::Other),
                Some(id) if id > 0 => Some(TabFilter::Split(id)),
                _ => None,
            }
        };
        self.db
            .read(move |conn| {
                repo::threads::list(
                    conn,
                    &repo::threads::ListArgs {
                        view,
                        tab,
                        account_id,
                        folder_id,
                        cursor,
                        limit: limit.clamp(1, 200),
                    },
                )
            })
            .await
    }

    pub async fn get_thread(&self, thread_id: i64) -> Result<ThreadDetail> {
        let t0 = std::time::Instant::now();
        let mut detail = self
            .db
            .read(move |conn| {
                let thread = repo::threads::get_summary(conn, thread_id)?
                    .ok_or_else(|| CoreError::NotFound(format!("thread {thread_id}")))?;
                let messages = repo::messages::list_for_thread(conn, thread_id)?;
                Ok(ThreadDetail { thread, messages })
            })
            .await?;
        let t_db = t0.elapsed();
        // Resolve embedded cid: images to data: URIs so they render in the
        // sandboxed iframe (which can't fetch cid: URLs). Batched: one DB
        // read and one encode pass for the whole thread.
        let pairs: Vec<(i64, String)> = detail
            .messages
            .iter_mut()
            .filter_map(|m| m.html_body.take().map(|h| (m.id, h)))
            .collect();
        let mut resolved = self.inline_cid_images_batch(thread_id, pairs).await;
        for m in &mut detail.messages {
            if let Some(html) = resolved.remove(&m.id) {
                m.html_body = Some(html);
            }
        }
        let t_cid = t0.elapsed() - t_db;
        // Kick off priority fetches for any unfetched bodies. "fetching" is
        // re-nudged too: a fetch command can be dropped (offline, reconnect),
        // and the fetch itself is idempotent once the body is cached. Request
        // newest-first: the last message is the one expanded on open, so it
        // leads the batch and its body fills in first.
        for m in detail.messages.iter().rev() {
            if m.body_state == "none" || m.body_state == "fetching" {
                self.request_body(m.account_id, m.id).await;
            }
        }
        let html_bytes: usize = detail
            .messages
            .iter()
            .filter_map(|m| m.html_body.as_ref().map(String::len))
            .sum();
        tracing::debug!(
            "get_thread {thread_id}: {} msgs, {html_bytes}B html, db {t_db:?}, cid {t_cid:?}, total {:?}",
            detail.messages.len(),
            t0.elapsed()
        );
        Ok(detail)
    }

    async fn request_body(&self, account_id: i64, message_id: i64) {
        let _ = self
            .db
            .write(move |conn| repo::messages::set_body_state(conn, message_id, "fetching"))
            .await;
        self.nudge(Some(account_id), || SyncCmd::FetchBody { message_id })
            .await;
    }

    pub async fn get_body(&self, message_id: i64) -> Result<MessageDetail> {
        let mut detail = self
            .db
            .read(move |conn| repo::messages::detail(conn, message_id))
            .await?;
        if detail.body_state == "none" || detail.body_state == "fetching" {
            self.request_body(detail.account_id, message_id).await;
        }
        if let Some(html) = detail.html_body.take() {
            detail.html_body = Some(self.inline_cid_images(message_id, html).await);
        }
        Ok(detail)
    }

    /// Newest message of `thread_id` that can be unsubscribed from, or None
    /// when the thread genuinely offers no list unsubscribe.
    ///
    /// The stored column alone is not enough to answer this: mail synced before
    /// List-Unsubscribe joined the IMAP header fetch has NULL there even when
    /// the cached raw message carries the header. So on a miss, re-read the
    /// raws we already have on disk (newest first) and persist the first header
    /// found, rather than telling the user there is no unsubscribe link.
    pub async fn thread_unsubscribe_message(&self, thread_id: i64) -> Result<Option<i64>> {
        if let Some(id) = self
            .db
            .read(move |conn| repo::messages::thread_unsubscribe_message(conn, thread_id))
            .await?
        {
            return Ok(Some(id));
        }
        let candidates = self
            .db
            .read(move |conn| repo::messages::thread_unsubscribe_candidates(conn, thread_id))
            .await?;
        for (id, raw_path) in candidates {
            let Ok(raw) = tokio::fs::read(&raw_path).await else {
                continue;
            };
            let Ok(headers) = crate::mime::parse_header_block(&raw) else {
                continue;
            };
            let Some(list_unsubscribe) = headers.list_unsubscribe else {
                continue;
            };
            let post = headers.list_unsubscribe_post;
            self.db
                .write(move |conn| {
                    repo::messages::set_list_unsubscribe(
                        conn,
                        id,
                        &list_unsubscribe,
                        post.as_deref(),
                    )
                })
                .await?;
            tracing::info!(
                message_id = id,
                thread_id,
                "recovered List-Unsubscribe from raw"
            );
            return Ok(Some(id));
        }
        Ok(None)
    }

    /// Unsubscribe from the list a message came from, preferring the RFC 8058
    /// one-click HTTPS POST, then the RFC 2369 mailto: (sent immediately over
    /// SMTP), and finally handing the URL back for the browser. The returned
    /// outcome states what actually happened so the UI can toast honestly.
    pub async fn unsubscribe_message(&self, message_id: i64) -> Result<UnsubscribeOutcome> {
        let detail = self
            .db
            .read(move |conn| repo::messages::detail(conn, message_id))
            .await?;
        let raw = detail
            .list_unsubscribe
            .ok_or_else(|| CoreError::NotFound("message has no List-Unsubscribe header".into()))?;
        let plan = unsubscribe::plan(&raw, detail.list_unsubscribe_post.as_deref())
            .ok_or_else(|| CoreError::Other("List-Unsubscribe header has no usable URI".into()))?;
        match plan {
            unsubscribe::UnsubscribePlan::OneClick { url } => {
                match unsubscribe::post_one_click(&url).await {
                    // The URL and recipient identify the user to the list (and
                    // often carry a token), so only the message id is logged.
                    Ok(()) => {
                        tracing::info!(message_id, "one-click unsubscribe accepted");
                        Ok(UnsubscribeOutcome::OneClick)
                    }
                    // The endpoint exists but didn't take the POST (blocked
                    // bots, expired token, outage): let the user finish there.
                    Err(e) => {
                        tracing::warn!(message_id, error = %e, "one-click unsubscribe failed; deferring to browser");
                        Ok(UnsubscribeOutcome::NeedsBrowser { url })
                    }
                }
            }
            unsubscribe::UnsubscribePlan::Mailto { to, subject, body } => {
                self.send_unsubscribe_mail(detail.account_id, &to, &subject, &body)
                    .await?;
                tracing::info!(message_id, "mailto unsubscribe sent");
                Ok(UnsubscribeOutcome::MailtoSent)
            }
            unsubscribe::UnsubscribePlan::Browser { url } => {
                Ok(UnsubscribeOutcome::NeedsBrowser { url })
            }
        }
    }

    /// Build and send the tiny unsubscribe-request message a mailto: List-
    /// Unsubscribe asks for. Sent directly (not through the pending-action
    /// queue): the user expects an immediate, definite answer, and there is no
    /// draft to reconcile.
    async fn send_unsubscribe_mail(
        &self,
        account_id: i64,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<()> {
        let cfg = self
            .db
            .read(move |conn| repo::accounts::get_config(conn, account_id))
            .await?
            .ok_or_else(|| CoreError::NotFound(format!("account {account_id}")))?;
        let from = Address {
            name: cfg.display_name.clone(),
            email: cfg.email.clone(),
        };
        let domain = cfg
            .email
            .split('@')
            .nth(1)
            .unwrap_or("localhost")
            .to_string();
        let recipients = [Address {
            name: None,
            email: to.to_string(),
        }];
        let out = crate::mime::OutgoingMessage {
            from,
            to: &recipients,
            cc: &[],
            bcc: &[],
            subject,
            body_text: body,
            body_html: None,
            in_reply_to: None,
            references: &[],
            message_id_domain: &domain,
            attachments: Vec::new(),
        };
        let (_msg_id, raw) = crate::mime::build_message(&out)?;
        let auth = match cfg.auth_kind {
            AuthKind::Password => crate::smtp::SmtpAuth::Password(
                credentials::load_async(cfg.id, Slot::Password).await?,
            ),
            AuthKind::Oauth2 => crate::smtp::SmtpAuth::XOAuth2(
                self.tokens.access_token(cfg.id, cfg.provider).await?,
            ),
        };
        crate::smtp::send_raw(&cfg, &auth, &cfg.email, &[to.to_string()], &raw).await
    }

    /// Rewrite `src="cid:…"` references in a message body to `data:` URIs built
    /// from its inline attachments, so embedded images render in the sandboxed
    /// iframe. No-op when the body has no cid: references. On any failure the
    /// original HTML is returned unchanged.
    async fn inline_cid_images(&self, message_id: i64, html: String) -> String {
        if !html.contains("cid:") {
            return html;
        }
        let atts = self
            .db
            .read(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, content_id, mime_type FROM attachments
                     WHERE message_id = ?1 AND content_id IS NOT NULL
                       AND (part_id IS NOT NULL OR imap_section IS NOT NULL)",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![message_id], |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, Option<String>>(2)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await;
        let atts = match atts {
            Ok(a) if !a.is_empty() => a,
            _ => return html,
        };
        let mut fetched = Vec::new();
        // Total raw bytes one call may embed; once exhausted, remaining parts
        // keep their cid: reference and render as the browser's broken-image
        // affordance (alt text where the sender set one) rather than loading.
        let mut budget = crate::mime::InlineImageBudget::default();
        for (attachment_id, content_id, mime) in atts {
            // Only image-ish parts are candidates; anything else keeps its
            // cid: reference and is not even fetched for this.
            if !crate::mime::inline_image_candidate(mime.as_deref()) {
                continue;
            }
            let Ok(path) = self.get_attachment(attachment_id).await else {
                continue;
            };
            // Size check on file metadata BEFORE the part is read.
            let Ok(meta) = tokio::fs::metadata(&path).await else {
                continue;
            };
            if meta.len() > crate::mime::INLINE_IMAGE_MAX_BYTES {
                continue;
            }
            // The emitted data: URI always uses the sniffed type - a part
            // labelled image/png that is really SVG/HTML is refused.
            if let Ok(bytes) = tokio::fs::read(&path).await
                && let Some(mime) = crate::mime::sniff_image_mime(&bytes)
                && budget.try_reserve(bytes.len() as u64)
            {
                fetched.push((content_id, mime, bytes));
            }
        }
        if fetched.is_empty() {
            return html;
        }
        // Extraction + base64 of (possibly large) image parts is CPU-bound.
        let fallback = html.clone();
        tokio::task::spawn_blocking(move || {
            use base64::Engine;
            let mut map = std::collections::HashMap::new();
            for (content_id, mime, bytes) in fetched {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                map.insert(
                    crate::mime::normalize_cid(&content_id),
                    format!("data:{mime};base64,{b64}"),
                );
            }
            crate::mime::rewrite_cid_src(&html, &map)
        })
        .await
        .unwrap_or(fallback)
    }

    /// Batch variant of `inline_cid_images` for the thread-open path: one DB
    /// read and one encode pass for the whole thread. Only attachments already
    /// on disk are inlined; missing ones are downloaded in the background (a
    /// `MailUpdated` event refreshes the thread when they land) so opening a
    /// thread never waits on the network. Returns every input id mapped to its
    /// (possibly rewritten) HTML.
    async fn inline_cid_images_batch(
        &self,
        thread_id: i64,
        pairs: Vec<(i64, String)>,
    ) -> std::collections::HashMap<i64, String> {
        use std::collections::HashMap;
        let mut out: HashMap<i64, String> = HashMap::new();
        let mut need: Vec<(i64, String)> = Vec::new();
        for (id, html) in pairs {
            if html.contains("cid:") {
                need.push((id, html));
            } else {
                out.insert(id, html);
            }
        }
        if need.is_empty() {
            return out;
        }

        let ids: Vec<i64> = need.iter().map(|(id, _)| *id).collect();
        let atts = self
            .db
            .read(move |conn| {
                let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let sql = format!(
                    "SELECT message_id, id, content_id, mime_type, file_path FROM attachments
                     WHERE message_id IN ({placeholders}) AND content_id IS NOT NULL
                       AND (part_id IS NOT NULL OR imap_section IS NOT NULL)"
                );
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(ids.iter()), |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, Option<String>>(4)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .unwrap_or_default();
        if atts.is_empty() {
            out.extend(need);
            return out;
        }

        let mut fetched: Vec<(i64, String, &'static str, Vec<u8>)> = Vec::new();
        let mut missing: Vec<i64> = Vec::new();
        // Total raw bytes one call may embed; once exhausted, remaining parts
        // keep their cid: reference and render as the browser's broken-image
        // affordance (alt text where the sender set one) rather than loading.
        let mut budget = crate::mime::InlineImageBudget::default();
        for (message_id, attachment_id, content_id, mime, file_path) in atts {
            // Only image-ish parts are candidates; anything else keeps its
            // cid: reference and is not even fetched for this.
            if !crate::mime::inline_image_candidate(mime.as_deref()) {
                continue;
            }
            // Unavailable means "on disk but unreadable/absent" and earns a
            // refetch below; an on-disk part over the per-image cap instead
            // leaves the cid: reference unresolved on purpose.
            let mut unavailable = file_path.is_none();
            let bytes = match &file_path {
                Some(path) => match tokio::fs::metadata(path).await {
                    // The size check runs on metadata BEFORE the part is
                    // read into memory.
                    Ok(meta) if meta.len() <= crate::mime::INLINE_IMAGE_MAX_BYTES => {
                        let bytes = tokio::fs::read(path).await.ok();
                        unavailable = bytes.is_none();
                        bytes
                    }
                    Ok(_) => None,
                    Err(_) => {
                        unavailable = true;
                        None
                    }
                },
                None => None,
            };
            match bytes {
                // The emitted data: URI always uses the sniffed type - a part
                // labelled image/png that is really SVG/HTML is refused.
                Some(bytes) => {
                    if let Some(mime) = crate::mime::sniff_image_mime(&bytes)
                        && budget.try_reserve(bytes.len() as u64)
                    {
                        fetched.push((message_id, content_id, mime, bytes));
                    }
                }
                None if unavailable => missing.push(attachment_id),
                None => {}
            }
        }
        if !missing.is_empty() {
            let core = self.clone();
            tokio::spawn(async move {
                let mut any = false;
                for id in missing {
                    any |= core.get_attachment(id).await.is_ok();
                }
                if any {
                    core.bus.emit(CoreEvent::MailUpdated {
                        thread_ids: vec![thread_id],
                    });
                }
            });
        }
        if fetched.is_empty() {
            out.extend(need);
            return out;
        }

        // Extraction + base64 of (possibly large) image parts is CPU-bound.
        let fallback = need.clone();
        let rewritten = tokio::task::spawn_blocking(move || {
            use base64::Engine;
            let mut maps: HashMap<i64, HashMap<String, String>> = HashMap::new();
            for (message_id, content_id, mime, bytes) in fetched {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                maps.entry(message_id).or_default().insert(
                    crate::mime::normalize_cid(&content_id),
                    format!("data:{mime};base64,{b64}"),
                );
            }
            need.into_iter()
                .map(|(id, html)| match maps.get(&id) {
                    Some(map) => {
                        let html = crate::mime::rewrite_cid_src(&html, map);
                        (id, html)
                    }
                    None => (id, html),
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or(fallback);
        out.extend(rewritten);
        out
    }

    pub async fn list_folders(&self, account_id: Option<i64>) -> Result<Vec<FolderInfo>> {
        self.db
            .read(move |conn| repo::folders::list_info(conn, account_id))
            .await
    }

    // ---------- actions ----------

    pub async fn perform_action(&self, args: PerformActionArgs) -> Result<ActionResult> {
        if args.kind == ActionKind::DeletePermanently {
            return self.delete_trash_threads(args.thread_ids).await;
        }
        let mut action_ids: Vec<i64> = Vec::new();
        let mut touched_accounts: Vec<i64> = Vec::new();

        for thread_id in args.thread_ids.clone() {
            let kind = args.kind;
            let params = args.params.clone();
            let ids = self
                .db
                .write(move |conn| apply_thread_action(conn, thread_id, kind, params.as_ref()))
                .await?;
            for (aid, account_id) in ids {
                action_ids.push(aid);
                if !touched_accounts.contains(&account_id) {
                    touched_accounts.push(account_id);
                }
            }
        }

        // A category is an inbox tab and its label is the tab: adding it files
        // the thread there, removing it sends the thread back. Any other label
        // can satisfy a label split ("has label Invoices"), which must follow
        // manual labelling straight away, not only on the next full re-sort.
        if matches!(args.kind, ActionKind::AddLabel | ActionKind::RemoveLabel) {
            let thread_ids = args.thread_ids.clone();
            let label_id = args.params.as_ref().and_then(|p| p.label_id);
            let added = args.kind == ActionKind::AddLabel;
            self.db
                .write(move |conn| {
                    let splits = repo::splits::list(conn)?;
                    let s = repo::settings::get(conn)?;
                    // With category tabs off, adding one is a plain tag, but
                    // taking it off still releases a thread filed under it.
                    let tab_label = match label_id {
                        Some(id) if s.auto_labels_enabled || !added => {
                            repo::labels::get(conn, id)?.filter(|l| l.is_auto)
                        }
                        _ => None,
                    };
                    if let Some(label) = tab_label {
                        for tid in thread_ids {
                            route::label_tab_changed(conn, &splits, tid, label.id, added)?;
                        }
                        return Ok(());
                    }
                    if splits.is_empty() {
                        return Ok(());
                    }
                    let fallback =
                        route::Fallback::from_settings(s.auto_labels_enabled, s.ai_categorize);
                    for tid in thread_ids {
                        route::reroute_after_label_change(conn, &splits, fallback, tid)?;
                    }
                    Ok(())
                })
                .await?;
        }

        self.bus.emit(CoreEvent::MailUpdated {
            thread_ids: args.thread_ids.clone(),
        });
        for acc in touched_accounts {
            self.nudge(Some(acc), || SyncCmd::RunActions).await;
        }
        Ok(ActionResult { action_ids })
    }

    pub async fn undo_last(&self) -> Result<bool> {
        let cutoff = now_ms() - 30_000;
        let last = self
            .db
            .read(move |conn| repo::actions::last_undoable(conn, cutoff))
            .await?;
        let Some(last) = last else { return Ok(false) };

        // Undo the whole gesture: same kind, created within 150ms of it.
        let (kind, created) = (last.kind.clone(), last.created_at);
        let undone_threads = self
            .db
            .write(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id FROM pending_actions
                     WHERE kind = ?1 AND ABS(created_at - ?2) <= 150
                       AND state IN ('pending','inflight','done')",
                )?;
                let ids = stmt
                    .query_map(rusqlite::params![kind, created], |r| r.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                drop(stmt);
                let mut threads = Vec::new();
                for id in ids {
                    if let Some(action) = repo::actions::get(conn, id)? {
                        if let Some(tid) = revert_action(conn, &action)? {
                            if !threads.contains(&tid) {
                                threads.push(tid);
                            }
                        }
                    }
                }
                Ok(threads)
            })
            .await?;

        if !undone_threads.is_empty() {
            self.bus.emit(CoreEvent::MailUpdated {
                thread_ids: undone_threads,
            });
        }
        self.nudge(None, || SyncCmd::RunActions).await;
        Ok(true)
    }

    pub async fn cancel_send(&self, action_id: i64) -> Result<bool> {
        self.db
            .write(move |conn| repo::actions::try_cancel(conn, action_id))
            .await
    }

    /// "Send now": make a queued send due immediately (skip the remaining undo
    /// window) and nudge its actor. Returns false if it was already sent or
    /// cancelled.
    pub async fn send_now(&self, action_id: i64) -> Result<bool> {
        let account_id = self
            .db
            .write(move |conn| repo::actions::expedite(conn, action_id))
            .await?;
        match account_id {
            Some(account_id) => {
                self.nudge(Some(account_id), || SyncCmd::RunActions).await;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    // ---------- compose ----------

    pub async fn save_draft(&self, args: SaveDraftArgs) -> Result<i64> {
        // Stage every attachment into an app-managed dir up front, so the paths
        // persisted to `draft_attachments` (and later read at dispatch) are
        // always files the app itself copied - never an arbitrary path handed
        // in by the frontend. Snapshotting here also fixes the sent bytes at
        // compose time rather than whatever the source file becomes later.
        let staging_root = self.paths.draft_attachments_dir();
        let mut staged: Vec<crate::models::DraftAttachmentIn> =
            Vec::with_capacity(args.attachments.len());
        // Copies this call created; removed if the save is rejected (they are
        // referenced by nothing until the transaction commits).
        let mut fresh_paths: Vec<String> = Vec::new();
        for att in &args.attachments {
            match stage_draft_attachment(&staging_root, &att.file_path, &att.filename).await {
                Ok(staged_file) => {
                    if staged_file.fresh {
                        fresh_paths.push(staged_file.path.clone());
                    }
                    staged.push(crate::models::DraftAttachmentIn {
                        file_path: staged_file.path,
                        filename: att.filename.clone(),
                    });
                }
                Err(e) => {
                    remove_staged_draft_files(&staging_root, &fresh_paths).await;
                    return Err(e);
                }
            }
        }
        let new_paths: HashSet<String> = staged.iter().map(|a| a.file_path.clone()).collect();
        let result = self
            .db
            .write(move |conn| {
                let tx = conn.transaction()?;

                let drafts_folder =
                    repo::folders::by_role(&tx, args.account_id, roles::DRAFTS)?.map(|f| f.id);

                // Thread: replies join the parent's thread.
                let thread_id = if let Some(parent_id) = args.in_reply_to_message_id {
                    repo::messages::get_row(&tx, parent_id)?.and_then(|r| r.thread_id)
                } else {
                    None
                };

                let draft_id = match args.draft_id {
                    Some(id) => {
                        // The is_draft predicate gates the whole update: a 0-row
                        // write means the id is not (or no longer) a draft -
                        // e.g. it was sent or arrived since the caller read it.
                        // Fail now so the transaction rolls back instead of
                        // overwriting a real message's body and attachments.
                        let updated = tx.execute(
                            "UPDATE messages SET subject = ?2, to_json = ?3, cc_json = ?4,
                                    bcc_json = ?5, date = ?6 WHERE id = ?1 AND is_draft = 1",
                            rusqlite::params![
                                id,
                                args.subject,
                                serde_json::to_string(&args.to)?,
                                serde_json::to_string(&args.cc)?,
                                serde_json::to_string(&args.bcc)?,
                                now_ms(),
                            ],
                        )?;
                        if updated == 0 {
                            return Err(CoreError::NotFound("draft".into()));
                        }
                        id
                    }
                    None => {
                        let account_email: String = tx.query_row(
                            "SELECT email FROM accounts WHERE id = ?1",
                            rusqlite::params![args.account_id],
                            |r| r.get(0),
                        )?;
                        let tid = match thread_id {
                            Some(t) => t,
                            None => repo::threads::create(
                                &tx,
                                args.account_id,
                                None,
                                &crate::mime::normalize_subject(&args.subject),
                            )?,
                        };
                        let nm = repo::messages::NewMessage {
                            account_id: args.account_id,
                            folder_id: drafts_folder.unwrap_or(0),
                            uid: None,
                            message_id: None,
                            gm_msgid: None,
                            gm_thrid: None,
                            subject: args.subject.clone(),
                            from: Some(Address {
                                name: None,
                                email: account_email,
                            }),
                            to: args.to.clone(),
                            cc: args.cc.clone(),
                            bcc: args.bcc.clone(),
                            date: now_ms(),
                            internal_date: None,
                            is_read: true,
                            is_starred: false,
                            is_draft: true,
                            is_outgoing: true,
                            is_automated: false,
                            has_attachments: false,
                            size: None,
                            snippet: crate::mime::make_snippet(&args.body_text),
                            references: Vec::new(),
                            list_unsubscribe: None,
                            list_unsubscribe_post: None,
                            sender_addr: None,
                        };
                        let id = repo::messages::insert(&tx, &nm, tid)?;
                        tx.execute(
                            "INSERT INTO drafts_meta (message_id, mode, in_reply_to_message_id)
                             VALUES (?1, ?2, ?3)",
                            rusqlite::params![id, args.mode, args.in_reply_to_message_id],
                        )?;
                        id
                    }
                };

                tx.execute(
                    "INSERT INTO message_bodies (message_id, text_body, html_body) VALUES (?1, ?2, ?3)
                     ON CONFLICT(message_id) DO UPDATE SET text_body = excluded.text_body,
                                                           html_body = excluded.html_body",
                    rusqlite::params![draft_id, args.body_text, args.body_html],
                )?;
                tx.execute(
                    "UPDATE messages SET body_state = 'cached', snippet = ?2 WHERE id = ?1",
                    rusqlite::params![draft_id, crate::mime::make_snippet(&args.body_text)],
                )?;
                // Staged outgoing attachments: replace on every save. Remember
                // the previous staged paths so files this save orphans can be
                // deleted once the transaction commits.
                let old_paths: Vec<String> = {
                    let mut stmt = tx.prepare(
                        "SELECT file_path FROM draft_attachments WHERE draft_id = ?1",
                    )?;
                    stmt.query_map(rusqlite::params![draft_id], |r| r.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };
                tx.execute(
                    "DELETE FROM draft_attachments WHERE draft_id = ?1",
                    rusqlite::params![draft_id],
                )?;
                for att in &staged {
                    tx.execute(
                        "INSERT INTO draft_attachments (draft_id, file_path, filename) VALUES (?1,?2,?3)",
                        rusqlite::params![draft_id, att.file_path, att.filename],
                    )?;
                }
                tx.execute(
                    "UPDATE messages SET has_attachments = ?2 WHERE id = ?1",
                    rusqlite::params![draft_id, (!staged.is_empty()) as i64],
                )?;
                let thread_id =
                    repo::messages::get_row(&tx, draft_id)?.and_then(|r| r.thread_id);
                if let Some(tid) = thread_id {
                    repo::threads::recompute(&tx, tid)?;
                }
                tx.commit()?;
                Ok((draft_id, thread_id, old_paths))
            })
            .await;
        let (draft_id, thread_id, old_paths) = match result {
            Ok(v) => v,
            Err(e) => {
                // Rejected save: the freshly staged copies belong to no draft.
                remove_staged_draft_files(&staging_root, &fresh_paths).await;
                return Err(e);
            }
        };
        // Committed: drop staged files the draft no longer references (e.g. an
        // attachment removed between saves). Old paths come from the DB and
        // may not be canonical (staging canonicalises on the way in), so the
        // comparison resolves both sides - a non-canonical alias of a kept
        // file must not be "orphaned" out from under the new row.
        let mut orphaned: Vec<String> = Vec::new();
        for old in old_paths {
            let canon = tokio::fs::canonicalize(&old)
                .await
                .map(|c| c.to_string_lossy().into_owned())
                .unwrap_or_else(|_| old.clone());
            if !new_paths.contains(&canon) {
                orphaned.push(old);
            }
        }
        remove_staged_draft_files(&staging_root, &orphaned).await;
        if let Some(thread_id) = thread_id {
            self.bus.emit(CoreEvent::MailUpdated {
                thread_ids: vec![thread_id],
            });
        }
        Ok(draft_id)
    }

    /// Load the complete editable state for a saved draft. Message detail omits
    /// Bcc and app-managed attachment paths, so reopening from the rendered
    /// message alone would silently lose both on the next save.
    pub async fn get_draft(&self, draft_id: i64) -> Result<SaveDraftArgs> {
        self.db
            .read(move |conn| {
                let mut draft = conn
                    .query_row(
                        "SELECT m.account_id, m.to_json, m.cc_json, m.bcc_json, m.subject,
                                COALESCE(b.text_body, ''), b.html_body,
                                COALESCE(dm.mode, 'new'), dm.in_reply_to_message_id,
                                m.is_draft
                         FROM messages m
                         LEFT JOIN message_bodies b ON b.message_id = m.id
                         LEFT JOIN drafts_meta dm ON dm.message_id = m.id
                         WHERE m.id = ?1",
                        rusqlite::params![draft_id],
                        |row| {
                            let is_draft = row.get::<_, i64>(9)? != 0;
                            Ok((
                                SaveDraftArgs {
                                    draft_id: Some(draft_id),
                                    account_id: row.get(0)?,
                                    to: serde_json::from_str(&row.get::<_, String>(1)?)
                                        .unwrap_or_default(),
                                    cc: serde_json::from_str(&row.get::<_, String>(2)?)
                                        .unwrap_or_default(),
                                    bcc: serde_json::from_str(&row.get::<_, String>(3)?)
                                        .unwrap_or_default(),
                                    subject: row.get(4)?,
                                    body_text: row.get(5)?,
                                    body_html: row.get(6)?,
                                    mode: row.get(7)?,
                                    in_reply_to_message_id: row.get(8)?,
                                    attachments: Vec::new(),
                                },
                                is_draft,
                            ))
                        },
                    )
                    .optional()?
                    .ok_or_else(|| CoreError::NotFound("draft".into()))?;
                if !draft.1 {
                    return Err(CoreError::NotFound("draft".into()));
                }

                let mut stmt = conn.prepare(
                    "SELECT file_path, filename
                     FROM draft_attachments WHERE draft_id = ?1 ORDER BY id",
                )?;
                draft.0.attachments = stmt
                    .query_map(rusqlite::params![draft_id], |row| {
                        Ok(crate::models::DraftAttachmentIn {
                            file_path: row.get(0)?,
                            filename: row.get(1)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(draft.0)
            })
            .await
    }

    pub async fn delete_draft(&self, draft_id: i64) -> Result<()> {
        let (thread_id, nudge_account, staged_paths) = self
            .db
            .write(move |conn| {
                // One transaction: the send cancellation, attachment-row
                // delete and message delete/move either all commit or none
                // do. A mid-closure failure (no Trash folder, a payload that
                // cannot be built) must not leave the draft half-deleted -
                // its queued send cancelled and its attachment rows gone.
                let tx = conn.transaction()?;
                let row = tx
                    .query_row(
                        "SELECT m.account_id, m.thread_id, m.folder_id, m.uid, m.is_draft,
                                COALESCE(f.role, '')
                         FROM messages m LEFT JOIN folders f ON f.id = m.folder_id
                         WHERE m.id = ?1",
                        rusqlite::params![draft_id],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, Option<i64>>(1)?,
                                row.get::<_, Option<i64>>(2)?,
                                row.get::<_, Option<i64>>(3)?,
                                row.get::<_, i64>(4)? != 0,
                                row.get::<_, String>(5)?,
                            ))
                        },
                    )
                    .optional()?
                    .ok_or_else(|| CoreError::NotFound("draft".into()))?;
                if !row.4 {
                    return Err(CoreError::NotFound("draft".into()));
                }

                // A queued send for this draft must not outlive the delete:
                // the dispatch reads the draft_attachments rows dropped below
                // and would deliver the message without its files (or, for a
                // server draft moved to Trash, send at all). Pending sends
                // are cancelled here - the same pending->cancelled
                // transition undo-send uses - inside this write so the
                // dispatcher's claim cannot slip between them. A send
                // already claimed is mid-flight, so the delete is refused
                // rather than racing its attachment read.
                let send_actions: Vec<(i64, String)> = {
                    let mut stmt = tx.prepare(
                        "SELECT id, state FROM pending_actions
                         WHERE kind = 'send' AND message_id = ?1
                           AND state IN ('pending','inflight')",
                    )?;
                    stmt.query_map(rusqlite::params![draft_id], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?
                };
                if send_actions.iter().any(|(_, s)| s == "inflight") {
                    return Err(CoreError::ActionRejected(
                        "this draft is already being sent".into(),
                    ));
                }

                // Fail-fast reads BEFORE any mutation: a server draft needs
                // a Trash folder and a buildable identity payload, and when
                // either fails the draft must come out of this call
                // untouched - not with its send cancelled and its rows gone.
                let remote_plan = if row.3.is_some() && row.5 != roles::TRASH {
                    // This draft exists on IMAP and will be moved to Trash.
                    // Not a "draft is gone" NotFound - the draft is still
                    // there; the delete itself cannot proceed without
                    // somewhere to move it, so it is rejected like the other
                    // un-deletable cases in trash.rs.
                    let trash = repo::folders::by_role(&tx, row.0, roles::TRASH)?
                        .ok_or_else(|| CoreError::DeleteRejected("no trash folder".into()))?;
                    let payload = move_identity_payload(&tx, draft_id, row.2, row.3, trash.id)?;
                    Some((trash.id, payload))
                } else {
                    None
                };

                // Staged attachment rows never outlive the draft: the local
                // delete cascades them, but the IMAP-move branch keeps the
                // message row (in Trash), so drop them explicitly either way.
                // Their files are removed once the write succeeds.
                let staged_paths: Vec<String> = {
                    let mut stmt =
                        tx.prepare("SELECT file_path FROM draft_attachments WHERE draft_id = ?1")?;
                    stmt.query_map(rusqlite::params![draft_id], |r| r.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };

                for (action_id, _) in send_actions {
                    repo::actions::try_cancel(&tx, action_id)?;
                }
                tx.execute(
                    "DELETE FROM draft_attachments WHERE draft_id = ?1",
                    rusqlite::params![draft_id],
                )?;

                let mut nudge_account = None;
                if let Some((trash_id, payload)) = remote_plan {
                    // Move it optimistically and queue the matching remote
                    // move so the next sync cannot resurrect the local row
                    // in Drafts.
                    repo::messages::set_uid_and_folder(&tx, draft_id, trash_id, None)?;
                    repo::actions::enqueue(
                        &tx,
                        row.0,
                        "trash",
                        Some(draft_id),
                        row.1,
                        &payload,
                        None,
                    )?;
                    nudge_account = Some(row.0);
                } else {
                    // Purely local drafts have no remote copy to preserve.
                    repo::messages::delete(&tx, draft_id)?;
                }
                if let Some(tid) = row.1 {
                    repo::threads::recompute(&tx, tid)?;
                }
                tx.commit()?;
                Ok((row.1, nudge_account, staged_paths))
            })
            .await?;
        remove_staged_draft_files(&self.paths.draft_attachments_dir(), &staged_paths).await;
        if let Some(thread_id) = thread_id {
            self.bus.emit(CoreEvent::MailUpdated {
                thread_ids: vec![thread_id],
            });
        }
        if let Some(account_id) = nudge_account {
            self.nudge(Some(account_id), || SyncCmd::RunActions).await;
        }
        Ok(())
    }

    pub async fn queue_send(&self, args: QueueSendArgs) -> Result<QueueSendResult> {
        let settings = self.db.read(|conn| repo::settings::get(conn)).await?;
        let dispatch_at = args
            .send_at
            .unwrap_or_else(|| now_ms() + settings.undo_send_seconds * 1000);

        let draft_id = args.draft_id;
        let (action_id, account_id) = self
            .db
            .write(move |conn| {
                let row = repo::messages::get_row(conn, draft_id)?
                    .ok_or_else(|| CoreError::NotFound("draft".into()))?;
                let payload = serde_json::json!({ "draftId": draft_id });
                let aid = repo::actions::enqueue(
                    conn,
                    row.account_id,
                    "send",
                    Some(draft_id),
                    row.thread_id,
                    &payload,
                    Some(dispatch_at),
                )?;
                Ok((aid, row.account_id))
            })
            .await?;

        // Fire exactly when the send comes due instead of waiting for the
        // scheduler's next tick (up to TICK_SECS of extra slop, which made even
        // an immediate send feel sluggish). The scheduler still covers restarts
        // and any timer this task misses. Only armed for near-term sends; far
        // future "send later" relies on the scheduler so we don't hold a task
        // sleeping for hours.
        let delay_ms = (dispatch_at - now_ms()).max(0);
        if delay_ms <= 15 * 60 * 1000 {
            let core = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms as u64)).await;
                core.nudge(Some(account_id), || SyncCmd::RunActions).await;
            });
        }
        Ok(QueueSendResult {
            action_id,
            dispatch_at,
        })
    }

    /// Return a stable cached attachment path. Legacy messages extract from
    /// their raw MIME; selectively-cached messages download only the requested
    /// IMAP section through the priority reader.
    pub async fn get_attachment(&self, attachment_id: i64) -> Result<String> {
        let fetch_lock = {
            let mut locks = self.attachment_locks.lock().await;
            match locks.get(&attachment_id).and_then(std::sync::Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(tokio::sync::Mutex::new(()));
                    locks.insert(attachment_id, Arc::downgrade(&lock));
                    lock
                }
            }
        };
        let _fetch_guard = fetch_lock.lock().await;

        // This check deliberately happens after acquiring the single-flight
        // lock: a concurrent caller may just have populated `file_path`.
        let (message_id, part_id, imap_section, filename, mime_type, file_path) = self
            .db
            .read(move |conn| {
                conn.query_row(
                    "SELECT message_id, part_id, imap_section, filename, mime_type, file_path
                     FROM attachments WHERE id = ?1",
                    rusqlite::params![attachment_id],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, Option<String>>(1)?,
                            r.get::<_, Option<String>>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, Option<String>>(4)?,
                            r.get::<_, Option<String>>(5)?,
                        ))
                    },
                )
                .map_err(Into::into)
            })
            .await?;

        if let Some(path) = file_path {
            if tokio::fs::metadata(&path).await.is_ok() {
                // Files cached before quarantining existed get it now.
                quarantine::mark(std::path::Path::new(&path))?;
                return Ok(path);
            }
        }

        let row = self
            .db
            .read(move |conn| repo::messages::get_row(conn, message_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("message".into()))?;

        // Prefer the legacy raw cache when it is healthy. If its file was
        // removed/corrupted but this row also has an IMAP section, safely fall
        // through to the remote section instead of making the attachment
        // permanently inaccessible because of a stale `raw_path`.
        let legacy = match (row.raw_path.as_ref(), part_id.as_deref()) {
            (Some(raw_path), Some(part_id)) => match tokio::fs::read(raw_path).await {
                Ok(raw) => match crate::mime::extract_attachment(&raw, part_id) {
                    Ok(value) => Some(value),
                    Err(error) if imap_section.is_none() => return Err(error),
                    Err(_) => None,
                },
                Err(error) if imap_section.is_none() => return Err(error.into()),
                Err(_) => None,
            },
            (Some(_), None) if imap_section.is_none() => {
                return Err(CoreError::NotFound("attachment part".into()));
            }
            _ => None,
        };
        let (bytes, parsed_name) = if let Some(value) = legacy {
            value
        } else {
            let handle = self
                .handles
                .read()
                .await
                .get(&row.account_id)
                .cloned()
                .ok_or_else(|| CoreError::NotFound(format!("account {}", row.account_id)))?;
            (handle.fetch_attachment(attachment_id).await?, None)
        };

        let mut safe_name = safe_filename(
            &filename
                .map(|name| crate::mime::decode_encoded_words(&name))
                .or(parsed_name)
                .unwrap_or_else(|| format!("attachment-{attachment_id}")),
        );
        // Invites and other body parts often carry no filename; give the temp
        // file an extension from its MIME type so opening it hands off to the
        // right app (a `text/calendar` part becomes `*.ics`, not a bare name
        // the OS opens in a text editor or refuses to open at all).
        if std::path::Path::new(&safe_name).extension().is_none() {
            if let Some(ext) = mime_type.as_deref().and_then(ext_for_mime) {
                safe_name.push('.');
                safe_name.push_str(ext);
            }
        }
        // This path is not part of the account's tracked task set (the UI
        // spawns it directly), so the account may have been removed while the
        // remote fetch ran. Re-check before touching its directories - a late
        // create_dir_all must never resurrect a removed account's folder.
        let account_gone = !self
            .db
            .read(move |conn| Ok(repo::accounts::get(conn, row.account_id)?.is_some()))
            .await?;
        if account_gone {
            return Err(CoreError::NotFound("account".into()));
        }
        let dir = self
            .paths
            .attachments_dir(row.account_id)
            .join(attachment_id.to_string());
        tokio::fs::create_dir_all(&dir).await?;
        let path = dir.join(&safe_name);
        // Defense in depth: the cached file must be a direct child of `dir`
        // whatever the platform's path rules make of the name.
        if path.parent() != Some(dir.as_path()) {
            return Err(CoreError::Other("unsafe attachment filename".into()));
        }
        let partial = dir.join(".download.part");
        tokio::fs::write(&partial, &bytes).await?;
        // Quarantined before it gets its real name, so the OS never sees the
        // final file without the flag.
        quarantine::mark(&partial)?;
        tokio::fs::rename(&partial, &path).await?;
        // The remote fetch can outlive the account: the pre-write existence
        // check above narrows the window but cannot close it (removal is not
        // atomic with this untracked task). Re-check once more and clean up
        // what was just created so a removed account's directories do not
        // resurrect on disk.
        let account_gone = !self
            .db
            .read(move |conn| Ok(repo::accounts::get(conn, row.account_id)?.is_some()))
            .await?;
        if account_gone {
            let _ = tokio::fs::remove_dir_all(&dir).await;
            // `remove_dir` (not _all) only succeeds when this account dir is
            // otherwise empty - never touches a live account's contents.
            let _ = tokio::fs::remove_dir(self.paths.attachments_dir(row.account_id)).await;
            return Err(CoreError::NotFound("account".into()));
        }

        let path_str = path.to_string_lossy().to_string();
        let p = path_str.clone();
        self.db
            .write(move |conn| {
                conn.execute(
                    "UPDATE attachments SET file_path = ?2 WHERE id = ?1",
                    rusqlite::params![attachment_id, p],
                )?;
                Ok(())
            })
            .await?;
        Ok(path_str)
    }

    /// Extract an attachment and write it to a caller-chosen destination (the
    /// "download" / save-as path). Reuses `get_attachment` so extraction and
    /// filename handling stay in one place.
    pub async fn save_attachment(&self, attachment_id: i64, dest: String) -> Result<()> {
        let src = self.get_attachment(attachment_id).await?;
        tokio::fs::copy(&src, &dest).await?;
        quarantine::mark(std::path::Path::new(&dest))?;
        Ok(())
    }

    /// Extract an attachment in memory and convert it to a safe, inert
    /// preview payload (sanitized HTML / text / cell grid / base64 media).
    pub async fn preview_attachment(
        &self,
        attachment_id: i64,
    ) -> Result<preview::AttachmentPreview> {
        let (filename, mime_type, size) = self
            .db
            .read(move |conn| {
                conn.query_row(
                    "SELECT filename, mime_type, size FROM attachments WHERE id = ?1",
                    rusqlite::params![attachment_id],
                    |r| {
                        Ok((
                            r.get::<_, Option<String>>(0)?,
                            r.get::<_, Option<String>>(1)?,
                            r.get::<_, Option<i64>>(2)?,
                        ))
                    },
                )
                .map_err(Into::into)
            })
            .await?;
        if size.is_some_and(|value| value > preview::MAX_PREVIEW_BYTES as i64) {
            return Ok(preview::AttachmentPreview::Unsupported {
                reason: "too_large".into(),
            });
        }
        let path = self.get_attachment(attachment_id).await?;
        let bytes = tokio::fs::read(path).await?;
        // Parsing untrusted office/spreadsheet formats is CPU-bound; keep it
        // off the async runtime threads.
        let preview = tokio::task::spawn_blocking(move || {
            preview::build_preview(&bytes, filename.as_deref(), mime_type.as_deref())
        })
        .await
        .map_err(|e| CoreError::Other(e.to_string()))?;
        Ok(preview)
    }

    /// Compose "To" autocomplete. `account_id` Some scopes suggestions to the
    /// sending account's own contacts; None returns contacts across all accounts
    /// (the "show contacts from all accounts" setting).
    pub async fn list_contacts(
        &self,
        prefix: String,
        account_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<Address>> {
        self.db
            .read(move |conn| {
                repo::contacts::autocomplete(conn, &prefix, account_id, limit.clamp(1, 50))
            })
            .await
    }

    /// Contact suggestions for the search screen: every query token must match
    /// (accent-insensitive), ranked by how much the user emails that contact.
    /// Search operators are stripped first so "from:x be" still suggests on "be".
    pub async fn suggest_contacts(
        &self,
        query: String,
        limit: i64,
    ) -> Result<Vec<ContactSuggestion>> {
        let text = search::parse(&query).text;
        self.db
            .read(move |conn| repo::contacts::suggest(conn, &text, None, limit.clamp(1, 20)))
            .await
    }

    // ---------- calendar ----------

    pub async fn list_events(&self, start_ms: i64, end_ms: i64) -> Result<Vec<CalendarEvent>> {
        let (mut events, masters) = self
            .db
            .read(move |conn| {
                Ok((
                    repo::calendar::list_range(conn, start_ms, end_ms)?,
                    repo::calendar::recurring_masters(conn, end_ms)?,
                ))
            })
            .await?;

        // Expand recurring series into concrete occurrences. Occurrences keep
        // the master's row id (edits/deletes address the whole series in v1);
        // unsupported rules fall back to the master row alone.
        for m in masters {
            let Some(rrule) = m.event.rrule.clone() else {
                continue;
            };
            let duration = m
                .event
                .ends_at
                .map(|e| e - m.event.starts_at)
                .unwrap_or(1_800_000);
            let Some(occs) = caldav::rrule::expand(
                &rrule,
                m.event.starts_at,
                duration,
                m.ical_raw.as_deref(),
                start_ms,
                end_ms,
            ) else {
                continue; // unsupported rule: the master entry stands alone
            };
            events.retain(|e| e.id != m.event.id);
            for occ in occs {
                let mut e = m.event.clone();
                e.starts_at = occ.start;
                e.ends_at = Some(occ.end);
                events.push(e);
            }
        }
        events.sort_by_key(|e| e.starts_at);
        Ok(events)
    }

    /// Invite events carried by one message (the thread invite card).
    pub async fn events_for_message(&self, message_id: i64) -> Result<Vec<CalendarEvent>> {
        self.db
            .read(move |conn| repo::calendar::for_message(conn, message_id))
            .await
    }

    /// Create a meeting. The event lands on the local calendar immediately;
    /// if it has attendees, an invite email with an ICS (METHOD:REQUEST) is
    /// drafted and queued through the normal send pipeline (undo window,
    /// offline queueing, sent-folder append all apply).
    pub async fn create_event(&self, args: CreateEventArgs) -> Result<CalendarEvent> {
        if args.summary.trim().is_empty() {
            return Err(CoreError::Other("event needs a title".into()));
        }
        if args.ends_at <= args.starts_at {
            return Err(CoreError::Other("event must end after it starts".into()));
        }
        let account_id = args.account_id;
        let account = self
            .db
            .read(move |conn| repo::accounts::get(conn, account_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))?;

        if let Some(calendar_id) = args.calendar_id {
            let cal = self
                .db
                .read(move |conn| repo::caldav::get_calendar(conn, calendar_id))
                .await?
                .ok_or_else(|| CoreError::NotFound("calendar".into()))?;
            if cal.account_id != account_id {
                return Err(CoreError::Other(
                    "calendar belongs to another account".into(),
                ));
            }
            if cal.read_only {
                return Err(CoreError::Other("calendar is read-only".into()));
            }
            if !cal.enabled {
                return Err(CoreError::Other("calendar is disabled".into()));
            }
        }

        let uid = format!("{}-{}@comail", now_ms(), crate::mime::rand_token());
        let attendees: Vec<EventAttendee> = args
            .attendees
            .iter()
            .map(|a| EventAttendee {
                email: a.email.clone(),
                name: a.name.clone(),
                partstat: Some("NEEDS-ACTION".into()),
            })
            .collect();

        let ev = args.clone();
        let organizer_email = account.email.clone();
        let uid_for_db = uid.clone();
        let event_id = self
            .db
            .write(move |conn| {
                repo::calendar::insert_local(
                    conn,
                    account_id,
                    ev.calendar_id,
                    &uid_for_db,
                    ev.summary.trim(),
                    ev.location.as_deref(),
                    ev.description.as_deref(),
                    ev.join_url.as_deref(),
                    &organizer_email,
                    &attendees,
                    ev.starts_at,
                    ev.ends_at,
                    ev.all_day,
                )
            })
            .await?;

        if !args.attendees.is_empty() {
            let organizer = Address {
                name: account.display_name.clone(),
                email: account.email.clone(),
            };
            let ics = calendar::build_request_ics(&calendar::InviteSpec {
                uid: &uid,
                sequence: 0,
                summary: args.summary.trim(),
                description: args.description.as_deref(),
                location: args.location.as_deref(),
                join_url: args.join_url.as_deref(),
                organizer: &organizer,
                attendees: &args.attendees,
                starts_at_ms: args.starts_at,
                ends_at_ms: args.ends_at,
                dtstamp_ms: now_ms(),
            });
            let body_text = invite_body_text(&args);
            self.send_calendar_mail(
                account_id,
                args.attendees.clone(),
                format!("Invitation: {}", args.summary.trim()),
                body_text,
                &ics,
            )
            .await?;
        }

        self.enqueue_cal_push(event_id, account_id, "cal_put")
            .await?;

        // Microsoft accounts have no CalDAV endpoint, so also write the event
        // into their Outlook / Microsoft 365 calendar via Graph - that is what
        // Teams and Outlook show. Best-effort: a Graph failure (e.g. the
        // account predates the calendar consent) must not fail event creation,
        // which already succeeded locally. Skipped when the account has a
        // connected calendar: the sync task's push already writes it (and a
        // second direct POST would duplicate the event in Outlook).
        if account.provider == Provider::Microsoft {
            let has_cal_config = self
                .db
                .read(move |conn| repo::caldav::get_config(conn, account_id))
                .await?
                .is_some();
            if !has_cal_config {
                if let Err(e) = self.push_event_to_graph(account_id, &args).await {
                    tracing::warn!(error = %e, "graph: could not sync event to Outlook calendar");
                }
            }
        }

        self.db
            .read(move |conn| repo::calendar::get(conn, event_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("event".into()))
    }

    /// Write a just-created event into the Microsoft 365 calendar via Graph.
    async fn push_event_to_graph(&self, account_id: i64, args: &CreateEventArgs) -> Result<()> {
        let token = self
            .tokens
            .access_token_for_scope(
                account_id,
                Provider::Microsoft,
                oauth::providers::MS_CALENDARS_SCOPE,
            )
            .await?;
        // Fold the join link into the body so it rides along in Outlook/Teams.
        let body_html = match (&args.description, &args.join_url) {
            (d, Some(url)) => Some(format!(
                "{}<p><a href=\"{}\">Join the meeting</a></p>",
                d.as_deref().unwrap_or(""),
                url
            )),
            (Some(d), None) if !d.trim().is_empty() => Some(d.clone()),
            _ => None,
        };
        let attendees = args
            .attendees
            .iter()
            .map(|a| graph::GraphAttendee {
                email: a.email.clone(),
                name: a.name.clone(),
            })
            .collect();
        graph::create_calendar_event(
            &token,
            None,
            &graph::GraphEvent {
                subject: args.summary.trim(),
                body_html,
                location: args.location.as_deref(),
                start_ms: args.starts_at,
                end_ms: args.ends_at,
                all_day: args.all_day,
                attendees,
            },
        )
        .await
        .map(|_| ())
    }

    /// Answer an invite: store our response and email an ICS METHOD:REPLY to
    /// the organizer (the standard-compliant path every calendar understands).
    pub async fn rsvp_event(&self, args: RsvpEventArgs) -> Result<CalendarEvent> {
        let partstat = match args.response.as_str() {
            "accepted" => "ACCEPTED",
            "tentative" => "TENTATIVE",
            "declined" => "DECLINED",
            _ => return Err(CoreError::Other("invalid RSVP response".into())),
        };
        let event_id = args.event_id;
        let (ev, uid_seq) = self
            .db
            .read(move |conn| {
                Ok((
                    repo::calendar::get(conn, event_id)?,
                    repo::calendar::uid_and_sequence(conn, event_id)?,
                ))
            })
            .await?;
        let ev = ev.ok_or_else(|| CoreError::NotFound("event".into()))?;
        let (uid, sequence) = uid_seq.ok_or_else(|| CoreError::NotFound("event".into()))?;

        let account_id = ev.account_id;
        let account = self
            .db
            .read(move |conn| repo::accounts::get(conn, account_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))?;

        // Reply goes to the organizer; without one there is nobody to notify,
        // but we still record the response locally.
        if let Some(organizer) = ev.organizer.clone().filter(|o| !o.is_empty()) {
            let me = Address {
                name: account.display_name.clone(),
                email: account.email.clone(),
            };
            let ics = calendar::build_reply_ics(&calendar::ReplySpec {
                uid: &uid,
                sequence,
                summary: ev.summary.as_deref(),
                partstat,
                organizer_email: &organizer,
                attendee: &me,
                starts_at_ms: ev.starts_at,
                ends_at_ms: ev.ends_at,
                dtstamp_ms: now_ms(),
            });
            let verb = match partstat {
                "ACCEPTED" => "Accepted",
                "TENTATIVE" => "Tentative",
                _ => "Declined",
            };
            let title = ev.summary.clone().unwrap_or_else(|| "(no title)".into());
            self.send_calendar_mail(
                account_id,
                vec![Address {
                    name: None,
                    email: organizer,
                }],
                format!("{verb}: {title}"),
                format!(
                    "{} has responded {} to: {title}",
                    account.email,
                    verb.to_lowercase()
                ),
                &ics,
            )
            .await?;
        }

        self.db
            .write(move |conn| repo::calendar::set_rsvp(conn, event_id, partstat))
            .await?;
        // CalDAV-backed invites also sync the PARTSTAT change to the server.
        self.enqueue_cal_push(event_id, ev.account_id, "cal_put")
            .await?;
        self.db
            .read(move |conn| repo::calendar::get(conn, event_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("event".into()))
    }

    /// Edit an event we organize. The change is applied locally at once,
    /// attendees get an updated REQUEST ICS (bumped SEQUENCE) when `notify`,
    /// and CalDAV-backed events are flagged for the next push.
    pub async fn update_event(&self, args: UpdateEventArgs) -> Result<CalendarEvent> {
        if args.summary.trim().is_empty() {
            return Err(CoreError::Other("event needs a title".into()));
        }
        if args.ends_at <= args.starts_at {
            return Err(CoreError::Other("event must end after it starts".into()));
        }
        let event_id = args.event_id;
        let existing = self
            .db
            .read(move |conn| repo::calendar::get(conn, event_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("event".into()))?;
        if !existing.is_local {
            return Err(CoreError::Other(
                "only events you organize can be edited".into(),
            ));
        }

        // Preserve responses attendees already gave; new addresses start out
        // NEEDS-ACTION.
        let attendees: Vec<EventAttendee> = args
            .attendees
            .iter()
            .map(|a| EventAttendee {
                email: a.email.clone(),
                name: a.name.clone(),
                partstat: existing
                    .attendees
                    .iter()
                    .find(|old| old.email.eq_ignore_ascii_case(&a.email))
                    .and_then(|old| old.partstat.clone())
                    .or_else(|| Some("NEEDS-ACTION".into())),
            })
            .collect();

        let args_for_db = args.clone();
        let atts_for_db = attendees.clone();
        self.db
            .write(move |conn| {
                repo::calendar::update_local_fields(conn, &args_for_db, &atts_for_db)
            })
            .await?;

        if args.notify && !args.attendees.is_empty() {
            let account_id = existing.account_id;
            let account = self
                .db
                .read(move |conn| repo::accounts::get(conn, account_id))
                .await?
                .ok_or_else(|| CoreError::NotFound("account".into()))?;
            let (uid, sequence) = self
                .db
                .read(move |conn| repo::calendar::uid_and_sequence(conn, event_id))
                .await?
                .ok_or_else(|| CoreError::NotFound("event".into()))?;
            let organizer = Address {
                name: account.display_name.clone(),
                email: account.email.clone(),
            };
            let ics = calendar::build_request_ics(&calendar::InviteSpec {
                uid: &uid,
                sequence,
                summary: args.summary.trim(),
                description: args.description.as_deref(),
                location: args.location.as_deref(),
                join_url: args.join_url.as_deref(),
                organizer: &organizer,
                attendees: &args.attendees,
                starts_at_ms: args.starts_at,
                ends_at_ms: args.ends_at,
                dtstamp_ms: now_ms(),
            });
            let body = invite_body_text(&CreateEventArgs {
                account_id,
                calendar_id: None,
                summary: args.summary.clone(),
                description: args.description.clone(),
                location: args.location.clone(),
                join_url: args.join_url.clone(),
                starts_at: args.starts_at,
                ends_at: args.ends_at,
                all_day: args.all_day,
                attendees: args.attendees.clone(),
            });
            self.send_calendar_mail(
                account_id,
                args.attendees.clone(),
                format!("Updated invitation: {}", args.summary.trim()),
                body,
                &ics,
            )
            .await?;
        }

        self.enqueue_cal_push(event_id, existing.account_id, "cal_put")
            .await?;
        self.db
            .read(move |conn| repo::calendar::get(conn, event_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("event".into()))
    }

    /// Delete an event. Organized events with attendees email a METHOD:CANCEL
    /// when `notify`; CalDAV-backed rows become tombstones deleted at the next
    /// push, purely local rows disappear immediately.
    pub async fn delete_event(&self, event_id: i64, notify: bool) -> Result<()> {
        let ev = self
            .db
            .read(move |conn| repo::calendar::get(conn, event_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("event".into()))?;

        if notify && ev.is_local && !ev.attendees.is_empty() {
            let account_id = ev.account_id;
            let account = self
                .db
                .read(move |conn| repo::accounts::get(conn, account_id))
                .await?
                .ok_or_else(|| CoreError::NotFound("account".into()))?;
            let (uid, sequence) = self
                .db
                .read(move |conn| repo::calendar::uid_and_sequence(conn, event_id))
                .await?
                .ok_or_else(|| CoreError::NotFound("event".into()))?;
            let organizer = Address {
                name: account.display_name.clone(),
                email: account.email.clone(),
            };
            let to: Vec<Address> = ev
                .attendees
                .iter()
                .map(|a| Address {
                    name: a.name.clone(),
                    email: a.email.clone(),
                })
                .collect();
            let title = ev.summary.clone().unwrap_or_else(|| "(no title)".into());
            let ics = calendar::build_cancel_ics(&calendar::InviteSpec {
                uid: &uid,
                sequence: sequence + 1,
                summary: &title,
                description: None,
                location: ev.location.as_deref(),
                join_url: None,
                organizer: &organizer,
                attendees: &to,
                starts_at_ms: ev.starts_at,
                ends_at_ms: ev.ends_at.unwrap_or(ev.starts_at + 1_800_000),
                dtstamp_ms: now_ms(),
            });
            self.send_calendar_mail(
                account_id,
                to,
                format!("Cancelled: {title}"),
                format!("{title} has been cancelled."),
                &ics,
            )
            .await?;
        }

        // CalDAV rows need the server-side DELETE; keep a tombstone and let
        // the push path finish the job. Mail-invite rows keep a terminal
        // tombstone - purging them would let the next re-parse of the
        // archived invitation email resurrect the event. Purely local rows
        // go right away.
        if ev.calendar_id.is_some() {
            self.db
                .write(move |conn| repo::calendar::mark_deleted(conn, event_id))
                .await?;
            self.enqueue_cal_push(event_id, ev.account_id, "cal_delete")
                .await?;
        } else if ev.message_id.is_some() {
            self.db
                .write(move |conn| repo::calendar::mark_deleted(conn, event_id))
                .await?;
        } else {
            self.db
                .write(move |conn| repo::calendar::hard_delete(conn, event_id))
                .await?;
        }
        Ok(())
    }

    // ---------- caldav ----------

    /// Connect a calendar server to an account. Generic servers store the app
    /// password in the keyring; Google reuses the account's OAuth tokens (the
    /// caller must have completed the calendar-scope re-consent first).
    /// Discovery doubles as the connection test - nothing persists on failure.
    pub async fn connect_calendar(&self, args: ConnectCalendarArgs) -> Result<Vec<Calendar>> {
        let account_id = args.account_id;
        let kind = if args.kind == "google" {
            "google"
        } else {
            "generic"
        };
        let base_url = match kind {
            "google" => caldav::GOOGLE_CALDAV_BASE.to_string(),
            _ => {
                let url = args
                    .url
                    .clone()
                    .filter(|u| !u.trim().is_empty())
                    .ok_or_else(|| CoreError::CalDav("server URL is required".into()))?;
                let mut url = url.trim().to_string();
                if !url.contains("://") {
                    url = format!("https://{url}");
                }
                url
            }
        };

        // Build auth without persisting anything yet.
        let auth = match kind {
            "google" => caldav::DavAuth::Bearer(
                self.tokens
                    .access_token(account_id, Provider::Gmail)
                    .await?,
            ),
            _ => {
                let user = args.username.clone().unwrap_or_default();
                let pass = args
                    .password
                    .clone()
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| CoreError::CalDav("password is required".into()))?;
                caldav::DavAuth::Basic(user, pass)
            }
        };
        let transport = caldav::HttpTransport::new(auth)?;
        let discovery = caldav::discovery::discover(&transport, &base_url).await?;

        // Persist: keyring first, then config + collections.
        if kind == "generic" {
            if let Some(pass) = args.password.clone() {
                credentials::store_async(account_id, Slot::CaldavPassword, pass).await?;
            }
        }
        let cfg = repo::caldav::CaldavConfig {
            account_id,
            kind: kind.to_string(),
            base_url,
            username: args.username.clone(),
            principal_url: discovery.principal_url.clone(),
            home_set_url: Some(discovery.home_set_url.clone()),
            enabled: true,
            last_error: None,
        };
        let calendars = discovery.calendars.clone();
        let out = self
            .db
            .write(move |conn| {
                let tx = conn.transaction()?;
                repo::caldav::upsert_config(&tx, &cfg)?;
                let mut first_id = None;
                for c in &calendars {
                    let id = repo::caldav::upsert_calendar(
                        &tx,
                        account_id,
                        &c.url,
                        c.display_name.as_deref(),
                        c.color.as_deref(),
                        false,
                    )?;
                    first_id.get_or_insert(id);
                }
                if let Some(id) = first_id {
                    // Keep an existing default if one is set; else first wins.
                    let has_default: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM calendars WHERE account_id = ?1 AND is_default = 1",
                        rusqlite::params![account_id],
                        |r| r.get(0),
                    )?;
                    if has_default == 0 {
                        repo::caldav::set_default_calendar(&tx, account_id, id)?;
                    }
                }
                let list = repo::caldav::list_calendars(&tx, Some(account_id))?;
                tx.commit()?;
                Ok(list)
            })
            .await?;

        self.spawn_cal_task(account_id).await;
        self.nudge_cal(Some(account_id)).await;
        Ok(out)
    }

    /// Google calendar connection: re-run the OAuth consent with the
    /// calendar scope added (scopes are fixed at consent time, so the account
    /// must re-consent) and swap in the widened tokens, then discover.
    pub async fn connect_google_calendar(
        &self,
        account_id: i64,
        open_url: impl FnOnce(String) + Send,
    ) -> Result<Vec<Calendar>> {
        let account = self
            .db
            .read(move |conn| repo::accounts::get(conn, account_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))?;
        if account.provider != Provider::Gmail {
            return Err(CoreError::CalDav(
                "google calendar needs a Gmail account".into(),
            ));
        }

        let outcome = tokio::select! {
            r = oauth::flow::authorize_with(
                Provider::Gmail,
                &[oauth::providers::GOOGLE_CALENDAR_SCOPE],
                Some(&account.email),
                open_url,
            ) => r?,
            _ = self.oauth_cancel.notified() => {
                return Err(CoreError::Auth("sign-in cancelled".into()));
            }
        };
        if !outcome.email.eq_ignore_ascii_case(&account.email) {
            return Err(CoreError::Auth(format!(
                "consent was granted for {} - expected {}",
                outcome.email, account.email
            )));
        }
        self.tokens
            .store_initial(
                account_id,
                outcome.access_token,
                outcome.expires_in,
                outcome.refresh_token,
            )
            .await?;

        self.connect_calendar(ConnectCalendarArgs {
            account_id,
            kind: "google".into(),
            url: None,
            username: None,
            password: None,
        })
        .await
    }

    /// Mint a Graph token for one extra scope, widening consent in the
    /// browser when the scope was never granted (incremental consent, like
    /// `connect_google_calendar`). `open_url` opens the consent page.
    async fn graph_token_with_consent(
        &self,
        account_id: i64,
        scope: &str,
        open_url: impl FnOnce(String) + Send,
    ) -> Result<String> {
        let account = self
            .db
            .read(move |conn| repo::accounts::get(conn, account_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("account".into()))?;
        if account.provider != Provider::Microsoft {
            return Err(CoreError::Auth("needs a Microsoft account".into()));
        }

        let extra_scopes = [scope];
        match self
            .tokens
            .access_token_for_scope(account_id, Provider::Microsoft, scope)
            .await
        {
            Ok(t) => Ok(t),
            // Scope not yet consented (or refresh token stale): widen consent
            // in the browser, then mint the Graph token again.
            Err(CoreError::NeedsReauth) => {
                let outcome = tokio::select! {
                    r = oauth::flow::authorize_with(
                        Provider::Microsoft,
                        &extra_scopes,
                        Some(&account.email),
                        open_url,
                    ) => r?,
                    _ = self.oauth_cancel.notified() => {
                        return Err(CoreError::Auth("sign-in cancelled".into()));
                    }
                };
                if !outcome.email.eq_ignore_ascii_case(&account.email) {
                    return Err(CoreError::Auth(format!(
                        "consent was granted for {} - expected {}",
                        outcome.email, account.email
                    )));
                }
                self.tokens
                    .store_initial(
                        account_id,
                        outcome.access_token,
                        outcome.expires_in,
                        outcome.refresh_token,
                    )
                    .await?;
                self.tokens
                    .access_token_for_scope(account_id, Provider::Microsoft, scope)
                    .await
            }
            Err(e) => Err(e),
        }
    }

    /// Create a Microsoft Teams online meeting for a Microsoft account and
    /// return its join URL (for insertion into a compose draft).
    ///
    /// Needs a Graph-scoped token; the first attempt may trigger an
    /// incremental re-consent in the browser.
    pub async fn create_teams_meeting(
        &self,
        account_id: i64,
        subject: &str,
        start_ms: i64,
        end_ms: i64,
        open_url: impl FnOnce(String) + Send,
    ) -> Result<graph::OnlineMeeting> {
        let token = self
            .graph_token_with_consent(
                account_id,
                oauth::providers::MS_ONLINE_MEETINGS_SCOPE,
                open_url,
            )
            .await?;
        graph::create_online_meeting(&token, subject, start_ms, end_ms).await
    }

    /// Microsoft calendar connection: Outlook / Microsoft 365 has no CalDAV
    /// endpoint, so the calendar syncs via Graph. Widens consent to
    /// `Calendars.ReadWrite` when needed, lists the account's calendars and
    /// persists them under a "microsoft"-kind config; the shared calendar
    /// task then pulls via calendarView delta.
    pub async fn connect_microsoft_calendar(
        &self,
        account_id: i64,
        open_url: impl FnOnce(String) + Send,
    ) -> Result<Vec<Calendar>> {
        let token = self
            .graph_token_with_consent(account_id, oauth::providers::MS_CALENDARS_SCOPE, open_url)
            .await?;
        let discovered = graph::list_calendars(&token).await?;
        if discovered.is_empty() {
            return Err(CoreError::CalDav("no calendars found".into()));
        }

        let cfg = repo::caldav::CaldavConfig {
            account_id,
            kind: "microsoft".to_string(),
            base_url: graph::GRAPH_BASE.to_string(),
            username: None,
            principal_url: None,
            home_set_url: None,
            enabled: true,
            last_error: None,
        };
        let out = self
            .db
            .write(move |conn| {
                let tx = conn.transaction()?;
                repo::caldav::upsert_config(&tx, &cfg)?;
                let mut default_id = None;
                let mut first_id = None;
                for c in &discovered {
                    let id = repo::caldav::upsert_calendar(
                        &tx,
                        account_id,
                        &c.id,
                        c.name.as_deref(),
                        c.hex_color.as_deref(),
                        !c.can_edit,
                    )?;
                    first_id.get_or_insert(id);
                    if c.is_default {
                        default_id.get_or_insert(id);
                    }
                }
                if let Some(id) = default_id.or(first_id) {
                    // Keep an existing default if one is set; else Outlook's
                    // default calendar (or the first) wins.
                    let has_default: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM calendars WHERE account_id = ?1 AND is_default = 1",
                        rusqlite::params![account_id],
                        |r| r.get(0),
                    )?;
                    if has_default == 0 {
                        repo::caldav::set_default_calendar(&tx, account_id, id)?;
                    }
                }
                let list = repo::caldav::list_calendars(&tx, Some(account_id))?;
                tx.commit()?;
                Ok(list)
            })
            .await?;

        self.spawn_cal_task(account_id).await;
        self.nudge_cal(Some(account_id)).await;
        Ok(out)
    }

    /// Disconnect the calendar server: events stay locally, sync bookkeeping
    /// is cleared, credentials removed.
    pub async fn disconnect_calendar(&self, account_id: i64) -> Result<()> {
        self.cal_handles.write().await.remove(&account_id);
        self.db
            .write(move |conn| repo::caldav::delete_config(conn, account_id))
            .await?;
        let _ = tokio::task::spawn_blocking(move || {
            let _ = credentials::store(account_id, Slot::CaldavPassword, "");
        })
        .await;
        self.bus.emit(CoreEvent::CalendarUpdated { account_id });
        Ok(())
    }

    pub async fn list_calendars(&self, account_id: Option<i64>) -> Result<Vec<Calendar>> {
        self.db
            .read(move |conn| repo::caldav::list_calendars(conn, account_id))
            .await
    }

    pub async fn set_calendar_enabled(&self, calendar_id: i64, enabled: bool) -> Result<()> {
        self.db
            .write(move |conn| repo::caldav::set_calendar_enabled(conn, calendar_id, enabled))
            .await?;
        let cal = self
            .db
            .read(move |conn| repo::caldav::get_calendar(conn, calendar_id))
            .await?;
        if let Some(cal) = cal {
            self.bus.emit(CoreEvent::CalendarUpdated {
                account_id: cal.account_id,
            });
        }
        Ok(())
    }

    /// User override of the calendar's display color (`#RRGGBB`). None
    /// clears the override so the next discovery restores the server color.
    pub async fn set_calendar_color(&self, calendar_id: i64, color: Option<String>) -> Result<()> {
        if let Some(c) = &color {
            let valid = c.len() == 7
                && c.starts_with('#')
                && c[1..].chars().all(|ch| ch.is_ascii_hexdigit());
            if !valid {
                return Err(CoreError::Other("invalid color".into()));
            }
        }
        let cal = self
            .db
            .read(move |conn| repo::caldav::get_calendar(conn, calendar_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("calendar".into()))?;
        self.db
            .write(move |conn| {
                repo::caldav::set_calendar_color(conn, calendar_id, color.as_deref())
            })
            .await?;
        self.bus.emit(CoreEvent::CalendarUpdated {
            account_id: cal.account_id,
        });
        Ok(())
    }

    /// Make this calendar the account's target for newly created events.
    pub async fn set_default_calendar(&self, calendar_id: i64) -> Result<()> {
        let cal = self
            .db
            .read(move |conn| repo::caldav::get_calendar(conn, calendar_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("calendar".into()))?;
        if cal.read_only {
            return Err(CoreError::Other("calendar is read-only".into()));
        }
        let account_id = cal.account_id;
        self.db
            .write(move |conn| repo::caldav::set_default_calendar(conn, account_id, calendar_id))
            .await?;
        self.bus.emit(CoreEvent::CalendarUpdated { account_id });
        Ok(())
    }

    pub async fn calendar_sync_now(&self, account_id: Option<i64>) {
        self.nudge_cal(account_id).await;
    }

    // ---------- carddav (read-only contacts) ----------

    /// Connect a CardDAV server to an account. The password is typed, or
    /// reused from a generic CalDAV login on the same server. Discovery
    /// doubles as the connection test - nothing persists on failure.
    pub async fn connect_contacts(&self, args: ConnectContactsArgs) -> Result<ContactServer> {
        let account_id = args.account_id;
        let base_url = carddav::normalize_url(&args.url)
            .ok_or_else(|| CoreError::CardDav("server URL is required".into()))?;
        let host = carddav::host_of(&base_url)
            .ok_or_else(|| CoreError::CardDav(format!("bad server URL {base_url}")))?;

        let (username, password) = match args.reuse_calendar_account_id {
            Some(cal_account) => {
                let login = self
                    .list_calendar_logins()
                    .await?
                    .into_iter()
                    .find(|l| l.account_id == cal_account)
                    .ok_or_else(|| CoreError::CardDav("no calendar sign-in to reuse".into()))?;
                // The calendar password only ever goes to its own server.
                if !login.hosts.iter().any(|h| carddav::same_server(&host, h)) {
                    return Err(CoreError::CardDav(format!(
                        "the calendar sign-in belongs to a different server than {host}"
                    )));
                }
                let pass = credentials::load_async(cal_account, Slot::CaldavPassword).await?;
                (login.username, pass)
            }
            None => {
                let pass = args
                    .password
                    .clone()
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| CoreError::CardDav("password is required".into()))?;
                (args.username.clone().unwrap_or_default(), pass)
            }
        };

        let transport =
            caldav::HttpTransport::new(caldav::DavAuth::Basic(username.clone(), password.clone()))
                .map_err(carddav::as_carddav)?;
        let discovery = carddav::discovery::discover(&transport, &base_url).await?;

        // Persist: keyring first, then config + address books.
        credentials::store_async(account_id, Slot::CarddavPassword, password).await?;
        let cfg = repo::carddav::CarddavConfig {
            account_id,
            base_url,
            username: Some(username),
            principal_url: discovery.principal_url.clone(),
            home_set_url: Some(discovery.home_set_url.clone()),
            enabled: true,
            last_error: None,
            last_synced_at: None,
        };
        let books = discovery.books;
        let server = self
            .db
            .write(move |conn| {
                let tx = conn.transaction()?;
                repo::carddav::upsert_config(&tx, &cfg)?;
                let urls: Vec<String> = books.iter().map(|b| b.url.clone()).collect();
                repo::carddav::prune_address_books(&tx, account_id, &urls)?;
                for b in &books {
                    repo::carddav::upsert_address_book(
                        &tx,
                        account_id,
                        &b.url,
                        b.display_name.as_deref(),
                    )?;
                }
                let server = repo::carddav::list_servers(&tx)?
                    .into_iter()
                    .find(|s| s.account_id == account_id);
                tx.commit()?;
                Ok(server)
            })
            .await?
            .ok_or_else(|| CoreError::NotFound("contact server".into()))?;

        // A reconnect replaces the running task; the first pull starts now.
        self.spawn_contacts_task(account_id).await;
        self.nudge_contacts(Some(account_id)).await;
        self.bus.emit(CoreEvent::ContactsUpdated {
            account_id,
            changed: false,
        });
        Ok(server)
    }

    /// Disconnect the CardDAV server: its contacts go (harvested ones keep
    /// what mail taught us), credentials are removed.
    pub async fn disconnect_contacts(&self, account_id: i64) -> Result<()> {
        self.contacts_handles.write().await.remove(&account_id);
        self.db
            .write(move |conn| {
                let tx = conn.transaction()?;
                repo::carddav::delete_config(&tx, account_id)?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        let _ = tokio::task::spawn_blocking(move || {
            credentials::delete(account_id, Slot::CarddavPassword);
        })
        .await;
        self.bus.emit(CoreEvent::ContactsUpdated {
            account_id,
            changed: true,
        });
        Ok(())
    }

    /// Every connected CardDAV server with its address books and sync status.
    pub async fn list_contact_servers(&self) -> Result<Vec<ContactServer>> {
        self.db.read(|conn| repo::carddav::list_servers(conn)).await
    }

    /// Include or exclude one address book. Excluding drops its contacts
    /// right away; including pulls it in full.
    pub async fn set_address_book_enabled(
        &self,
        address_book_id: i64,
        enabled: bool,
    ) -> Result<()> {
        let book = self
            .db
            .read(move |conn| repo::carddav::get_address_book(conn, address_book_id))
            .await?
            .ok_or_else(|| CoreError::NotFound("address book".into()))?;
        self.db
            .write(move |conn| {
                let tx = conn.transaction()?;
                repo::carddav::set_address_book_enabled(&tx, address_book_id, enabled)?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        if enabled {
            self.nudge_contacts(Some(book.account_id)).await;
        }
        self.bus.emit(CoreEvent::ContactsUpdated {
            account_id: book.account_id,
            changed: !enabled,
        });
        Ok(())
    }

    pub async fn contacts_sync_now(&self, account_id: Option<i64>) {
        self.nudge_contacts(account_id).await;
    }

    /// Address-book details for one email address (contact pane); None when
    /// no enabled address book holds it.
    pub async fn get_contact_card(&self, email: String) -> Result<Option<ContactCard>> {
        self.db
            .read(move |conn| repo::carddav::card_for_email(conn, &email))
            .await
    }

    /// Generic CalDAV logins a CardDAV connection could reuse (no secrets).
    pub async fn list_calendar_logins(&self) -> Result<Vec<CalendarLogin>> {
        self.db
            .read(|conn| {
                let mut out = Vec::new();
                for cfg in repo::caldav::all_configs(conn)? {
                    if cfg.kind != "generic" {
                        continue;
                    }
                    let calendars = repo::caldav::list_calendars(conn, Some(cfg.account_id))?;
                    let mut hosts: Vec<String> = Vec::new();
                    for url in
                        std::iter::once(&cfg.base_url).chain(calendars.iter().map(|c| &c.url))
                    {
                        if let Some(h) = carddav::host_of(url) {
                            if !hosts.contains(&h) {
                                hosts.push(h);
                            }
                        }
                    }
                    out.push(CalendarLogin {
                        account_id: cfg.account_id,
                        username: cfg.username.unwrap_or_default(),
                        hosts,
                    });
                }
                Ok(out)
            })
            .await
    }

    /// Queue a CalDAV write for the account's calendar task, when the account
    /// has one configured. No-op otherwise (purely local calendars).
    async fn enqueue_cal_push(&self, event_id: i64, account_id: i64, kind: &str) -> Result<()> {
        let kind = kind.to_string();
        self.db
            .write(move |conn| {
                if repo::caldav::get_config(conn, account_id)?.is_none() {
                    return Ok(());
                }
                // Dirty guards the row against being clobbered by a pull that
                // runs between now and the push.
                if kind == "cal_put" {
                    repo::calendar::mark_dirty(conn, event_id)?;
                }
                let payload = serde_json::json!({ "eventId": event_id });
                repo::actions::enqueue(conn, account_id, &kind, None, None, &payload, None)?;
                Ok(())
            })
            .await?;
        self.nudge_cal(Some(account_id)).await;
        Ok(())
    }

    /// Draft + queue an email carrying an ICS part, through the normal send
    /// pipeline. The ICS is staged like an attachment.
    async fn send_calendar_mail(
        &self,
        account_id: i64,
        to: Vec<Address>,
        subject: String,
        body_text: String,
        ics: &str,
    ) -> Result<()> {
        let tmp_dir = self.paths.data_dir.join("tmp");
        tokio::fs::create_dir_all(&tmp_dir).await?;
        let tmp_path = tmp_dir.join(format!("invite-{}.ics", crate::mime::rand_token()));
        tokio::fs::write(&tmp_path, ics.as_bytes()).await?;

        let draft_id = self
            .save_draft(SaveDraftArgs {
                draft_id: None,
                account_id,
                to,
                cc: Vec::new(),
                bcc: Vec::new(),
                subject,
                body_text,
                body_html: None,
                mode: "new".into(),
                in_reply_to_message_id: None,
                attachments: vec![DraftAttachmentIn {
                    file_path: tmp_path.to_string_lossy().into_owned(),
                    filename: "invite.ics".into(),
                }],
            })
            .await?;
        // The draft staged its own copy; the temp file can go.
        let _ = tokio::fs::remove_file(&tmp_path).await;
        self.queue_send(QueueSendArgs {
            draft_id,
            send_at: None,
        })
        .await?;
        Ok(())
    }

    // ---------- AI ----------

    async fn ai_config(&self, scenario: Scenario) -> Result<ai::AiConfig> {
        let settings = self.db.read(|conn| repo::settings::get(conn)).await?;
        self.ai_config_from(&settings, scenario).await
    }

    /// Build an [`ai::AiConfig`] for `scenario` from already-loaded settings,
    /// picking the model for the scenario's tier (all tiers share the base URL
    /// and stored API key).
    async fn ai_config_from(
        &self,
        settings: &Settings,
        scenario: Scenario,
    ) -> Result<ai::AiConfig> {
        let on_device = ai::apple::is_apple(&settings.ai_base_url);
        let api_key = match credentials::load_async(0, Slot::AiApiKey).await {
            Ok(k) if !on_device => k,
            // Apple Intelligence runs on-device; local endpoints (LM Studio,
            // Ollama over http://) need no key either. Hosted ones do, so fail
            // early with a pointer to Settings.
            _ if on_device || settings.ai_base_url.starts_with("http://") => String::new(),
            _ => return Err(CoreError::AiNotConfigured),
        };
        Ok(ai::AiConfig {
            base_url: settings.ai_base_url.clone(),
            // The on-device provider has exactly one model, whatever the tier.
            model: if on_device {
                ai::apple::MODEL_ID.to_string()
            } else {
                resolve_ai_model(settings, scenario)
            },
            api_key,
            language: ai::ui_language_name(&settings.language).map(str::to_string),
            zero_retention: settings.ai_zero_retention,
            usage_sink: self.usage_sink(scenario),
        })
    }

    /// Records each model call's token usage under `scenario`.
    fn usage_sink(&self, scenario: Scenario) -> Option<Arc<dyn Fn(ai::AiUsage) + Send + Sync>> {
        let db = self.db.clone();
        let scenario = scenario.as_str().to_string();
        Some(Arc::new(move |usage: ai::AiUsage| {
            let db = db.clone();
            let scenario = scenario.clone();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let result = db
                        .write(move |conn| {
                            repo::ai_usage::record(
                                conn,
                                now_ms(),
                                &usage.model,
                                &scenario,
                                usage.prompt_tokens,
                                usage.completion_tokens,
                                usage.total_tokens,
                                usage.exact,
                            )
                        })
                        .await;
                    if let Err(e) = result {
                        tracing::warn!("recording ai usage: {e}");
                    }
                });
            }
        }))
    }

    /// The primary decision endpoint followed by the backups, in order.
    fn decision_endpoints(settings: &Settings) -> Vec<DecisionEndpoint> {
        let mut out = vec![DecisionEndpoint {
            provider: settings.decision_provider.clone(),
            model: settings.decision_model.clone(),
            base_url: settings.decision_base_url.clone(),
            format: settings.decision_format.clone(),
        }];
        out.extend(settings.decision_backups.iter().cloned());
        out.retain(|e| e.provider != "off" && !e.provider.is_empty());
        out
    }

    /// One endpoint resolved to a callable config, or `None` when it's
    /// incomplete or keyless. OpenRouter and custom endpoints fall back to the
    /// chat AI key; OpenAI does only when the chat endpoint is OpenAI too.
    async fn decision_config(
        &self,
        settings: &Settings,
        ep: &DecisionEndpoint,
    ) -> Option<ai::decisions::DecisionConfig> {
        use ai::decisions::{self as dec, Dialect};
        let (url, dialect, default_model, slot) = match ep.provider.as_str() {
            "openrouter" => (
                dec::OPENROUTER_URL.to_string(),
                Dialect::OpenRouter,
                dec::DEFAULT_OPENROUTER_MODEL,
                Slot::DecisionApiKey,
            ),
            "openai" => (
                dec::OPENAI_URL.to_string(),
                Dialect::OpenAi,
                dec::DEFAULT_OPENAI_MODEL,
                Slot::DecisionOpenAiKey,
            ),
            "custom" if !ep.base_url.trim().is_empty() => {
                let dialect = Dialect::from_setting(&ep.format);
                let model = match dialect {
                    Dialect::OpenRouter => dec::DEFAULT_OPENROUTER_MODEL,
                    Dialect::OpenAi => dec::DEFAULT_OPENAI_MODEL,
                };
                (
                    ep.base_url.trim().to_string(),
                    dialect,
                    model,
                    Slot::DecisionCustomKey,
                )
            }
            _ => return None,
        };
        let share_ai_key = match ep.provider.as_str() {
            "openai" => settings.ai_base_url.contains("api.openai.com"),
            _ => true,
        };
        let api_key = match credentials::load_async(0, slot).await {
            Ok(k) => k,
            Err(_) => match credentials::load_async(0, Slot::AiApiKey).await {
                Ok(k) if share_ai_key => k,
                // Local custom endpoints may need no key.
                _ if url.starts_with("http://") => String::new(),
                _ => return None,
            },
        };
        let model = ep.model.trim();
        Some(dec::DecisionConfig {
            provider: ep.provider.clone(),
            url,
            model: if model.is_empty() {
                default_model.to_string()
            } else {
                model.to_string()
            },
            api_key,
            dialect,
            min_confidence: settings.decision_min_confidence.clamp(0.0, 1.0),
            zero_retention: settings.ai_zero_retention,
            usage_sink: self.usage_sink(Scenario::Categorize),
        })
    }

    /// Every usable decision endpoint, primary first.
    async fn decision_configs(&self, settings: &Settings) -> Vec<ai::decisions::DecisionConfig> {
        let mut out = Vec::new();
        for ep in Self::decision_endpoints(settings) {
            if let Some(cfg) = self.decision_config(settings, &ep).await {
                out.push(cfg);
            }
        }
        out
    }

    /// Who answers AI checks and categories for one feature: decision models
    /// (when enabled for it), then the chat model (API, local, or Apple
    /// on-device) when allowed. Empty = no AI: checks count as "no" and
    /// categories use the built-in heuristic.
    async fn deciders(&self, settings: &Settings, use_decision: bool) -> Deciders {
        let decision = if use_decision {
            self.decision_configs(settings).await
        } else {
            Vec::new()
        };
        let chat = if decision.is_empty() || settings.decision_chat_fallback {
            self.ai_config_from(settings, Scenario::Categorize)
                .await
                .ok()
        } else {
            None
        };
        Deciders {
            decision,
            chat,
            min_confidence: settings.decision_min_confidence.clamp(0.0, 1.0),
        }
    }

    pub async fn ai_usage_stats(&self) -> Result<AiUsageStats> {
        self.db.read(|conn| repo::ai_usage::stats(conn)).await
    }

    pub async fn email_stats(&self) -> Result<EmailStats> {
        self.db.read(|conn| repo::email_stats::stats(conn)).await
    }

    /// Translate a plain-language automation request into a validated action
    /// plan. This only previews behavior; it never executes mailbox actions.
    pub async fn ai_plan_automation(&self, prompt: String) -> Result<AiAutomationPlan> {
        let prompt = prompt.trim();
        if prompt.is_empty() {
            return Ok(AiAutomationPlan {
                issues: vec!["Describe the emails to match and what Comail should do.".into()],
                ..AiAutomationPlan::default()
            });
        }
        let (settings, labels, splits) = self
            .db
            .read(|conn| {
                Ok((
                    repo::settings::get(conn)?,
                    repo::labels::list(conn)?,
                    repo::splits::list(conn)?,
                ))
            })
            .await?;
        let cfg = self.ai_config_from(&settings, Scenario::Categorize).await?;
        let messages = route::automation_planner_prompt(prompt, &labels, &splits);
        let output = ai::chat_structured(
            &cfg,
            messages,
            "automation_plan",
            route::automation_plan_schema(),
        )
        .await?;
        Ok(route::validate_automation_plan(
            route::parse_automation_plan(&output),
            &labels,
            &splits,
        ))
    }

    pub async fn set_ai_key(&self, api_key: String) -> Result<()> {
        if api_key.trim().is_empty() {
            credentials::delete_all(0);
            return Ok(());
        }
        credentials::store_async(0, Slot::AiApiKey, api_key.trim().to_string()).await
    }

    /// Store (or, when empty, forget) the decision API key for one provider
    /// ("openrouter" | "openai" | "custom"). Unset falls back to the chat AI key.
    pub async fn set_decision_key(&self, provider: String, api_key: String) -> Result<()> {
        let slot = || match provider.as_str() {
            "openai" => Slot::DecisionOpenAiKey,
            "custom" => Slot::DecisionCustomKey,
            _ => Slot::DecisionApiKey,
        };
        let key = api_key.trim().to_string();
        if key.is_empty() {
            let slot = slot();
            tokio::task::spawn_blocking(move || credentials::delete(0, slot))
                .await
                .map_err(|e| CoreError::Other(e.to_string()))?;
            return Ok(());
        }
        credentials::store_async(0, slot(), key).await
    }

    pub async fn ai_status(&self) -> Result<AiStatus> {
        let settings = self.db.read(|conn| repo::settings::get(conn)).await?;
        let apple = ai::apple::availability();
        let decision = self.decision_configs(&settings).await.into_iter().next();
        let (configured, model) = if ai::apple::is_apple(&settings.ai_base_url) {
            (
                apple == ai::apple::Availability::Available,
                ai::apple::MODEL_ID.to_string(),
            )
        } else {
            (
                credentials::load_async(0, Slot::AiApiKey).await.is_ok()
                    || settings.ai_base_url.starts_with("http://"),
                settings.ai_model,
            )
        };
        Ok(AiStatus {
            configured,
            model,
            base_url: settings.ai_base_url,
            apple_intelligence: apple.as_str().to_string(),
            decision_configured: decision.is_some(),
            decision_model: decision.map(|d| d.model).unwrap_or_default(),
        })
    }

    /// Model ids from the configured endpoint. Works keyless on OpenRouter,
    /// so this is available before an API key is saved.
    pub async fn ai_list_models(&self) -> Result<Vec<String>> {
        let settings = self.db.read(|conn| repo::settings::get(conn)).await?;
        let api_key = credentials::load_async(0, Slot::AiApiKey)
            .await
            .unwrap_or_default();
        ai::list_models(&settings.ai_base_url, &api_key).await
    }

    /// Parse a natural-language palette query ("meeting tomorrow 8pm ...")
    /// into a structured intent the UI can execute.
    pub async fn ai_command(&self, query: String) -> Result<AiIntent> {
        let cfg = self.ai_config(Scenario::Command).await?;
        ai::intent(&cfg, &query).await
    }

    /// Turn a plain-language description ("all email from hoang with subject
    /// software update") into a search query, grounded in matching contacts.
    /// May instead return a clarifying question; the UI re-calls with the
    /// answers in `history`.
    pub async fn ai_search_filter(
        &self,
        request: String,
        history: Vec<ai::search_filter::FilterTurn>,
    ) -> Result<ai::search_filter::SearchFilter> {
        let cfg = self.ai_config(Scenario::Command).await?;
        let words = ai::search_filter::name_candidates(&request);
        let (contacts, self_emails) = self
            .db
            .read(move |conn| {
                let mut seen = HashSet::new();
                let mut contacts = Vec::new();
                for w in &words {
                    for c in repo::contacts::suggest(conn, w, None, 6)? {
                        if seen.insert(c.email.to_lowercase()) {
                            contacts.push(c);
                        }
                    }
                }
                contacts.truncate(24);
                let selves = repo::accounts::list(conn)?
                    .into_iter()
                    .map(|a| a.email)
                    .collect::<Vec<_>>();
                Ok((contacts, selves))
            })
            .await?;
        ai::search_filter::search_filter(&cfg, &request, &history, &contacts, &self_emails).await
    }

    pub async fn ai_summarize(&self, thread_id: i64) -> Result<crate::models::AiThreadSummary> {
        let cfg = self.ai_config(Scenario::Summarize).await?;
        let detail = self.get_thread(thread_id).await?;
        let budget = ai::apple::context_chars(&cfg.base_url, 24_000);
        let context = ai::thread_context(&detail.messages, budget);
        let bus = self.bus.clone();
        ai::summarize_thread_stream(&cfg, &detail.thread.subject, &context, move |delta| {
            bus.emit(CoreEvent::AiSummaryDelta {
                thread_id,
                delta: delta.to_owned(),
            });
        })
        .await
    }

    /// Up to 3 short one-tap reply suggestions grounded in the thread, shown
    /// as chips in an empty reply composer. Runs on the instant tier: the
    /// chips are only useful if they appear before the user starts typing.
    /// With `ai_quick_replies` off nothing is sent and the list is empty.
    pub async fn ai_quick_replies(&self, thread_id: i64) -> Result<Vec<String>> {
        let settings = self.db.read(|conn| repo::settings::get(conn)).await?;
        if !settings.ai_quick_replies {
            return Ok(Vec::new());
        }
        let cfg = self.ai_config_from(&settings, Scenario::QuickReply).await?;
        let detail = self.get_thread(thread_id).await?;
        let budget = ai::apple::context_chars(&cfg.base_url, 12_000);
        let context = ai::thread_context(&detail.messages, budget);
        // Match the user's learned voice when voice drafting is enabled, same as
        // full AI drafts; otherwise pass an empty profile for the neutral prompt.
        let profile = if settings.voice_drafting {
            settings.voice_profile.as_str()
        } else {
            ""
        };
        ai::quick_replies(&cfg, &detail.thread.subject, &context, profile).await
    }

    /// Draft or rewrite email body text. With a thread, the reply is grounded
    /// in its content; without, it's freeform writing from the instruction.
    /// A non-empty `current_draft` switches to edit mode: the model revises it
    /// per the instruction instead of writing from scratch.
    /// When `voice` (or the persisted setting) is on, the draft imitates the
    /// user's learned writing style and their similar past sent emails.
    /// With a `request_id`, answer text streams as [`CoreEvent::AiDraftDelta`]
    /// while it's generated; the full draft is still returned at the end.
    #[allow(clippy::too_many_arguments)]
    pub async fn ai_draft(
        &self,
        thread_id: Option<i64>,
        reply_to_message_id: Option<i64>,
        instruction: String,
        current_draft: String,
        sender_name: String,
        voice: Option<bool>,
        has_signature: bool,
        request_id: Option<String>,
    ) -> Result<String> {
        let settings = self.db.read(|conn| repo::settings::get(conn)).await?;
        let cfg = self.ai_config_from(&settings, Scenario::Draft).await?;
        let use_voice = voice.unwrap_or(settings.voice_drafting);

        let (subject, context, reply_target) = match thread_id {
            Some(tid) => {
                let detail = self.get_thread(tid).await?;
                (
                    detail.thread.subject.clone(),
                    ai::thread_context(
                        &detail.messages,
                        ai::apple::context_chars(&cfg.base_url, 24_000),
                    ),
                    ai::reply_target_line(&detail.messages, reply_to_message_id),
                )
            }
            None => (String::new(), String::new(), String::new()),
        };

        let prompt = if use_voice {
            let query = format!("{subject}\n{instruction}");
            // The on-device model's small window fits one example, not three.
            let n = if ai::apple::is_apple(&cfg.base_url) {
                1
            } else {
                3
            };
            let examples = self.voice_examples(&query, n).await.unwrap_or_default();
            ai::draft_prompt_voiced(
                &subject,
                &context,
                &reply_target,
                &instruction,
                &current_draft,
                &sender_name,
                &settings.voice_profile,
                &examples,
                has_signature,
            )
        } else {
            ai::draft_prompt(
                &subject,
                &context,
                &reply_target,
                &instruction,
                &current_draft,
                &sender_name,
                has_signature,
            )
        };
        let messages = ai::apply_language(prompt, &cfg);

        match request_id {
            Some(request_id) => {
                let bus = self.bus.clone();
                ai::chat_stream(&cfg, messages, move |delta| {
                    bus.emit(CoreEvent::AiDraftDelta {
                        request_id: request_id.clone(),
                        delta: delta.to_owned(),
                    });
                })
                .await
            }
            None => ai::chat(&cfg, messages).await,
        }
    }

    /// Typed follow-ups for a finished draft (e.g. "create this event"),
    /// decided by the model against a strict schema. Empty when none fit.
    pub async fn ai_draft_actions(
        &self,
        thread_id: Option<i64>,
        draft: String,
    ) -> Result<Vec<AiDraftAction>> {
        let cfg = self.ai_config(Scenario::Command).await?;
        let (subject, context) = match thread_id {
            Some(tid) => {
                let detail = self.get_thread(tid).await?;
                (
                    detail.thread.subject.clone(),
                    ai::thread_context(
                        &detail.messages,
                        ai::apple::context_chars(&cfg.base_url, 12_000),
                    ),
                )
            }
            None => (String::new(), String::new()),
        };
        ai::draft_actions(&cfg, &subject, &context, &draft).await
    }

    /// Copy-edit a draft body (plain text or simple HTML) without changing
    /// meaning, tone, or language. Returns the corrected draft.
    pub async fn ai_proofread(&self, body: String) -> Result<String> {
        let cfg = self.ai_config(Scenario::Draft).await?;
        ai::chat(&cfg, ai::proofread_prompt(&body)).await
    }

    /// Generate a clean email signature for an account from its name and
    /// address. Returns plain text with line breaks for the caller to render.
    pub async fn ai_signature(&self, name: String, email: String) -> Result<String> {
        let cfg = self.ai_config(Scenario::Draft).await?;
        ai::chat(
            &cfg,
            ai::apply_language(ai::signature_prompt(&name, &email), &cfg),
        )
        .await
    }

    /// Distill the user's writing voice from their sent mail and persist it as
    /// a style profile. Returns the profile text.
    pub async fn ai_learn_voice(&self) -> Result<String> {
        let cfg = self.ai_config(Scenario::Voice).await?;
        let samples = self
            .db
            .read(|conn| {
                let rows = repo::messages::list_sent_bodies(conn, None, 30)?;
                Ok::<_, CoreError>(
                    rows.into_iter()
                        .map(|(_, subj, body)| format!("Subject: {subj}\n{body}"))
                        .collect::<Vec<_>>(),
                )
            })
            .await?;
        if samples.is_empty() {
            return Err(CoreError::Other(
                "No sent emails to learn from yet. Send or sync some mail first.".into(),
            ));
        }
        let profile = ai::chat(&cfg, ai::voice_profile_prompt(&samples)).await?;

        let p = profile.clone();
        let now = now_ms();
        self.db
            .write(move |conn| {
                let mut s = repo::settings::get(conn)?;
                s.voice_profile = p;
                s.voice_learned_at = now;
                repo::settings::set(conn, &s)
            })
            .await?;
        Ok(profile)
    }

    /// Up to `k` (incoming → the user's reply) exchanges from their sent mail
    /// most relevant to `query`, for few-shot voice imitation. Prefers semantic
    /// retrieval; falls back to recent sent mail when the index is empty.
    async fn voice_examples(&self, query: &str, k: usize) -> Result<Vec<(String, String)>> {
        let hits = self.vector_hits(query, 40, None).await.unwrap_or_default();
        let hit_ids: Vec<i64> = hits.iter().map(|(id, _)| *id).collect();
        self.db
            .read(move |conn| {
                let sent_ids = repo::messages::filter_sent(conn, &hit_ids)?;
                let mut out: Vec<(String, String)> = Vec::new();
                for mid in sent_ids {
                    if out.len() >= k {
                        break;
                    }
                    if let Some(pair) = build_example_pair(conn, mid)? {
                        out.push(pair);
                    }
                }
                if out.is_empty() {
                    // No index / no similar sent mail: use recent sent as exemplars.
                    for (_, subject, body) in
                        repo::messages::list_sent_bodies(conn, None, k as i64)?
                    {
                        out.push((format!("(Compose a new email. Subject: {subject})"), body));
                    }
                }
                Ok::<_, CoreError>(out)
            })
            .await
    }

    // ---------- search ----------

    pub async fn search(
        &self,
        query: String,
        account_id: Option<i64>,
        limit: i64,
    ) -> Result<repo::search::SearchResults> {
        let mut parsed = search::parse(&query);
        // Scope every branch (lexical, semantic, operator filters) to the UI's
        // active account when one is selected; None searches all accounts.
        parsed.account_id = account_id;
        let limit = limit.clamp(1, 100);
        let t0 = std::time::Instant::now();

        // The lexical DB read and the semantic branch (a CPU-bound model
        // forward pass + KNN) are independent - run them concurrently so
        // latency is max(lexical, semantic), not their sum. Semantic is
        // best-effort and skipped for queries too short to carry meaning.
        let lex_fut = {
            let q = parsed.clone();
            self.db.read(move |conn| {
                repo::search::lexical_candidates(conn, &q, repo::search::candidate_cap(limit))
            })
        };
        let vec_fut = async {
            if parsed.text.chars().count() < 3 {
                Vec::new()
            } else {
                self.vector_hits(&parsed.text, 200, parsed.account_id)
                    .await
                    .unwrap_or_default()
            }
        };
        let (lexical, vec_hits) = tokio::join!(lex_fut, vec_fut);
        let lexical = lexical?;
        let t_branches = t0.elapsed();

        let parsed2 = parsed.clone();
        let out = self
            .db
            .read(move |conn| {
                let now = chrono::Utc::now().timestamp_millis();
                let mut out = repo::search::rank(conn, &parsed2, lexical, &vec_hits, limit, now)?;
                out.explain = repo::search::explain(conn, &parsed2)?;
                Ok(out)
            })
            .await;
        // Query text stays out of the log: it is often a name or address.
        tracing::debug!(
            query_chars = parsed.text.chars().count(),
            "search: branches {:?}, rank+hydrate {:?}",
            t_branches,
            t0.elapsed() - t_branches
        );
        out
    }

    /// What `query` will do - its understood filters and anything it could
    /// not use - for the search box's live explain row. Cheap: parsing plus a
    /// label-table lookup, so it can run on every keystroke.
    pub async fn explain_search(&self, query: String) -> Result<search::SearchExplain> {
        self.db
            .read(move |conn| repo::search::explain(conn, &search::parse(&query)))
            .await
    }

    /// Remember that `thread_id` was opened from a search for `query`, so
    /// future searches rank it (and its sender) higher. Local only.
    pub async fn record_search_open(&self, query: String, thread_id: i64) -> Result<()> {
        let key = search::parse(&query).terms.join(" ");
        self.db
            .write(move |conn| {
                repo::search_history::record(
                    conn,
                    &key,
                    thread_id,
                    chrono::Utc::now().timestamp_millis(),
                )
            })
            .await
    }

    pub async fn clear_search_history(&self) -> Result<()> {
        self.db
            .write(|conn| repo::search_history::clear(conn))
            .await
    }

    /// Embed `text` as a query and return the top-`k` (message_id, score) hits
    /// from the in-memory index. Empty when no local model is loaded. Query
    /// embeddings are cached, so repeated or backspaced-over queries skip the
    /// model forward pass entirely. `account_id` scopes the hits to one
    /// account; `None` searches the whole index.
    async fn vector_hits(
        &self,
        text: &str,
        k: usize,
        account_id: Option<i64>,
    ) -> Result<Vec<(i64, f32)>> {
        let Some(embedder) = self.embed.embedder().await else {
            return Ok(Vec::new());
        };
        let qv = match self.embed.cached_query(text).await {
            Some(v) => v,
            None => {
                let t = text.to_string();
                let v = tokio::task::spawn_blocking(move || embedder.embed_query(&t))
                    .await
                    .map_err(|e| CoreError::Other(format!("embed query join: {e}")))??;
                self.embed.cache_query(text.to_string(), v.clone()).await;
                v
            }
        };
        let Some(account) = account_id else {
            let idx = self.embed.index.read().await;
            return Ok(idx.search(&qv, k));
        };
        // The index is global (no per-account partition): when scoped, widen
        // the candidate pool adaptively — an account holding only a small
        // share of the index may need many more candidates before k of its
        // own hits surface. The pool grows up to SCOPE_WIDEN_ROUNDS times
        // until k in-account hits are found or the index is exhausted. If the
        // index is extremely skewed this can still return fewer than k hits;
        // keyword retrieval then remains the account's coverage.
        const SCOPE_WIDEN_ROUNDS: usize = 3;
        let mut pool = k.saturating_mul(8).clamp(k, 2_000);
        let mut scoped = Vec::new();
        for _ in 0..=SCOPE_WIDEN_ROUNDS {
            let (hits, idx_len) = {
                let idx = self.embed.index.read().await;
                (idx.search(&qv, pool.min(idx.len())), idx.len())
            };
            scoped = self.scope_hits_to_account(hits, account).await?;
            if scoped.len() >= k || pool >= idx_len {
                break;
            }
            pool = pool.saturating_mul(4).min(idx_len);
        }
        Ok(scoped.into_iter().take(k).collect())
    }

    /// Keep only vector hits whose message lives in `account` (score order
    /// preserved). The in-memory index stores message ids only, so account
    /// scoping is a DB lookup; the ids are from our own index and safe to
    /// inline like `repo::search`'s candidate queries do.
    async fn scope_hits_to_account(
        &self,
        hits: Vec<(i64, f32)>,
        account_id: i64,
    ) -> Result<Vec<(i64, f32)>> {
        if hits.is_empty() {
            return Ok(hits);
        }
        let ids: Vec<i64> = hits.iter().map(|(id, _)| *id).collect();
        let keep: HashSet<i64> = self
            .db
            .read(move |conn| {
                let id_list = ids
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let mut stmt = conn.prepare(&format!(
                    "SELECT id FROM visible_messages WHERE account_id = ?1 AND id IN ({id_list})"
                ))?;
                let set = stmt
                    .query_map(rusqlite::params![account_id], |r| r.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<HashSet<i64>>>()?;
                Ok::<_, CoreError>(set)
            })
            .await?;
        Ok(hits
            .into_iter()
            .filter(|(id, _)| keep.contains(id))
            .collect())
    }

    /// Pre-compute and cache the query embedding for `query` while the user is
    /// still typing, so the search that fires when they pause skips the model
    /// forward pass. Best-effort: no-ops when the model isn't loaded, the
    /// query is too short for the semantic branch, or it's already cached.
    pub async fn warm_query_embedding(&self, query: String) {
        let parsed = search::parse(&query);
        if parsed.text.chars().count() < 3 {
            return;
        }
        let Some(embedder) = self.embed.embedder().await else {
            return;
        };
        if self.embed.cached_query(&parsed.text).await.is_some() {
            return;
        }
        let t = parsed.text.clone();
        if let Ok(Ok(v)) = tokio::task::spawn_blocking(move || embedder.embed_query(&t)).await {
            self.embed.cache_query(parsed.text, v).await;
        }
    }

    // ---------- semantic index / RAG ----------

    pub async fn embedding_status(&self) -> Result<EmbeddingStatus> {
        let settings = self.db.read(|conn| repo::settings::get(conn)).await?;
        let enabled = settings.embedding_backend == "local";
        let model = settings.embedding_model.clone();
        let model_id = embed::spec_or_default(&model).key.to_string();
        let m = model_id.clone();
        let (total, embedded, pending) = self
            .db
            .read(move |conn| repo::embeddings::counts(conn, &m))
            .await?;
        let ready = self.embed.embedder().await.is_some()
            && *self.embed.active_model.read().await == model_id;
        Ok(EmbeddingStatus {
            enabled,
            model: model_id,
            total,
            embedded,
            pending,
            ready,
        })
    }

    /// Requeue the whole mailbox for (re-)embedding. The worker drains it.
    pub async fn semantic_reindex(&self) -> Result<i64> {
        let n = self
            .db
            .write(|conn| repo::embeddings::mark_all_pending(conn))
            .await?;
        Ok(n as i64)
    }

    /// RAG: answer a natural-language question grounded in the most relevant
    /// messages, returning the answer plus its source citations.
    /// Answer a question about the mailbox. Seeds with a semantic-search RAG
    /// pass, then hands the model `search_inbox` / `read_email` tools so it can
    /// reformulate queries and read whole threads before answering. Every round
    /// streams. Falls back to a plain
    /// one-shot RAG answer if the model/endpoint doesn't support tool calling.
    /// `account_id` scopes retrieval to one account (the sidebar filter);
    /// `None` searches every account.
    pub async fn ai_ask(
        &self,
        question: String,
        request_id: String,
        account_id: Option<i64>,
    ) -> Result<AskResult> {
        const MAX_ROUNDS: usize = 6;
        let cfg = self.ai_config(Scenario::Ask).await?;

        // The on-device model has a small context window and no tool calling:
        // it answers in one pass over fewer seed sources.
        let on_device = ai::apple::is_apple(&cfg.base_url);

        // RAG seed: the model always starts from the best hybrid matches.
        let seed = if on_device { 4 } else { 8 };
        let sources = self.retrieve_search(&question, seed, account_id).await?;
        if sources.is_empty() {
            return Ok(AskResult {
                answer: "I couldn't find anything relevant in your mailbox. \
                         Make sure semantic search is enabled and indexing has finished."
                    .into(),
                citations: Vec::new(),
            });
        }
        // Surface the seed sources immediately; more are emitted as the model searches.
        self.emit_ask_citations(&request_id, &sources);
        // Excerpts of mail whose body hasn't downloaded yet are just the
        // snippet; fetch those so the model reads real text.
        let mut sources = self.ensure_bodies(sources).await;

        let mut initial_context = String::new();
        for (i, m) in sources.iter().enumerate() {
            initial_context.push_str(&ai::format_excerpt(i + 1, m));
        }
        let ask_system = format!("{}{}", ai::AGENTIC_ASK_SYSTEM, ai::language_directive(&cfg));
        let mut messages: Vec<serde_json::Value> = vec![
            serde_json::json!({ "role": "system", "content": ask_system }),
            serde_json::json!({
                "role": "user",
                "content": format!("Emails:\n\n{initial_context}\nQuestion: {question}"),
            }),
        ];
        let tools = ai::ask_tools();

        let reasoning = |text: String| {
            self.bus.emit(CoreEvent::AskReasoning {
                request_id: request_id.clone(),
                delta: text,
            });
        };

        // Agentic loop: let the model search and read until it answers or we
        // hit the round cap. Every round streams, so a direct answer reaches
        // the UI token by token. `answer = Some` means the model produced text.
        let mut answer: Option<String> = None;
        let rounds = if on_device { 0 } else { MAX_ROUNDS };
        for round in 0..rounds {
            let emitted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (bus_a, rid_a, emitted_a) = (self.bus.clone(), request_id.clone(), emitted.clone());
            let (bus_r, rid_r) = (self.bus.clone(), request_id.clone());
            let step = ai::chat_tools_stream(
                &cfg,
                messages.clone(),
                tools.clone(),
                move |delta| {
                    emitted_a.store(true, std::sync::atomic::Ordering::Relaxed);
                    bus_a.emit(CoreEvent::AskDelta {
                        request_id: rid_a.clone(),
                        delta: delta.to_string(),
                    });
                },
                move |delta| {
                    bus_r.emit(CoreEvent::AskReasoning {
                        request_id: rid_r.clone(),
                        delta: delta.to_string(),
                    });
                },
            )
            .await;
            let emitted = emitted.load(std::sync::atomic::Ordering::Relaxed);
            match step {
                Ok(ai::ChatStep::Content(text)) => {
                    if !emitted && !text.trim().is_empty() {
                        // Non-streaming fallback answered: emit it in one go.
                        self.bus.emit(CoreEvent::AskDelta {
                            request_id: request_id.clone(),
                            delta: text.clone(),
                        });
                    } else if emitted && text.trim().is_empty() {
                        self.bus.emit(CoreEvent::AskReset {
                            request_id: request_id.clone(),
                        });
                    }
                    answer = Some(text);
                    break;
                }
                Ok(ai::ChatStep::Tools { assistant, calls }) => {
                    if emitted {
                        // That text was a preamble to the tool calls, not the answer.
                        self.bus.emit(CoreEvent::AskReset {
                            request_id: request_id.clone(),
                        });
                    }
                    messages.push(assistant);
                    for call in calls {
                        let (result, added) = match call.name.as_str() {
                            "search_inbox" => {
                                self.run_search_inbox(
                                    &call.arguments,
                                    &mut sources,
                                    account_id,
                                    &reasoning,
                                )
                                .await
                            }
                            "read_email" => (
                                self.run_read_email(
                                    &call.arguments,
                                    &sources,
                                    account_id,
                                    &reasoning,
                                )
                                .await,
                                0,
                            ),
                            other => (format!("Unknown tool: {other}"), 0),
                        };
                        messages.push(serde_json::json!({
                            "role": "tool",
                            "tool_call_id": call.id,
                            "content": result,
                        }));
                        if added > 0 {
                            self.emit_ask_citations(&request_id, &sources);
                        }
                    }
                }
                Err(e) => {
                    // Any tool-round failure (no tool support, a provider hiccup,
                    // a malformed tool reply) shouldn't sink the whole Ask - we
                    // already have grounded sources, so fall through to a plain
                    // streamed answer over them instead of erroring out.
                    tracing::warn!("ai_ask tool round {round} failed, using plain fallback: {e}");
                    if emitted {
                        self.bus.emit(CoreEvent::AskReset {
                            request_id: request_id.clone(),
                        });
                    }
                    break;
                }
            }
        }

        let answer = match answer {
            // The agentic path answered directly (already streamed above).
            // Empty answers fall through to the streamed fallback below rather
            // than settling on a blank result.
            Some(text) if !text.trim().is_empty() => text,
            _ => {
                // Cap reached while still searching, a tool-less model, or a
                // mid-loop failure: force a final streamed answer over everything
                // gathered, tools off. Reasoning is streamed on its own channel.
                messages.push(serde_json::json!({
                    "role": "system",
                    "content": "Now answer the user's question using ONLY the numbered excerpts \
                                and emails above. Cite them like [1]. If the answer isn't there, \
                                say you couldn't find it. Answer in the user's language, \
                                concisely; light Markdown is fine, no preamble.",
                }));
                let (bus_a, rid_a) = (self.bus.clone(), request_id.clone());
                let (bus_r, rid_r) = (self.bus.clone(), request_id.clone());
                let (answer, _reasoning) = ai::chat_stream_json_split(
                    &cfg,
                    messages,
                    move |delta| {
                        bus_a.emit(CoreEvent::AskDelta {
                            request_id: rid_a.clone(),
                            delta: delta.to_string(),
                        });
                    },
                    move |delta| {
                        bus_r.emit(CoreEvent::AskReasoning {
                            request_id: rid_r.clone(),
                            delta: delta.to_string(),
                        });
                    },
                )
                .await?;
                answer
            }
        };
        // Never settle on a blank answer - the model thought but produced no
        // user-facing text.
        let answer = if answer.trim().is_empty() {
            "I couldn't find an answer to that in your mailbox.".to_string()
        } else {
            answer
        };
        self.bus.emit(CoreEvent::AskDone { request_id });

        Ok(AskResult {
            answer,
            citations: Self::ask_citations(&sources),
        })
    }

    /// Operator-aware hybrid retrieval (semantic RAG fused with `from:`/`to:`/
    /// `subject:`/`is:`/`has:` keyword filters) hydrated to message details for
    /// citation. Powers both the Ask RAG seed and the agentic `search_inbox`
    /// tool, so the model can search by meaning, sender, recipient, and more.
    /// `account_id` scopes every branch to one account; `None` searches all.
    async fn retrieve_search(
        &self,
        query: &str,
        k: usize,
        account_id: Option<i64>,
    ) -> Result<Vec<MessageDetail>> {
        let mut parsed = crate::search::parse(query);
        // The account filter is a query operator for the repo layer: it narrows
        // the lexical branch and the semantic hits alike (see
        // `repo::search::message_hits`).
        parsed.account_id = account_id;
        // Semantic branch only carries meaning for queries of a few chars+.
        let vec_hits = if parsed.text.chars().count() >= 3 {
            self.vector_hits(&parsed.text, 200, account_id)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let k = k as i64;
        self.db
            .read(move |conn| {
                let ids = repo::search::message_hits(conn, &parsed, &vec_hits, k)?;
                let mut out = Vec::new();
                for id in ids {
                    if let Ok(d) = repo::messages::detail(conn, id) {
                        out.push(d);
                    }
                }
                Ok::<_, CoreError>(out)
            })
            .await
    }

    /// Execute a `search_inbox` tool call: run the search, append any *new*
    /// messages to `sources` with stable citation numbers, and return the
    /// excerpt block for the model plus how many new sources were added.
    /// `account_id` keeps the tool inside the sidebar's account filter.
    async fn run_search_inbox(
        &self,
        arguments: &str,
        sources: &mut Vec<MessageDetail>,
        account_id: Option<i64>,
        progress: &impl Fn(String),
    ) -> (String, usize) {
        let args: serde_json::Value =
            serde_json::from_str(arguments).unwrap_or_else(|_| serde_json::json!({}));
        let query = args["query"].as_str().unwrap_or("").trim().to_string();
        if query.is_empty() {
            return ("(empty query - nothing searched)".into(), 0);
        }
        if sources.len() >= 24 {
            return (
                "Source limit reached; answer with what you already have.".into(),
                0,
            );
        }
        progress(format!("\nSearching \u{201c}{query}\u{201d}\n"));
        let limit = args["limit"].as_u64().unwrap_or(6).clamp(1, 8) as usize;
        let details = self
            .retrieve_search(&query, limit, account_id)
            .await
            .unwrap_or_default();
        let details: Vec<MessageDetail> = details
            .into_iter()
            .filter(|d| {
                // Retrieval is already account-scoped; the explicit check
                // keeps another account's mail out even if that ever regresses.
                account_id.is_none_or(|a| d.account_id == a)
                    && !sources.iter().any(|s| s.id == d.id)
            })
            .collect();
        let details = self.ensure_bodies(details).await;

        let mut block = String::new();
        let mut added = 0;
        for d in details {
            if sources.iter().any(|s| s.id == d.id) {
                continue; // already cited under an earlier number
            }
            block.push_str(&ai::format_excerpt(sources.len() + 1, &d));
            sources.push(d);
            added += 1;
            if sources.len() >= 24 {
                break;
            }
        }
        let text = if added == 0 {
            format!("No new results for \"{query}\".")
        } else {
            format!("Results for \"{query}\":\n\n{block}")
        };
        (text, added)
    }

    /// Execute a `read_email` tool call: the whole thread behind citation `n`,
    /// with full bodies (fetched now if they haven't downloaded yet).
    /// `account_id` keeps the tool inside the sidebar's account filter.
    async fn run_read_email(
        &self,
        arguments: &str,
        sources: &[MessageDetail],
        account_id: Option<i64>,
        progress: &impl Fn(String),
    ) -> String {
        let args: serde_json::Value =
            serde_json::from_str(arguments).unwrap_or_else(|_| serde_json::json!({}));
        let n = args["n"]
            .as_u64()
            .or_else(|| {
                args["n"]
                    .as_str()
                    .and_then(|s| s.trim_matches(['[', ']']).parse().ok())
            })
            .unwrap_or(0) as usize;
        let Some(src) = n.checked_sub(1).and_then(|i| sources.get(i)) else {
            return format!("No excerpt [{n}]. Valid numbers are 1-{}.", sources.len());
        };
        // Sources are account-scoped already, but never serve another
        // account's content when a filter is set.
        if account_id.is_some_and(|a| src.account_id != a) {
            return format!("Excerpt [{n}] is outside the selected account.");
        }
        progress(format!("\nReading \u{201c}{}\u{201d}\n", src.subject));
        let thread_id = src.thread_id;
        let mut messages = match self
            .db
            .read(move |conn| repo::messages::list_for_thread(conn, thread_id))
            .await
        {
            Ok(m) if !m.is_empty() => m,
            _ => vec![src.clone()],
        };
        if let Some(a) = account_id {
            messages.retain(|m| m.account_id == a);
            if messages.is_empty() {
                messages = vec![src.clone()];
            }
        }
        let messages = self.ensure_bodies(messages).await;
        format!(
            "Full conversation for [{n}] (Subject: {}):\n\n{}",
            src.subject,
            ai::thread_context(&messages, 16_000)
        )
    }

    /// Make sure `msgs` carry their bodies: request any not yet downloaded and
    /// wait briefly for them, so the model reads real text instead of a
    /// one-line snippet. Returns whatever is available when the wait ends.
    async fn ensure_bodies(&self, msgs: Vec<MessageDetail>) -> Vec<MessageDetail> {
        let missing = |m: &MessageDetail| {
            m.text_body.as_deref().map_or(true, |b| b.trim().is_empty())
                && (m.body_state == "none" || m.body_state == "fetching")
        };
        let pending: Vec<(i64, i64)> = msgs
            .iter()
            .filter(|m| missing(m))
            .map(|m| (m.account_id, m.id))
            .collect();
        if pending.is_empty() {
            return msgs;
        }
        for &(account_id, id) in &pending {
            self.request_body(account_id, id).await;
        }
        let ids: Vec<i64> = pending.iter().map(|p| p.1).collect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
        let mut fresh = loop {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let want = ids.clone();
            let fresh: std::collections::HashMap<i64, MessageDetail> = self
                .db
                .read(move |conn| {
                    Ok::<_, CoreError>(
                        want.iter()
                            .filter_map(|&id| repo::messages::detail(conn, id).ok())
                            .map(|d| (d.id, d))
                            .collect(),
                    )
                })
                .await
                .unwrap_or_default();
            let done = ids
                .iter()
                .all(|id| fresh.get(id).map_or(true, |d| !missing(d)));
            if done || std::time::Instant::now() >= deadline {
                break fresh;
            }
        };
        msgs.into_iter()
            .map(|m| match fresh.remove(&m.id) {
                Some(d) if !missing(&d) => d,
                _ => m,
            })
            .collect()
    }

    fn emit_ask_citations(&self, request_id: &str, sources: &[MessageDetail]) {
        self.bus.emit(CoreEvent::AskCitations {
            request_id: request_id.to_string(),
            citations: Self::ask_citations(sources),
        });
    }

    fn ask_citations(sources: &[MessageDetail]) -> Vec<AskCitation> {
        sources
            .iter()
            .map(|d| AskCitation {
                message_id: d.id,
                thread_id: d.thread_id,
                subject: d.subject.clone(),
                from: d.from.name.clone().unwrap_or_else(|| d.from.email.clone()),
                date: d.date,
                snippet: d.snippet.clone(),
            })
            .collect()
    }

    // ---------- snippets / splits / settings ----------

    pub async fn list_snippets(&self) -> Result<Vec<Snippet>> {
        self.db.read(|conn| repo::snippets::list(conn)).await
    }

    pub async fn save_snippet(
        &self,
        id: Option<i64>,
        name: String,
        shortcut: Option<String>,
        subject: Option<String>,
        body_text: String,
    ) -> Result<Snippet> {
        self.db
            .write(move |conn| {
                repo::snippets::save(
                    conn,
                    id,
                    &name,
                    shortcut.as_deref(),
                    subject.as_deref(),
                    &body_text,
                )
            })
            .await
    }

    pub async fn delete_snippet(&self, id: i64) -> Result<()> {
        self.db
            .write(move |conn| repo::snippets::delete(conn, id))
            .await
    }

    pub async fn use_snippet(&self, id: i64) -> Result<()> {
        self.db
            .write(move |conn| repo::snippets::bump_usage(conn, id))
            .await
    }

    pub async fn list_splits(&self) -> Result<Vec<SplitRule>> {
        self.db.read(|conn| repo::splits::list(conn)).await
    }

    /// First split rule (in position order) that matches a thread, if any.
    /// `threads.routed_tab` can't answer this for rules with a `target` (they
    /// write the target's route key, not `split:<id>`), so re-run the matcher.
    pub async fn find_matching_split(&self, thread_id: i64) -> Result<Option<SplitRule>> {
        self.db
            .read(move |conn| {
                let rules = repo::splits::list(conn)?;
                let decision = route::decide(&route::RuleSubject::load(conn, thread_id)?, &rules);
                Ok(decision
                    .matched_split
                    .and_then(|id| rules.into_iter().find(|r| r.id == id)))
            })
            .await
    }

    /// Why a thread is in its tab: the stored route plus a trace of every split
    /// rule tried. `current` can differ from the rules' verdict when the AI
    /// classifier or the heuristic routed the thread.
    pub async fn explain_route(&self, thread_id: i64) -> Result<route::RouteExplanation> {
        self.db
            .read(move |conn| {
                let current: Option<String> = conn
                    .query_row(
                        "SELECT routed_tab FROM threads WHERE id = ?1",
                        rusqlite::params![thread_id],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten();
                let rules = repo::splits::list(conn)?;
                let decision = route::explain(&route::RuleSubject::load(conn, thread_id)?, &rules);
                Ok(route::RouteExplanation { current, decision })
            })
            .await
    }

    /// Dry-run a draft condition against recent mail for the rule editor.
    pub async fn preview_split_condition(
        &self,
        condition: RuleCondition,
        limit: usize,
    ) -> Result<route::decide::ConditionPreview> {
        self.db
            .read(move |conn| route::decide::preview(conn, &condition, 2000, limit.min(50)))
            .await
    }

    pub async fn save_split(
        &self,
        id: Option<i64>,
        name: String,
        position: i64,
        query: SplitRuleQuery,
        condition: Option<RuleCondition>,
        target: Option<RouteKey>,
        ai: Option<AiCheck>,
        count_all: bool,
        apply_existing: bool,
    ) -> Result<SplitRule> {
        let saved = self
            .db
            .write(move |conn| {
                if let Some(cond) = &condition {
                    let user_labels: Vec<i64> = repo::labels::list(conn)?
                        .into_iter()
                        .filter(|l| !l.is_auto)
                        .map(|l| l.id)
                        .collect();
                    let errs = cond.validate(&user_labels);
                    if !errs.is_empty() {
                        let msg = errs.iter().map(|e| e.to_string()).collect::<Vec<_>>();
                        return Err(CoreError::Other(format!(
                            "invalid rule condition: {}",
                            msg.join("; ")
                        )));
                    }
                }
                route::reroute::validate_target(conn, id, target)?;
                let before = repo::splits::list(conn)?;
                let saved = repo::splits::save(
                    conn,
                    id,
                    &name,
                    position,
                    &query,
                    condition.as_ref(),
                    target,
                    ai.as_ref(),
                    count_all,
                )?;
                Ok((saved, before))
            })
            .await?;
        let (saved, before) = saved;
        self.apply_rule_change(before, apply_existing).await?;
        Ok(saved)
    }

    /// Delete a split. Threads in its tab always fall back to the AI,
    /// heuristic or Important/Other (they'd be invisible otherwise); with
    /// `apply_existing`, other inbox threads it out-prioritized are re-sorted
    /// too.
    pub async fn delete_split(&self, id: i64, apply_existing: bool) -> Result<()> {
        let before = self
            .db
            .write(move |conn| {
                let tx = conn.transaction()?;
                let before = repo::splits::list(&tx)?;
                route::reroute::detach_targets_to(&tx, id)?;
                repo::splits::delete(&tx, id)?;
                tx.commit()?;
                Ok(before)
            })
            .await?;
        self.apply_rule_change(before, apply_existing).await?;
        Ok(())
    }

    /// What a pending rule edit, delete or reorder would do to existing inbox
    /// mail, so the UI can ask "move N threads?" before saving. Read-only.
    pub async fn preview_rule_change(
        &self,
        change: route::reroute::RuleChange,
    ) -> Result<route::reroute::RuleChangeImpact> {
        self.db
            .read(move |conn| {
                let before = repo::splits::list(conn)?;
                let after = change.apply_to(&before);
                route::reroute::impact(conn, &before, &after, 5)
            })
            .await
    }

    /// Bring stored routing in line with a rule change from `before` to the
    /// current rules. Threads left in a tab that no longer exists are always
    /// re-routed; with `apply_existing`, every inbox thread whose rule outcome
    /// changed moves too (chunked, so sync can interleave). Never touches AI or
    /// heuristic decisions the change doesn't affect. Returns threads moved.
    async fn apply_rule_change(
        &self,
        before: Vec<SplitRule>,
        apply_existing: bool,
    ) -> Result<usize> {
        let (after, fallback) = self
            .db
            .read(|conn| {
                let s = repo::settings::get(conn)?;
                Ok((
                    repo::splits::list(conn)?,
                    route::Fallback::from_settings(s.auto_labels_enabled, s.ai_categorize),
                ))
            })
            .await?;
        let mut moved = 0;
        if apply_existing {
            let ids = self
                .db
                .read(|conn| route::reroute::inbox_thread_ids(conn))
                .await?;
            for chunk in ids.chunks(route::reroute::CHUNK) {
                let (chunk, b, a) = (chunk.to_vec(), before.clone(), after.clone());
                moved += self
                    .db
                    .write(move |conn| {
                        let tx = conn.transaction()?;
                        let n = route::reroute::apply_diff(&tx, &b, &a, fallback, &chunk)?;
                        tx.commit()?;
                        Ok(n)
                    })
                    .await?;
            }
        }
        moved += self
            .db
            .write(move |conn| {
                let tx = conn.transaction()?;
                let orphans = route::reroute::orphaned_thread_ids(&tx)?;
                for &id in &orphans {
                    route::route_thread_deterministic(&tx, &after, fallback, id)?;
                }
                tx.commit()?;
                Ok(orphans.len())
            })
            .await?;
        // Also wakes the background AI router for any thread now 'pending'.
        self.bus.emit(CoreEvent::MailUpdated { thread_ids: vec![] });
        Ok(moved)
    }

    /// Persist a single shared tab order across custom splits and auto-label
    /// tabs. `order` lists every reorderable tab top-to-bottom as `(kind, id)`
    /// where `kind` is `"split"` or `"label"`; its index becomes the row's
    /// `position`. Built-in Important/Other are pinned and never included.
    ///
    /// Only re-resolves routing when the splits' relative priority actually
    /// changed (moving an auto-label around can't affect first-match-wins), so a
    /// pure label move stays cheap.
    pub async fn reorder_tabs(
        &self,
        order: Vec<(String, i64)>,
        apply_existing: bool,
    ) -> Result<()> {
        let before = self
            .db
            .write(move |conn| {
                let tx = conn.transaction()?;
                let split_ids = |tx: &rusqlite::Transaction| -> rusqlite::Result<Vec<i64>> {
                    tx.prepare("SELECT id FROM split_rules ORDER BY position, id")?
                        .query_map([], |r| r.get(0))?
                        .collect()
                };
                let before_rules = repo::splits::list(&tx)?;
                let before = split_ids(&tx)?;
                for (i, (kind, id)) in order.iter().enumerate() {
                    let pos = i as i64;
                    match kind.as_str() {
                        "split" => tx.execute(
                            "UPDATE split_rules SET position = ?2 WHERE id = ?1",
                            rusqlite::params![id, pos],
                        )?,
                        "label" => tx.execute(
                            "UPDATE labels SET position = ?2 WHERE id = ?1",
                            rusqlite::params![id, pos],
                        )?,
                        _ => 0,
                    };
                }
                let after = split_ids(&tx)?;
                tx.commit()?;
                Ok((before != after).then_some(before_rules))
            })
            .await?;
        if let Some(before) = before {
            self.apply_rule_change(before, apply_existing).await?;
        } else {
            self.bus.emit(CoreEvent::MailUpdated { thread_ids: vec![] });
        }
        Ok(())
    }

    pub async fn list_labels(&self) -> Result<Vec<Label>> {
        self.db.read(|conn| repo::labels::list(conn)).await
    }

    pub async fn save_label(
        &self,
        id: Option<i64>,
        name: String,
        color: String,
        position: i64,
    ) -> Result<Label> {
        self.db
            .write(move |conn| repo::labels::save(conn, id, &name, &color, position))
            .await
    }

    pub async fn delete_label(&self, id: i64) -> Result<()> {
        self.db
            .write(move |conn| {
                let was_category = repo::labels::get(conn, id)?.is_some_and(|l| l.is_auto);
                repo::labels::delete(conn, id)?;
                // Cached verdicts may name the deleted category.
                if was_category {
                    route::clear_cache(conn)?;
                }
                Ok(())
            })
            .await
    }

    /// Add a custom AI category: an auto label the classifier can pick, with
    /// optional guidance for the model. Cached verdicts are dropped so senders
    /// are re-judged against the new list.
    pub async fn create_category(
        &self,
        name: String,
        color: String,
        description: String,
    ) -> Result<Label> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(CoreError::Other("category name is empty".into()));
        }
        let label = self
            .db
            .write(move |conn| {
                let label = repo::labels::create_auto(conn, &name, &color)?;
                if !description.trim().is_empty() {
                    let mut settings = repo::settings::get(conn)?;
                    settings
                        .ai_category_descriptions
                        .insert(label.keyword.clone(), description.trim().to_string());
                    repo::settings::set(conn, &settings)?;
                }
                route::clear_cache(conn)?;
                Ok(label)
            })
            .await?;
        Ok(label)
    }

    pub async fn restore_auto_labels(&self) -> Result<i64> {
        let restored = self
            .db
            .write(|conn| repo::labels::restore_auto_defaults(conn))
            .await?;
        if restored > 0 {
            self.reroute_all_sync().await?;
        }
        Ok(restored)
    }

    /// Re-sort every inbox thread (rules, categories, AI queue) without running
    /// the automation rules. Behind "Re-run auto labels" in the split inbox
    /// settings and the palette, where archiving or trashing mail, or one AI
    /// request per conversation, would come as a surprise.
    pub async fn relabel_auto(&self) -> Result<i64> {
        self.resort(false).await
    }

    /// Re-resolve every inbox thread's tab from scratch, run the automation
    /// rules over the inbox, and drain the AI queue, so the caller sees the
    /// final state. Behind "Run automations", which asks first when a rule
    /// would archive, trash or call the AI.
    pub async fn reroute_all(&self) -> Result<i64> {
        self.resort(true).await
    }

    /// [`Core::reroute_all`]. Without `automations` the automation rules don't
    /// run, as for [`Core::relabel_auto`] and the one-shot startup backfill,
    /// which must never archive or relabel old mail on its own.
    async fn resort(&self, automations: bool) -> Result<i64> {
        let n = self.reroute_all_sync().await?;
        // Automations before the AI categories, as for new mail (see
        // ai_router_loop), so a rule's route_to wins over the category.
        if automations && let Err(e) = self.run_automations_on_inbox().await {
            tracing::warn!("automations on existing mail failed: {e}");
        }
        // Drain the AI queue now so the caller sees the final state. A failing
        // model leaves the rest 'pending' for the background router.
        while let Ok(done) = self.classify_pending(200).await {
            if done == 0 {
                break;
            }
        }
        Ok(n)
    }

    /// Deterministic re-route of every inbox thread (rules, then the heuristic
    /// or the AI queue), in chunks so sync can interleave. Clears the AI
    /// sender cache so an edited category prompt re-evaluates. Local AI
    /// annotations are kept, and the automation rules don't run here (see
    /// [`Core::reroute_all`]).
    async fn reroute_all_sync(&self) -> Result<i64> {
        let (ids, splits, fallback) = self
            .db
            .write(|conn| {
                // Keep the one-shot backfill marker; drop real sender decisions.
                conn.execute(
                    "DELETE FROM route_cache WHERE sender_domain <> '__routing_backfill__'",
                    [],
                )?;
                let s = repo::settings::get(conn)?;
                Ok((
                    route::reroute::inbox_thread_ids(conn)?,
                    repo::splits::list(conn)?,
                    route::Fallback::from_settings(s.auto_labels_enabled, s.ai_categorize),
                ))
            })
            .await?;
        let mut n = 0i64;
        for chunk in ids.chunks(route::reroute::CHUNK) {
            let (chunk, splits) = (chunk.to_vec(), splits.clone());
            n += self
                .db
                .write(move |conn| {
                    let tx = conn.transaction()?;
                    for &id in &chunk {
                        route::route_thread_deterministic(&tx, &splits, fallback, id)?;
                    }
                    tx.commit()?;
                    Ok(chunk.len() as i64)
                })
                .await?;
        }
        n += self
            .db
            .write(move |conn| {
                let tx = conn.transaction()?;
                let orphans = route::reroute::orphaned_thread_ids(&tx)?;
                for &id in &orphans {
                    route::route_thread_deterministic(&tx, &splits, fallback, id)?;
                }
                tx.commit()?;
                Ok(orphans.len() as i64)
            })
            .await?;
        // Routing changed across many threads; a blanket refresh is fine here.
        // The emit also wakes the background AI router to handle any 'pending'.
        self.bus.emit(CoreEvent::MailUpdated { thread_ids: vec![] });
        Ok(n)
    }

    /// Resolve up to `limit` threads waiting as `pending`: first the AI
    /// checks of split rules (in rule order), then the category. Each AI step
    /// tries the decision models, then the chat model; with no AI configured
    /// at all, checks count as "no" and categories use the built-in heuristic,
    /// so nothing stays pending for want of an API key. A configured AI that
    /// fails leaves the thread pending for a later retry.
    pub async fn classify_pending(&self, limit: i64) -> Result<i64> {
        let _guard = self.ai_router_lock.lock().await;
        let settings = self.db.read(|conn| repo::settings::get(conn)).await?;
        let fallback =
            route::Fallback::from_settings(settings.auto_labels_enabled, settings.ai_categorize);
        let descriptions = settings.ai_category_descriptions.clone();

        // (thread id, facts if it has inbound mail, rule facts)
        let (jobs, cache, splits, catalog) = self
            .db
            .read(move |conn| {
                let ids: Vec<i64> = conn
                    .prepare(
                        "SELECT id FROM threads WHERE routed_tab = 'pending'
                         ORDER BY last_message_at DESC LIMIT ?1",
                    )?
                    .query_map(rusqlite::params![limit], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                let mut jobs = Vec::new();
                for id in ids {
                    jobs.push((
                        id,
                        route::thread_facts(conn, id)?,
                        route::RuleSubject::load(conn, id)?,
                    ));
                }
                Ok((
                    jobs,
                    route::load_cache(conn)?,
                    repo::splits::list(conn)?,
                    route::category_catalog(conn, &descriptions)?,
                ))
            })
            .await?;
        if jobs.is_empty() {
            return Ok(0);
        }

        let split_ai = if splits.iter().any(|s| s.ai.is_some()) {
            self.deciders(&settings, settings.decision_use_splits).await
        } else {
            Deciders {
                decision: Vec::new(),
                chat: None,
                min_confidence: 0.0,
            }
        };
        let cat_ai = if fallback == route::Fallback::Ai {
            self.deciders(&settings, settings.decision_use_categories)
                .await
        } else {
            Deciders {
                decision: Vec::new(),
                chat: None,
                min_confidence: 0.0,
            }
        };

        enum Verdict {
            /// A split (or other route key) claimed the thread.
            Route(String),
            /// AI category keyword, `None` = no category.
            Category(Option<String>),
            /// No AI: built-in header heuristic.
            Heuristic(route::ThreadFacts),
            Unrouted,
        }
        let mut resolved: Vec<(i64, Verdict)> = Vec::new();
        let mut decided: HashMap<String, Option<String>> = HashMap::new();
        let mut cache_writes: Vec<(String, String)> = Vec::new();
        let mut failures = 0usize;

        for (tid, facts, subject) in jobs {
            // 1. Split rules, with their AI checks answered.
            let candidates = route::decide::ai_candidates(&subject, &splits);
            let mut yes: HashSet<i64> = HashSet::new();
            if !candidates.is_empty() {
                if let Some(facts) = &facts {
                    let checks: Vec<(String, String, f64)> = candidates
                        .iter()
                        .filter_map(|sp| {
                            let ai = sp.ai.as_ref()?;
                            Some((
                                format!("split_{}", sp.id),
                                ai.instruction.clone(),
                                ai.min_confidence.unwrap_or(split_ai.min_confidence),
                            ))
                        })
                        .collect();
                    match split_ai.checks(facts, &checks).await {
                        Ok(ids) => {
                            yes = candidates
                                .iter()
                                .filter(|sp| ids.contains(&format!("split_{}", sp.id)))
                                .map(|sp| sp.id)
                                .collect();
                        }
                        Err(e) => {
                            failures += 1;
                            tracing::warn!("split ai checks failed for thread {tid}: {e}");
                            continue;
                        }
                    }
                }
            }
            if let Some(key) = route::decide::decide_with_answers(&subject, &splits, &yes).route {
                resolved.push((tid, Verdict::Route(key.to_string())));
                continue;
            }

            // 2. Category.
            let Some(facts) = facts else {
                resolved.push((tid, Verdict::Unrouted));
                continue;
            };
            match fallback {
                route::Fallback::Off => resolved.push((tid, Verdict::Unrouted)),
                route::Fallback::Heuristic => resolved.push((tid, Verdict::Heuristic(facts))),
                route::Fallback::Ai if !cat_ai.any() => {
                    resolved.push((tid, Verdict::Heuristic(facts)))
                }
                route::Fallback::Ai => {
                    let domain = route::sender_domain(&facts.from_addr);
                    let kw = if let Some(hit) = cache.get(&domain) {
                        // Cache stores the category keyword, "" = no category.
                        (!hit.is_empty()).then(|| hit.clone())
                    } else if let Some(d) = decided.get(&domain) {
                        d.clone()
                    } else {
                        match cat_ai
                            .category(&facts, &settings.ai_category_prompt, &catalog)
                            .await
                        {
                            Ok(kw) => {
                                decided.insert(domain.clone(), kw.clone());
                                cache_writes.push((domain.clone(), kw.clone().unwrap_or_default()));
                                kw
                            }
                            // Transient failure: leave this thread 'pending' so it
                            // retries, and don't poison the cache for the sender.
                            Err(e) => {
                                failures += 1;
                                tracing::warn!("ai categorize failed for thread {tid}: {e}");
                                continue;
                            }
                        }
                    };
                    resolved.push((tid, Verdict::Category(kw)));
                }
            }
        }

        if resolved.is_empty() && failures > 0 {
            // Every model call failed (offline, quota, bad key). Report it so
            // the router backs off instead of retrying in a tight loop; the
            // threads stay 'pending' and keep their Important/Other fallback.
            return Err(CoreError::Other(format!(
                "ai routing: all {failures} classification call(s) failed"
            )));
        }

        let count = self
            .db
            .write(move |conn| {
                use rusqlite::OptionalExtension;
                for (domain, key) in &cache_writes {
                    route::cache_put(conn, domain, key)?;
                }
                let mut count = 0i64;
                for (tid, verdict) in &resolved {
                    let key = match verdict {
                        Verdict::Route(k) => Some(k.clone()),
                        Verdict::Category(Some(kw)) => conn
                            .query_row(
                                "SELECT id FROM labels WHERE keyword = ?1 AND is_auto = 1",
                                rusqlite::params![kw],
                                |r| r.get::<_, i64>(0),
                            )
                            .optional()?
                            .map(|id| format!("label:{id}")),
                        Verdict::Category(None) | Verdict::Unrouted => None,
                        Verdict::Heuristic(facts) => route::heuristic_key(conn, facts)?,
                    };
                    // Sync or a rule edit routed the thread while the model was
                    // thinking: that newer decision wins.
                    if route::apply_ai_tab(conn, *tid, key.as_deref())? {
                        count += 1;
                    }
                }
                Ok(count)
            })
            .await?;
        if count > 0 {
            self.bus.emit(CoreEvent::MailUpdated { thread_ids: vec![] });
        }
        Ok(count)
    }

    /// Run the user's automation rules on newly received mail, once per
    /// message. A rule matches when its condition (the rule decision API) holds
    /// and, if it has an AI instruction, the decision model (or the chat
    /// classifier as fallback) says yes. Only the rule's own action allow-list
    /// runs. Returns the number of threads processed.
    pub async fn run_automations(&self, limit: i64) -> Result<i64> {
        self.run_automations_on(AutomationScope::New(limit)).await
    }

    /// Run the automation rules over every conversation already in the inbox,
    /// whatever its age and whether they ran on it before: the explicit "Run
    /// automations" action, so a rule also files the mail that arrived before
    /// it was made. In chunks, so sync and the background router interleave.
    async fn run_automations_on_inbox(&self) -> Result<i64> {
        let ids = self
            .db
            .read(|conn| route::reroute::inbox_thread_ids(conn))
            .await?;
        let mut processed = 0;
        for chunk in ids.chunks(50) {
            match self
                .run_automations_on(AutomationScope::Threads(chunk.to_vec()))
                .await
            {
                Ok(n) => processed += n,
                // Every AI check in this chunk failed; the next chunk may
                // still have rules that need no model.
                Err(e) => tracing::warn!("automations on existing mail: {e}"),
            }
        }
        Ok(processed)
    }

    async fn run_automations_on(&self, scope: AutomationScope) -> Result<i64> {
        /// Mail older than this is never automated, so a fresh account's
        /// backfill or a long outage can't archive history.
        const MAX_AGE_MS: i64 = 3 * 24 * 60 * 60 * 1000;
        let _guard = self.ai_router_lock.lock().await;
        let settings = self.db.read(|conn| repo::settings::get(conn)).await?;
        let rules: Vec<AiAutomationRule> = settings
            .ai_automation_rules
            .iter()
            .filter(|rule| {
                rule.enabled
                    && !rule.actions.is_empty()
                    && (rule.condition.is_some() || !rule.instruction.trim().is_empty())
            })
            .cloned()
            .collect();
        let cutoff = now_ms() - MAX_AGE_MS;
        let no_rules = rules.is_empty();
        if no_rules && matches!(scope, AutomationScope::Threads(_)) {
            return Ok(0);
        }

        // (thread id, newest inbound message id, rule facts, AI facts)
        let jobs = self
            .db
            .write(move |conn| {
                // Mail nothing will ever automate is settled right away, so
                // creating a rule later doesn't sweep up a backlog.
                if no_rules {
                    conn.execute(
                        "UPDATE messages SET automations_applied = 1 WHERE automations_applied = 0",
                        [],
                    )?;
                    return Ok(Vec::new());
                }
                let rows = match &scope {
                    AutomationScope::New(limit) => {
                        conn.execute(
                            "UPDATE messages SET automations_applied = 1
                             WHERE automations_applied = 0
                               AND (date < ?1 OR is_outgoing = 1 OR is_draft = 1)",
                            rusqlite::params![cutoff],
                        )?;
                        let mut stmt = conn.prepare(
                            "SELECT thread_id, MAX(id) FROM messages
                             WHERE automations_applied = 0 AND is_outgoing = 0 AND is_draft = 0
                             GROUP BY thread_id ORDER BY MAX(date) DESC LIMIT ?1",
                        )?;
                        stmt.query_map(rusqlite::params![limit], |r| {
                            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                    }
                    AutomationScope::Threads(ids) => {
                        let mut rows = Vec::new();
                        for &tid in ids {
                            let mid: Option<i64> = conn.query_row(
                                "SELECT MAX(id) FROM messages
                                 WHERE thread_id = ?1 AND is_outgoing = 0 AND is_draft = 0",
                                rusqlite::params![tid],
                                |r| r.get(0),
                            )?;
                            rows.extend(mid.map(|mid| (tid, mid)));
                        }
                        rows
                    }
                };
                let mut out = Vec::new();
                for (tid, mid) in rows {
                    let subject = route::RuleSubject::load(conn, tid)?;
                    let facts = route::thread_facts(conn, tid)?;
                    out.push((tid, mid, subject, facts));
                }
                Ok(out)
            })
            .await?;
        if jobs.is_empty() {
            return Ok(0);
        }

        let needs_ai = rules.iter().any(|r| !r.instruction.trim().is_empty());
        let ai = if needs_ai {
            self.deciders(&settings, settings.decision_use_rules).await
        } else {
            Deciders {
                decision: Vec::new(),
                chat: None,
                min_confidence: 0.0,
            }
        };

        // (thread id, newest message id, actions to run in rule order)
        let mut plans: Vec<(i64, i64, Vec<AiAutomationAction>)> = Vec::new();
        let mut failures = 0usize;
        for (tid, mid, subject, facts) in jobs {
            // Deterministic gate first; only survivors with an AI check cost a
            // model call.
            let gated: Vec<&AiAutomationRule> = rules
                .iter()
                .filter(|r| {
                    r.condition
                        .as_ref()
                        .is_none_or(|c| route::decide::matches(c, &subject))
                })
                .collect();
            let checks: Vec<(String, String, f64)> = gated
                .iter()
                .filter(|r| !r.instruction.trim().is_empty())
                .map(|r| {
                    (
                        r.id.clone(),
                        r.instruction.clone(),
                        r.min_confidence.unwrap_or(ai.min_confidence),
                    )
                })
                .collect();
            let mut yes: HashSet<String> = HashSet::new();
            if let (false, Some(facts)) = (checks.is_empty(), &facts) {
                match ai.checks(facts, &checks).await {
                    Ok(ids) => yes = ids,
                    // A configured model that failed: retry this message on a
                    // later pass rather than silently dropping its AI rules.
                    Err(e) => {
                        failures += 1;
                        tracing::warn!("automation checks failed for thread {tid}: {e}");
                        continue;
                    }
                }
            }
            let ai_yes: HashSet<&str> = yes.iter().map(String::as_str).collect();
            plans.push((tid, mid, actions_for(&gated, &ai_yes)));
        }

        fn actions_for(
            gated: &[&AiAutomationRule],
            ai_yes: &std::collections::HashSet<&str>,
        ) -> Vec<AiAutomationAction> {
            // The user's rule/action order, so compound behavior is deterministic.
            gated
                .iter()
                .filter(|r| r.instruction.trim().is_empty() || ai_yes.contains(r.id.as_str()))
                .flat_map(|r| r.actions.iter().cloned())
                .collect()
        }

        if plans.is_empty() && failures > 0 {
            return Err(CoreError::Other(format!(
                "automations: all {failures} decision call(s) failed"
            )));
        }

        // One write pass: routing and local annotations, then the marker.
        let processed = plans.len() as i64;
        let action_plans = self
            .db
            .write(move |conn| {
                let mut out: Vec<(i64, Vec<AiAutomationAction>)> = Vec::new();
                for (tid, mid, actions) in plans {
                    let mut prefixes = Vec::new();
                    let mut notes = Vec::new();
                    for action in &actions {
                        match action.kind.as_str() {
                            // A thread the user filed into a tab by its label
                            // stays there.
                            "route_to"
                                if valid_automation_route(conn, &action.value)?
                                    && route::tab_override(conn, tid)?.is_none() =>
                            {
                                route::apply_tab(conn, tid, Some(&action.value))?;
                            }
                            "subject_prefix" if !action.value.trim().is_empty() => {
                                prefixes.push(action.value.as_str());
                            }
                            "body_note" if !action.value.trim().is_empty() => {
                                notes.push(action.value.trim());
                            }
                            _ => {}
                        }
                    }
                    if !prefixes.is_empty() || !notes.is_empty() {
                        conn.execute(
                            "UPDATE messages SET local_subject_prefix = ?2, local_body_note = ?3
                             WHERE id = ?1",
                            rusqlite::params![mid, prefixes.concat(), notes.join("\n\n")],
                        )?;
                    }
                    // Older unhandled messages in the thread are settled too:
                    // rules judge the conversation as of its newest message.
                    conn.execute(
                        "UPDATE messages SET automations_applied = 1
                         WHERE thread_id = ?1 AND id <= ?2 AND automations_applied = 0",
                        rusqlite::params![tid, mid],
                    )?;
                    if !actions.is_empty() {
                        out.push((tid, actions));
                    }
                }
                Ok(out)
            })
            .await?;

        // Threads that just gained a label may now satisfy a label-based split
        // rule, so re-check their split routing once the labels are written.
        let relabeled: Vec<i64> = action_plans
            .iter()
            .filter(|(_, actions)| actions.iter().any(|a| a.kind == "add_label"))
            .map(|(tid, _)| *tid)
            .collect();
        let changed = !action_plans.is_empty();

        // Mailbox mutations reuse the normal optimistic + queued action path,
        // so IMAP state, retries, and UI refreshes behave exactly like a click.
        for (thread_id, actions) in action_plans {
            for action in actions {
                let (kind, params) = match action.kind.as_str() {
                    "mark_read" => (Some(ActionKind::MarkRead), None),
                    "star" => (Some(ActionKind::Star), None),
                    "archive" => (Some(ActionKind::Archive), None),
                    "trash" => (Some(ActionKind::Trash), None),
                    "add_label" | "remove_label" => {
                        let Some(label_id) = action.value.parse::<i64>().ok() else {
                            continue;
                        };
                        let kind = if action.kind == "add_label" {
                            ActionKind::AddLabel
                        } else {
                            ActionKind::RemoveLabel
                        };
                        (
                            Some(kind),
                            Some(ActionParams {
                                wake_at: None,
                                target_folder_id: None,
                                label_id: Some(label_id),
                            }),
                        )
                    }
                    _ => (None, None),
                };
                let Some(kind) = kind else { continue };
                if let Err(e) = self
                    .perform_action(PerformActionArgs {
                        kind,
                        thread_ids: vec![thread_id],
                        params,
                    })
                    .await
                {
                    tracing::warn!(
                        "automation action {} failed for thread {thread_id}: {e}",
                        action.kind
                    );
                }
            }
        }
        if !relabeled.is_empty() {
            self.db
                .write(move |conn| {
                    let splits = repo::splits::list(conn)?;
                    for tid in relabeled {
                        route::reapply_splits_only(conn, &splits, tid)?;
                    }
                    Ok(())
                })
                .await?;
        }
        if changed {
            self.bus.emit(CoreEvent::MailUpdated { thread_ids: vec![] });
        }
        Ok(processed)
    }

    /// Send one tiny question to every configured decision provider, in chain
    /// order, so Settings can show which are reachable (and how fast).
    pub async fn test_decision_provider(&self) -> Result<Vec<DecisionTestResult>> {
        let settings = self.db.read(|conn| repo::settings::get(conn)).await?;
        let mut out = Vec::new();
        for ep in Self::decision_endpoints(&settings) {
            let Some(cfg) = self.decision_config(&settings, &ep).await else {
                out.push(DecisionTestResult {
                    provider: ep.provider.clone(),
                    model: ep.model.clone(),
                    ok: false,
                    latency_ms: 0,
                    probability: 0.0,
                    error: "missing API key or endpoint".into(),
                });
                continue;
            };
            let started = std::time::Instant::now();
            let result = ai::decisions::decide(
                &cfg,
                "From: billing@example.com\nSubject: Your invoice #1042\n\nAmount due: $40.",
                &[("invoice".into(), route::check_question("It is an invoice"))],
            )
            .await;
            let latency_ms = started.elapsed().as_millis() as i64;
            out.push(match result {
                Ok(answers) => match answers.get("invoice") {
                    Some(ai::decisions::Answer::Predicate { probability }) => DecisionTestResult {
                        provider: cfg.provider,
                        model: cfg.model,
                        ok: true,
                        latency_ms,
                        probability: *probability,
                        error: String::new(),
                    },
                    _ => DecisionTestResult {
                        provider: cfg.provider,
                        model: cfg.model,
                        ok: false,
                        latency_ms,
                        probability: 0.0,
                        error: "no answer for the test question".into(),
                    },
                },
                Err(e) => DecisionTestResult {
                    provider: cfg.provider,
                    model: cfg.model,
                    ok: false,
                    latency_ms,
                    probability: 0.0,
                    error: e.to_string(),
                },
            });
        }
        Ok(out)
    }

    /// Exact unread counts for every split tab and sidebar row in one call.
    pub async fn unread_counts(&self, account_id: Option<i64>) -> Result<UnreadCounts> {
        self.db
            .read(move |conn| {
                let splits = repo::splits::list(conn)?;
                let labels = repo::labels::list(conn)?;
                repo::counts::unread_counts(conn, account_id, &splits, &labels)
            })
            .await
    }

    /// Every conversation each inbox tab holds, read or not (the "all"
    /// tab-count setting).
    pub async fn tab_totals(&self, account_id: Option<i64>) -> Result<TabTotals> {
        self.db
            .read(move |conn| {
                let splits = repo::splits::list(conn)?;
                let labels = repo::labels::list(conn)?;
                repo::counts::tab_totals(conn, account_id, &splits, &labels)
            })
            .await
    }

    /// The newest verification code received in the last `max_age_minutes`.
    pub async fn latest_verification_code(
        &self,
        max_age_minutes: i64,
    ) -> Result<Option<VerificationCode>> {
        let since = now_ms() - max_age_minutes.max(1) * 60_000;
        let recent = self
            .db
            .read(move |conn| repo::messages::recent_received(conn, since, 50))
            .await?;
        Ok(recent.into_iter().find_map(|m| {
            let code = m.verification_code?;
            Some(VerificationCode {
                code,
                message_id: m.id,
                thread_id: m.thread_id,
                sender: m
                    .from
                    .name
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or(m.from.email),
                subject: m.subject,
                received_at: m.date,
            })
        }))
    }

    /// A spoken briefing over the newest unread Important threads (Siri's
    /// "catch me up"). Falls back to a plain sender/subject rundown when no AI
    /// provider is configured or the call fails.
    pub async fn inbox_brief(&self) -> Result<String> {
        let page = self
            .list_threads(View::Inbox, Some(-1), None, None, None, None, 40)
            .await?;
        let unread: Vec<ThreadSummary> = page
            .threads
            .into_iter()
            .filter(|t| t.unread_count > 0)
            .take(6)
            .collect();
        if unread.is_empty() {
            return Ok("You're all caught up - no unread important email.".into());
        }
        let sender = |t: &ThreadSummary| {
            t.participants
                .first()
                .map(|a| {
                    a.name
                        .clone()
                        .filter(|n| !n.trim().is_empty())
                        .unwrap_or(a.email.clone())
                })
                .unwrap_or_default()
        };
        let lines: String = unread
            .iter()
            .map(|t| format!("- {}: {} - {}\n", sender(t), t.subject, t.snippet))
            .collect();
        if let Ok(cfg) = self.ai_config(Scenario::Summarize).await {
            match ai::chat(&cfg, ai::brief_prompt(&lines)).await {
                Ok(text) if !text.trim().is_empty() => return Ok(text.trim().to_string()),
                Ok(_) => {}
                Err(e) => tracing::warn!("inbox brief via ai failed: {e}"),
            }
        }
        let rundown: Vec<String> = unread
            .iter()
            .take(3)
            .map(|t| format!("{} about \"{}\"", sender(t), t.subject))
            .collect();
        Ok(format!(
            "You have {} unread important conversation{}. Latest: {}.",
            unread.len(),
            if unread.len() == 1 { "" } else { "s" },
            rundown.join("; ")
        ))
    }

    /// The verification code in one message, if any (for notifications).
    pub async fn message_verification_code(&self, message_id: i64) -> Result<Option<String>> {
        let detail = self
            .db
            .read(move |conn| repo::messages::detail(conn, message_id))
            .await?;
        Ok(detail.verification_code)
    }

    /// Sender picture (Gravatar, BIMI brand logo, or site icon) as a data URL.
    pub async fn sender_avatar(&self, email: &str) -> Option<String> {
        avatars::resolve(&self.paths.data_dir, email).await
    }

    pub async fn get_settings(&self) -> Result<Settings> {
        self.db.read(|conn| repo::settings::get(conn)).await
    }

    pub async fn set_settings(&self, settings: Settings) -> Result<()> {
        apply_oauth_settings(&settings);
        self.db
            .write(move |conn| {
                // New category guidance invalidates cached sender verdicts.
                let before = repo::settings::get(conn)?;
                if before.ai_category_descriptions != settings.ai_category_descriptions
                    || before.ai_category_prompt != settings.ai_category_prompt
                {
                    route::clear_cache(conn)?;
                }
                repo::settings::set(conn, &settings)
            })
            .await?;
        // Start/stop/move the MCP server if its settings changed.
        if let Err(e) = self.mcp_apply_settings().await {
            tracing::warn!("mcp: apply settings failed: {e}");
        }
        Ok(())
    }

    /// Return notifications that are ready for the native host to dispatch.
    /// Eligibility is decided by sync before enqueueing; this API only exposes
    /// durable delivery state to the host process.
    pub async fn due_notifications(&self, limit: i64) -> Result<Vec<NotificationOutboxItem>> {
        let now = now_ms();
        let limit = limit.clamp(1, 100);
        self.db
            .read(move |conn| repo::notifications::list_due(conn, now, limit))
            .await
    }

    /// Resolve which inbox tab a thread lands in, for notification-scope
    /// filtering. `RoutedTab::Pending` means AI classification is still in
    /// flight and the host should wait before deciding.
    pub async fn notification_thread_tab(&self, thread_id: i64) -> Result<Option<RoutedTab>> {
        self.db
            .read(move |conn| repo::notifications::resolve_tab(conn, thread_id))
            .await
    }

    /// Defer a pending notification's next dispatch without consuming a delivery
    /// attempt, used while waiting for its thread's tab to resolve.
    pub async fn defer_notification_delivery(&self, id: i64, not_before: i64) -> Result<bool> {
        self.db
            .write(move |conn| repo::notifications::defer(conn, id, not_before))
            .await
    }

    /// Atomically claim one due notification. A false result means another
    /// dispatcher or a state transition won the race.
    pub async fn claim_notification_delivery(&self, id: i64) -> Result<bool> {
        let now = now_ms();
        self.db
            .write(move |conn| repo::notifications::try_claim(conn, id, now))
            .await
    }

    pub async fn mark_notification_delivered(&self, id: i64) -> Result<bool> {
        let now = now_ms();
        self.db
            .write(move |conn| repo::notifications::mark_delivered(conn, id, now))
            .await
    }

    pub async fn suppress_notification_delivery(
        &self,
        id: i64,
        reason: impl Into<String>,
    ) -> Result<bool> {
        let now = now_ms();
        let reason = reason.into();
        self.db
            .write(move |conn| repo::notifications::mark_suppressed(conn, id, now, &reason))
            .await
    }

    /// Return a claimed notification to the pending queue after a bounded
    /// delay. The cap prevents a bad caller from making a row disappear for an
    /// unreasonable amount of time.
    pub async fn retry_notification_delivery(
        &self,
        id: i64,
        delay_ms: i64,
        error: impl Into<String>,
    ) -> Result<bool> {
        const MAX_DELAY_MS: i64 = 24 * 60 * 60 * 1_000;
        let retry_at = now_ms().saturating_add(delay_ms.clamp(0, MAX_DELAY_MS));
        let error = error.into();
        self.db
            .write(move |conn| repo::notifications::retry(conn, id, retry_at, &error))
            .await
    }

    /// Recover rows left in `delivering` by a process crash. Native delivery is
    /// necessarily at-least-once because the OS send and SQLite commit cannot
    /// share a transaction.
    pub async fn recover_notification_deliveries(&self) -> Result<usize> {
        let now = now_ms();
        self.db
            .write(move |conn| repo::notifications::recover_delivering(conn, now))
            .await
    }
}

/// Build a (incoming → the user's reply) example from one of their sent
/// messages: the reply is its body, the incoming side is the message it
/// replied to (the prior message in its thread), or a synthetic prompt if it
/// started the thread. Returns None if the sent body is empty.
fn build_example_pair(
    conn: &rusqlite::Connection,
    sent_id: i64,
) -> Result<Option<(String, String)>> {
    let sent = repo::messages::detail(conn, sent_id)?;
    let reply = sent.text_body.clone().unwrap_or_default();
    if reply.trim().is_empty() {
        return Ok(None);
    }
    let msgs = repo::messages::list_for_thread(conn, sent.thread_id)?;
    let mut incoming: Option<&MessageDetail> = None;
    for m in &msgs {
        if m.id == sent_id {
            break;
        }
        incoming = Some(m);
    }
    let incoming_text = match incoming {
        Some(m) => {
            let body = m.text_body.clone().unwrap_or_else(|| m.snippet.clone());
            format!("Subject: {}\nFrom: {}\n{}", m.subject, m.from.email, body)
        }
        None => format!("(Compose a new email. Subject: {})", sent.subject),
    };
    Ok(Some((incoming_text, reply)))
}

/// Locate installer-bundled model files. The host (Tauri app) sets
/// `COMAIL_RESOURCE_DIR` to its resource dir so comail-core stays Tauri-free.
fn bundled_model_dir(key: &str) -> Option<std::path::PathBuf> {
    let base = std::env::var_os("COMAIL_RESOURCE_DIR")?;
    let dir = std::path::PathBuf::from(base).join("models").join(key);
    dir.join("model.safetensors").exists().then_some(dir)
}

async fn copy_model_files(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dst).await?;
    for f in embed::MODEL_FILES {
        tokio::fs::copy(src.join(f), dst.join(f)).await?;
    }
    Ok(())
}

/// Reduce an untrusted filename to a single, benign path component: strip
/// separators/NUL/control chars, leading dots and spaces, and cap the length.
/// A file extension for a MIME type, used to name an on-disk attachment when
/// the message gave it no filename. Without a recognizable extension the OS
/// can't route "Open in app" to the right handler (e.g. a `text/calendar`
/// invite written as a bare `attachment-3` never reaches the calendar app).
fn ext_for_mime(mime: &str) -> Option<&'static str> {
    Some(
        match mime
            .split(';')
            .next()
            .unwrap_or(mime)
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "text/calendar" => "ics",
            "application/pdf" => "pdf",
            "text/plain" => "txt",
            "text/html" => "html",
            "text/csv" => "csv",
            "application/json" => "json",
            "application/zip" => "zip",
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/gif" => "gif",
            "image/webp" => "webp",
            "image/svg+xml" => "svg",
            "message/rfc822" => "eml",
            _ => return None,
        },
    )
}

/// Unicode `Bidi_Control` characters. In a filename they reorder how the name
/// is displayed, e.g. `invoice\u{202E}fdp.app` shows as `invoiceppa.pdf`, so a
/// sender can disguise the real extension.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// An attachment name as shown to the user (attachment chip, preview title,
/// save-as default). Stripping bidi controls here, not only on the cached
/// file, is what defeats the spoof: the user decides to open a file from the
/// name the UI shows.
pub(crate) fn display_filename(name: &str) -> String {
    name.chars().filter(|&c| !is_bidi_control(c)).collect()
}

/// Names Windows maps to devices, with or without an extension (`CON.pdf`,
/// `com1.txt`). Writing to one talks to the device instead of creating a file.
fn is_windows_device_name(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    match (stem.get(..3), stem.get(3..)) {
        (Some("COM" | "LPT"), Some(n)) => {
            matches!(
                n,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        }
        _ => false,
    }
}

fn safe_filename(name: &str) -> String {
    // `:` matters beyond portability: on Windows a name like `C:evil.dll` is
    // drive-relative, and `Path::join` replaces the attachment directory with
    // it, writing the file into the process's working directory. The other
    // characters are ones Windows rejects in file names.
    let cleaned: String = name
        .chars()
        .filter(|&c| !is_bidi_control(c))
        .map(|c| {
            if matches!(
                c,
                '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
            ) || c.is_control()
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(['.', ' ']);
    let base = if trimmed.is_empty() {
        "attachment"
    } else {
        trimmed
    };
    let base: String = base.chars().take(200).collect();
    // Truncation can expose a trailing dot or space, which Windows drops.
    let base = base.trim_end_matches(['.', ' ']);
    if is_windows_device_name(base) {
        format!("_{base}")
    } else {
        base.to_string()
    }
}

/// One file staged into the draft-attachment staging area.
struct StagedAttachment {
    /// Canonicalised absolute path of the staged copy.
    path: String,
    /// True when this call created the copy; false when the source was
    /// already inside the staging root and nothing was written.
    fresh: bool,
}

/// Copy a composer-picked file into the app-managed draft-attachment staging
/// area and return the staged absolute path. A path already inside the staging
/// root (a reloaded draft round-tripping its own staged path) is returned
/// unchanged.
///
/// What this does and does not guarantee: dispatch only ever reads files
/// under the staging root, so a `draft_attachments` row cannot point SMTP at
/// an arbitrary path. But any *readable* path the frontend hands to
/// `save_draft` is still copied into staging and mailed - picking files is a
/// user gesture the renderer is trusted with, so this is not a boundary
/// against a compromised renderer exfiltrating files it can read.
async fn stage_draft_attachment(
    root: &std::path::Path,
    src: &str,
    filename: &str,
) -> Result<StagedAttachment> {
    tokio::fs::create_dir_all(root).await?;
    let root = tokio::fs::canonicalize(root).await?;
    let canon_src = tokio::fs::canonicalize(src)
        .await
        .map_err(|e| CoreError::Other(format!("attachment {filename}: {e}")))?;
    if canon_src.starts_with(&root) {
        // Already staged (e.g. re-saving a draft reloaded from the DB).
        return Ok(StagedAttachment {
            path: canon_src.to_string_lossy().into_owned(),
            fresh: false,
        });
    }
    let sub = root.join(crate::mime::rand_token());
    tokio::fs::create_dir_all(&sub).await?;
    let dst = sub.join(safe_filename(filename));
    tokio::fs::copy(&canon_src, &dst).await?;
    Ok(StagedAttachment {
        path: dst.to_string_lossy().into_owned(),
        fresh: true,
    })
}

/// Rename `dir` to a sibling `<name>.removing-<token>` and return the new
/// path; `None` when it does not exist. A fallback `remove_dir_all` covers
/// exotic rename failures so the caller never leaves a live directory in
/// place that a recycled id could inherit.
async fn tombstone_dir(dir: &std::path::Path, token: &str) -> Option<std::path::PathBuf> {
    let target = dir.parent()?.join(format!(
        "{}.removing-{token}",
        dir.file_name()?.to_string_lossy()
    ));
    match tokio::fs::rename(dir, &target).await {
        Ok(()) => Some(target),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "tombstone rename failed; deleting in place");
            let _ = tokio::fs::remove_dir_all(dir).await;
            None
        }
    }
}

/// Delete leftover `*.removing-*` directories under the mail, attachments and
/// draft-staging roots - the tail of a removal killed between commit and
/// post-commit cleanup.
async fn sweep_removal_tombstones(paths: &Paths) {
    for parent in [
        paths.mail_dir(0).parent().map(|p| p.to_path_buf()),
        paths.attachments_dir(0).parent().map(|p| p.to_path_buf()),
        Some(paths.draft_attachments_dir()),
    ]
    .into_iter()
    .flatten()
    {
        let mut entries = match tokio::fs::read_dir(&parent).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_name().to_string_lossy().contains(".removing-") {
                let _ = tokio::fs::remove_dir_all(entry.path()).await;
            }
        }
    }
}

/// Delete staged attachment files, but only paths that canonicalise inside
/// `root` - entries in `paths` come from the DB and are untrusted, so anything
/// resolving outside the staging area is left alone. Each file lives in its
/// own random subdirectory; the directory is removed too once it is empty.
/// Deletion is best-effort: leftovers are reclaimed by the startup sweep.
pub(crate) async fn remove_staged_draft_files(root: &std::path::Path, paths: &[String]) {
    let Ok(root) = tokio::fs::canonicalize(root).await else {
        return;
    };
    for path in paths {
        let Ok(canon) = tokio::fs::canonicalize(path).await else {
            continue;
        };
        if !canon.starts_with(&root) {
            tracing::warn!(
                path,
                "refusing to remove attachment outside draft staging area"
            );
            continue;
        }
        if let Err(e) = tokio::fs::remove_file(&canon).await {
            tracing::debug!(path, error = %e, "staged draft attachment already gone");
        }
        // The per-file subdirectory: drop it only when this was the last file.
        if let Some(dir) = canon.parent()
            && dir != root
            && dir.starts_with(&root)
        {
            let _ = tokio::fs::remove_dir(dir).await;
        }
    }
}

/// Startup GC for the draft-attachment staging area. Staged files whose
/// `draft_attachments` row is gone can never be read again - cleanup between a
/// committing transaction and file removal is best-effort, and a crash leaves
/// them behind. Removes top-level subdirectories that no row references,
/// skipping anything modified within `min_age` so a save racing startup (it
/// stages files before its transaction commits) is never undercut.
/// All deletion is confined to canonicalised children of `root`; the root
/// itself is never touched.
pub async fn sweep_draft_attachment_staging(
    db: &crate::db::Db,
    root: &std::path::Path,
    min_age: std::time::Duration,
) -> Result<usize> {
    let referenced: HashSet<std::path::PathBuf> = db
        .read(|conn| {
            let mut stmt = conn.prepare("SELECT file_path FROM draft_attachments")?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            Ok(rows)
        })
        .await?
        .into_iter()
        .filter_map(|p| std::path::PathBuf::from(p).canonicalize().ok())
        .collect();

    let Ok(root) = tokio::fs::canonicalize(root).await else {
        return Ok(0);
    };
    let mut removed = 0usize;
    let mut entries = tokio::fs::read_dir(&root).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path == root {
            continue;
        }
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        // A recently-touched directory may belong to an in-flight save; one
        // whose mtime is unreadable or lies in the future is kept too -
        // assume fresh rather than risk deleting a save's staging.
        let fresh = match meta.modified() {
            Err(_) => true,
            Ok(m) => m.elapsed().map_or(true, |age| age < min_age),
        };
        if fresh {
            continue;
        }
        let Ok(canon) = tokio::fs::canonicalize(&path).await else {
            continue;
        };
        if !canon.starts_with(&root) {
            continue;
        }
        if referenced.iter().any(|r| r.starts_with(&canon)) {
            continue;
        }
        if meta.is_dir() {
            tokio::fs::remove_dir_all(&canon).await?;
        } else {
            tokio::fs::remove_file(&canon).await?;
        }
        removed += 1;
    }
    Ok(removed)
}

/// Plain-text body for an outgoing invite email (the ICS carries the real
/// event; this is what non-calendar clients show).
fn invite_body_text(args: &CreateEventArgs) -> String {
    use chrono::TimeZone;
    let fmt = |ms: i64| {
        chrono::Local
            .timestamp_millis_opt(ms)
            .earliest()
            .map(|dt| {
                if args.all_day {
                    dt.format("%a, %b %e, %Y").to_string()
                } else {
                    dt.format("%a, %b %e, %Y at %H:%M").to_string()
                }
            })
            .unwrap_or_default()
    };
    let mut out = format!(
        "You are invited: {}\n\nWhen: {} - {}\n",
        args.summary.trim(),
        fmt(args.starts_at),
        fmt(args.ends_at)
    );
    if let Some(loc) = args.location.as_deref().filter(|l| !l.is_empty()) {
        out.push_str(&format!("Where: {loc}\n"));
    }
    if let Some(url) = args.join_url.as_deref().filter(|u| !u.is_empty()) {
        out.push_str(&format!("Join: {url}\n"));
    }
    if let Some(desc) = args.description.as_deref().filter(|d| !d.is_empty()) {
        out.push_str(&format!("\n{desc}\n"));
    }
    out
}

/// Push user-entered OAuth app registrations into the resolver.
fn apply_oauth_settings(settings: &Settings) {
    oauth::providers::set_configured(
        Provider::Gmail,
        &settings.google_client_id,
        &settings.google_client_secret,
    );
    oauth::providers::set_configured(
        Provider::Microsoft,
        &settings.ms_client_id,
        &settings.ms_client_secret,
    );
}

/// Which mail an automation pass looks at.
enum AutomationScope {
    /// Newly received mail the rules haven't handled yet, up to this many
    /// threads.
    New(i64),
    /// These threads as of their newest incoming message, however old and
    /// whether or not the rules ran on them before.
    Threads(Vec<i64>),
}

/// Validate a model-selected route against current local rows. The model only
/// receives configured values, but this protects stale/deleted targets too.
fn valid_automation_route(conn: &rusqlite::Connection, target: &str) -> Result<bool> {
    let (table, id) = match target.parse::<models::RouteKey>() {
        Ok(models::RouteKey::Important | models::RouteKey::Other) => return Ok(true),
        Ok(models::RouteKey::Split(id)) => ("split_rules", id),
        Ok(models::RouteKey::Label(id)) => ("labels", id),
        Ok(models::RouteKey::Pending) | Err(_) => return Ok(false),
    };
    let sql = format!("SELECT EXISTS (SELECT 1 FROM {table} WHERE id = ?1)");
    Ok(conn.query_row(&sql, rusqlite::params![id], |row| row.get::<_, i64>(0))? != 0)
}

/// Upper bound for one manual Inbox pass, shared by every account in the request.
const SYNC_NOW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);
/// How long account removal waits for the account's tasks to unwind before
/// aborting whatever is still running. Tasks observe the shared stop flag at
/// their await points and exit in milliseconds; the bound only bites for a
/// task parked in a network call (e.g. a connect to a dead server), which
/// then cannot hold deletion hostage.
const REMOVE_ACCOUNT_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Test-only failure injection for `remove_account`'s pre-commit phase:
/// make the writer-thread barrier report a failure, or roll the delete
/// transaction back after `repo::accounts::delete` has run.
#[cfg(test)]
static REMOVE_FAIL_BARRIER: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static REMOVE_FAIL_TX: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Test-only gate: when `REMOVE_PAUSE_FOR_ADD` is set, a removal holds the
/// lifecycle lock inside its locked section (post-commit, pre-cleanup) until
/// `REMOVE_RESUME_GATE` fires - lets a test queue an account add behind the
/// removal to prove id-keyed cleanup is ordered before the lock is released.
#[cfg(test)]
static REMOVE_PAUSE_FOR_ADD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static REMOVE_RESUME_GATE: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Wait for every account's foreground Inbox pass at once. The passes already
/// run concurrently (one actor per account); this waits on them concurrently
/// too, under a single shared deadline, and only reports once every account
/// has settled. A failing or hung account therefore neither hides the others'
/// results nor lets the caller refresh before they finish. Distinct failure
/// messages are joined, so a single-account request keeps its exact error.
async fn await_sync_passes(
    receivers: Vec<tokio::sync::oneshot::Receiver<std::result::Result<(), String>>>,
    limit: std::time::Duration,
) -> Result<()> {
    let outcomes = futures::future::join_all(
        receivers
            .into_iter()
            .map(|receiver| tokio::time::timeout(limit, receiver)),
    )
    .await;
    let mut failures: Vec<String> = Vec::new();
    for outcome in outcomes {
        let message = match outcome {
            Err(_) => Some("Inbox sync timed out".to_string()),
            Ok(Err(_)) => Some("sync actor stopped".to_string()),
            Ok(Ok(Err(message))) => Some(message),
            Ok(Ok(Ok(()))) => None,
        };
        if let Some(message) = message {
            if !failures.contains(&message) {
                failures.push(message);
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CoreError::Other(failures.join("; ")))
    }
}

#[cfg(test)]
mod sync_now_wait_tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::sync::oneshot;

    type Pass = oneshot::Sender<std::result::Result<(), String>>;

    fn channel() -> (Pass, oneshot::Receiver<std::result::Result<(), String>>) {
        oneshot::channel()
    }

    #[tokio::test]
    async fn waits_for_every_account_before_reporting_the_first_failure() {
        let (fail_tx, fail_rx) = channel();
        let (slow_tx, slow_rx) = channel();
        fail_tx.send(Err("authentication required".into())).unwrap();
        let slow = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            slow_tx.send(Ok(())).unwrap();
        });
        let started = Instant::now();
        let err = await_sync_passes(vec![fail_rx, slow_rx], Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            started.elapsed() >= Duration::from_millis(70),
            "returned before the slow account settled"
        );
        assert_eq!(
            err.to_string(),
            CoreError::Other("authentication required".into()).to_string()
        );
        slow.await.unwrap();
    }

    #[tokio::test]
    async fn shares_one_deadline_instead_of_stacking_per_account_timeouts() {
        let (a_tx, a_rx) = channel();
        let (b_tx, b_rx) = channel();
        let first = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            a_tx.send(Ok(())).unwrap();
        });
        let started = Instant::now();
        let err = await_sync_passes(vec![a_rx, b_rx], Duration::from_millis(300))
            .await
            .unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(420),
            "timeouts stacked: {elapsed:?}"
        );
        assert!(err.to_string().contains("Inbox sync timed out"));
        first.await.unwrap();
        drop(b_tx);
    }

    #[tokio::test]
    async fn succeeds_only_when_all_accounts_succeed_and_dedupes_messages() {
        let (a_tx, a_rx) = channel();
        let (b_tx, b_rx) = channel();
        a_tx.send(Ok(())).unwrap();
        b_tx.send(Ok(())).unwrap();
        await_sync_passes(vec![a_rx, b_rx], Duration::from_secs(1))
            .await
            .unwrap();

        let (c_tx, c_rx) = channel();
        let (d_tx, d_rx) = channel();
        c_tx.send(Err("offline".into())).unwrap();
        d_tx.send(Err("offline".into())).unwrap();
        let err = await_sync_passes(vec![c_rx, d_rx], Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            CoreError::Other("offline".into()).to_string()
        );
    }

    #[tokio::test]
    async fn reports_a_stopped_actor() {
        let (tx, rx) = channel();
        drop(tx);
        let err = await_sync_passes(vec![rx], Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sync actor stopped"));
    }
}

#[cfg(test)]
mod trash_regression_tests {
    use super::*;
    use crate::db::testutil;

    #[test]
    fn trash_moves_custom_folder_mail_and_hides_it_from_normal_views() {
        let mut c = testutil::conn();
        testutil::seed_account(&c);
        c.execute_batch(
            "INSERT INTO folders(id,account_id,imap_name,role) VALUES
            (2,1,'Trash','trash'),(3,1,'Spam','spam'),(4,1,'Custom',NULL);",
        )
        .unwrap();
        let (tid, mid) = testutil::seed_message(&c, "sender@test.dev", "trash test", false);
        c.execute(
            "UPDATE messages SET folder_id=4, is_starred=1 WHERE id=?1",
            [mid],
        )
        .unwrap();
        repo::threads::recompute(&c, tid).unwrap();
        let actions = apply_thread_action(&mut c, tid, ActionKind::Trash, None).unwrap();
        assert_eq!(actions.len(), 1, "role-less folders must enqueue a move");
        let folder: i64 = c
            .query_row("SELECT folder_id FROM messages WHERE id=?1", [mid], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(folder, 2);
        for view in [
            View::All,
            View::Starred,
            View::Inbox,
            View::Snoozed,
            View::Sent,
            View::Drafts,
            View::Done,
            View::Spam,
            View::Trash,
        ] {
            let is_trash = matches!(view, View::Trash);
            let page = repo::threads::list(
                &c,
                &repo::threads::ListArgs {
                    view,
                    tab: None,
                    account_id: Some(1),
                    folder_id: None,
                    cursor: None,
                    limit: 50,
                },
            )
            .unwrap();
            assert_eq!(page.threads.len(), usize::from(is_trash));
        }
        assert!(
            apply_thread_action(&mut c, tid, ActionKind::Trash, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn move_and_undo_capture_remote_identity_before_optimistic_changes() {
        let mut c = testutil::conn();
        testutil::seed_account(&c);
        c.execute_batch(
            "UPDATE folders SET uidvalidity=41 WHERE id=1;
            INSERT INTO folders(id,account_id,imap_name,role,uidvalidity)
            VALUES (2,1,'Trash','trash',42);",
        )
        .unwrap();
        let (tid, mid) = testutil::seed_message(&c, "sender@test.dev", "identity", false);
        c.execute(
            "UPDATE messages SET uid=11,message_id='move@test.invalid' WHERE id=?1",
            [mid],
        )
        .unwrap();
        let ids = apply_thread_action(&mut c, tid, ActionKind::Trash, None).unwrap();
        let action = repo::actions::get(&c, ids[0].0).unwrap().unwrap();
        assert_eq!(action.payload["srcUid"], 11);
        assert_eq!(action.payload["srcUidValidity"], 41);
        assert_eq!(action.payload["srcMessageId"], "move@test.invalid");
        assert_eq!(repo::messages::get_row(&c, mid).unwrap().unwrap().uid, None);
        c.execute(
            "UPDATE pending_actions SET state='done' WHERE id=?1",
            [action.id],
        )
        .unwrap();
        revert_action(&mut c, &action).unwrap();
        let inverse_id = c
            .query_row("SELECT MAX(id) FROM pending_actions", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap();
        let inverse = repo::actions::get(&c, inverse_id).unwrap().unwrap();
        assert_eq!(inverse.payload["srcFolderId"], 2);
        assert!(inverse.payload["srcUid"].is_null());
        assert_eq!(inverse.payload["srcUidValidity"], 42);
        assert_eq!(inverse.payload["srcMessageId"], "move@test.invalid");
        assert_eq!(inverse.payload["targetFolderId"], 1);
    }

    #[test]
    fn spam_moves_custom_folder_mail_too() {
        let mut c = testutil::conn();
        testutil::seed_account(&c);
        c.execute_batch(
            "INSERT INTO folders(id,account_id,imap_name,role) VALUES
            (2,1,'Spam','spam'),(3,1,'Custom',NULL);",
        )
        .unwrap();
        let (tid, mid) = testutil::seed_message(&c, "sender@test.dev", "spam test", false);
        c.execute("UPDATE messages SET folder_id=3 WHERE id=?1", [mid])
            .unwrap();
        assert_eq!(
            apply_thread_action(&mut c, tid, ActionKind::Spam, None)
                .unwrap()
                .len(),
            1
        );
        let folder: i64 = c
            .query_row("SELECT folder_id FROM messages WHERE id=?1", [mid], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(folder, 2);
    }
}

#[cfg(test)]
mod ask_scope_tests {
    use super::*;
    use crate::db::testutil;

    /// A minimal `Core` over a fresh tempdir DB - enough to run the Ask
    /// retrieval path (no actors, no embedder, no network).
    async fn test_core() -> (Core, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let paths = crate::config::Paths::for_tests(root.path());
        paths.ensure().unwrap();
        let core = Core {
            db: Db::open(&paths.db_file()).unwrap(),
            bus: EventBus::new(),
            paths: Arc::new(paths),
            tokens: TokenProvider::new(),
            handles: Arc::new(RwLock::new(HashMap::new())),
            cal_handles: Arc::new(RwLock::new(HashMap::new())),
            contacts_handles: Arc::new(RwLock::new(HashMap::new())),
            attachment_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            account_lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            embed: Arc::new(embed::EmbedState::new()),
            oauth_cancel: Arc::new(tokio::sync::Notify::new()),
            ui_ready: Arc::new(tokio::sync::Notify::new()),
            ai_router_lock: Arc::new(tokio::sync::Mutex::new(())),
            mcp: Arc::new(mcp::McpManager::default()),
        };
        (core, root)
    }

    /// Two accounts, each with one indexed message sharing `sharedterm`.
    /// Returns (account-1 message id, account-2 message id).
    async fn seed_two_accounts(db: &Db) -> (i64, i64) {
        db.write(|conn| {
            testutil::seed_account(conn);
            let (_, m1) = testutil::seed_message(conn, "a@one.dev", "sharedterm alpha", false);
            repo::search::index_message(conn, m1)?;
            // A body keeps `ensure_bodies` from kicking off (and waiting on)
            // a network fetch in tests.
            repo::messages::store_body(conn, m1, Some("alpha body"), None, None, false, None)?;
            conn.execute(
                "INSERT INTO accounts (id, email, provider, auth_kind, username,
                 imap_host, imap_port, smtp_host, smtp_port, created_at)
                 VALUES (2,'me2@test.dev','imap','password','me2','h',993,'h',587,0)",
                [],
            )?;
            conn.execute(
                "INSERT INTO folders (id, account_id, imap_name, role) VALUES (2,2,'INBOX','inbox')",
                [],
            )?;
            conn.execute(
                "INSERT INTO threads (id, account_id, subject_norm, unread_count, last_message_at)
                 VALUES (99, 2, 'sharedterm beta', 1, 1000)",
                [],
            )?;
            conn.execute(
                "INSERT INTO messages (thread_id, account_id, folder_id, uid, message_id, subject,
                 from_addr, date, is_read, is_automated, is_draft, is_outgoing)
                 VALUES (99, 2, 2, 99, 'mid-99', 'sharedterm beta', 'b@two.dev', 1000, 0, 0, 0, 0)",
                [],
            )?;
            let m2 = conn.last_insert_rowid();
            repo::search::index_message(conn, m2)?;
            repo::messages::store_body(conn, m2, Some("beta body"), None, None, false, None)?;
            Ok::<_, CoreError>((m1, m2))
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn retrieve_search_scopes_keyword_hits_to_the_account() {
        let (core, _tmp) = test_core().await;
        let (m1, m2) = seed_two_accounts(&core.db).await;

        let all = core.retrieve_search("sharedterm", 10, None).await.unwrap();
        assert!(all.iter().any(|m| m.id == m1));
        assert!(all.iter().any(|m| m.id == m2));

        let one = core
            .retrieve_search("sharedterm", 10, Some(1))
            .await
            .unwrap();
        assert_eq!(one.iter().map(|m| m.id).collect::<Vec<_>>(), vec![m1]);
        let two = core
            .retrieve_search("sharedterm", 10, Some(2))
            .await
            .unwrap();
        assert_eq!(two.iter().map(|m| m.id).collect::<Vec<_>>(), vec![m2]);
    }

    #[tokio::test]
    async fn vector_hit_scoping_drops_other_accounts() {
        let (core, _tmp) = test_core().await;
        let (m1, m2) = seed_two_accounts(&core.db).await;

        let hits = vec![(m2, 0.9f32), (m1, 0.8)];
        let one = core.scope_hits_to_account(hits.clone(), 1).await.unwrap();
        assert_eq!(one, vec![(m1, 0.8)]);
        let two = core.scope_hits_to_account(hits, 2).await.unwrap();
        assert_eq!(two, vec![(m2, 0.9)]);
        // Ids not in the DB at all are dropped too.
        let gone = core
            .scope_hits_to_account(vec![(999_999, 0.7), (m1, 0.6)], 1)
            .await
            .unwrap();
        assert_eq!(gone, vec![(m1, 0.6)]);
    }

    #[tokio::test]
    async fn search_inbox_tool_respects_account_scope() {
        let (core, _tmp) = test_core().await;
        let (m1, _m2) = seed_two_accounts(&core.db).await;
        let mut sources = Vec::new();
        let noop = |_| {};
        let (text, added) = core
            .run_search_inbox(r#"{"query":"sharedterm"}"#, &mut sources, Some(1), &noop)
            .await;
        assert_eq!(added, 1);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].id, m1);
        assert!(!text.contains("sharedterm beta"));
    }

    #[tokio::test]
    async fn read_email_tool_refuses_out_of_scope_source() {
        let (core, _tmp) = test_core().await;
        let (_m1, m2) = seed_two_accounts(&core.db).await;
        let mut sources = core
            .retrieve_search("sharedterm", 10, Some(1))
            .await
            .unwrap();
        assert_eq!(sources.len(), 1);
        // A foreign-account detail slipped into the citation list must not be
        // readable while the filter is on (scoped retrieval can't produce one,
        // but the guard holds even if it ever did).
        let foreign = core
            .db
            .read(move |conn| repo::messages::detail(conn, m2))
            .await
            .unwrap();
        sources.push(foreign);
        let noop = |_| {};
        let out = core
            .run_read_email(r#"{"n":2}"#, &sources, Some(1), &noop)
            .await;
        assert!(out.contains("outside the selected account"));
        let out = core
            .run_read_email(r#"{"n":1}"#, &sources, Some(1), &noop)
            .await;
        assert!(out.contains("sharedterm alpha"));
    }
}

fn action_identity_payload(
    conn: &rusqlite::Connection,
    message_id: i64,
) -> Result<serde_json::Value> {
    repo::actions::identity_payload(conn, message_id)
}

fn move_identity_payload(
    conn: &rusqlite::Connection,
    message_id: i64,
    source_folder: Option<i64>,
    source_uid: Option<i64>,
    target_folder: i64,
) -> Result<serde_json::Value> {
    let message = repo::messages::get_row(conn, message_id)?
        .ok_or_else(|| CoreError::NotFound("message for move".into()))?;
    let validity = source_folder
        .map(|id| repo::folders::get(conn, id))
        .transpose()?
        .flatten()
        .and_then(|folder| folder.uidvalidity);
    Ok(serde_json::json!({
        "srcFolderId": source_folder,
        "srcUid": source_uid,
        "srcUidValidity": validity,
        "srcMessageId": message.message_id,
        "targetFolderId": target_folder,
    }))
}

/// Shared optimistic move path for user actions and legacy Trash-intent repair.
#[allow(clippy::too_many_arguments)]
pub(crate) fn enqueue_move(
    tx: &rusqlite::Transaction,
    account_id: i64,
    thread_id: i64,
    msg_id: i64,
    src_folder: Option<i64>,
    src_uid: Option<i64>,
    target: i64,
    kind_str: &str,
) -> Result<i64> {
    let payload = move_identity_payload(tx, msg_id, src_folder, src_uid, target)?;
    repo::messages::set_uid_and_folder(tx, msg_id, target, None)?;
    repo::actions::enqueue(
        tx,
        account_id,
        kind_str,
        Some(msg_id),
        Some(thread_id),
        &payload,
        None,
    )
}

/// Optimistic local mutation + enqueue, in one transaction.
/// Returns (action_id, account_id) pairs.
fn apply_thread_action(
    conn: &mut rusqlite::Connection,
    thread_id: i64,
    kind: ActionKind,
    params: Option<&ActionParams>,
) -> Result<Vec<(i64, i64)>> {
    trash::ensure_not_deleting(conn, thread_id)?;
    let tx = conn.transaction()?;
    let mut out: Vec<(i64, i64)> = Vec::new();

    let account_id: i64 = tx.query_row(
        "SELECT account_id FROM threads WHERE id = ?1",
        rusqlite::params![thread_id],
        |r| r.get(0),
    )?;

    // Most thread actions intentionally ignore drafts. Archive and Trash are
    // exceptions: users can file or discard a draft from the Drafts view, and
    // excluding it here made the optimistic removal snap back on reconciliation.
    let include_drafts = matches!(kind, ActionKind::Archive | ActionKind::Trash);
    let mut stmt = tx.prepare(
        "SELECT m.id, m.folder_id, m.uid, m.is_read, m.is_starred, COALESCE(f.role,'')
         FROM messages m LEFT JOIN folders f ON f.id = m.folder_id
         WHERE m.thread_id = ?1 AND (m.is_draft = 0 OR ?2 = 1)",
    )?;
    #[allow(clippy::type_complexity)]
    let msgs: Vec<(i64, Option<i64>, Option<i64>, bool, bool, String)> = stmt
        .query_map(rusqlite::params![thread_id, include_drafts as i64], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get::<_, i64>(3)? != 0,
                r.get::<_, i64>(4)? != 0,
                r.get(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    fn folder_of(tx: &rusqlite::Transaction, account_id: i64, role: &str) -> Result<Option<i64>> {
        Ok(repo::folders::by_role(tx, account_id, role)?.map(|f| f.id))
    }

    match kind {
        ActionKind::DeletePermanently => {
            return Err(CoreError::DeleteRejected(
                "Use the atomic deletion batch".into(),
            ));
        }
        ActionKind::MarkRead | ActionKind::MarkUnread => {
            let target_read = kind == ActionKind::MarkRead;
            for (id, _f, _u, is_read, _s, _role) in &msgs {
                if *is_read != target_read {
                    repo::messages::set_read(&tx, *id, target_read)?;
                    let payload = action_identity_payload(&tx, *id)?;
                    let aid = repo::actions::enqueue(
                        &tx,
                        account_id,
                        kind.as_str(),
                        Some(*id),
                        Some(thread_id),
                        &payload,
                        None,
                    )?;
                    out.push((aid, account_id));
                }
            }
        }
        ActionKind::Star => {
            // Star the latest message only (thread-level star).
            if let Some((id, _f, _u, _r, is_starred, _role)) = msgs.iter().max_by_key(|m| m.0) {
                if *is_starred {
                    repo::threads::recompute(&tx, thread_id)?;
                    tx.commit()?;
                    return Ok(out);
                }
                repo::messages::set_starred(&tx, *id, true)?;
                let aid = repo::actions::enqueue(
                    &tx,
                    account_id,
                    "star",
                    Some(*id),
                    Some(thread_id),
                    &action_identity_payload(&tx, *id)?,
                    None,
                )?;
                out.push((aid, account_id));
            }
        }
        ActionKind::Unstar => {
            for (id, _f, _u, _r, is_starred, _role) in &msgs {
                if *is_starred {
                    repo::messages::set_starred(&tx, *id, false)?;
                    let aid = repo::actions::enqueue(
                        &tx,
                        account_id,
                        "unstar",
                        Some(*id),
                        Some(thread_id),
                        &action_identity_payload(&tx, *id)?,
                        None,
                    )?;
                    out.push((aid, account_id));
                }
            }
        }
        ActionKind::Archive | ActionKind::Trash | ActionKind::Spam => {
            let (target_role, kind_str) = match kind {
                ActionKind::Archive => (roles::ARCHIVE, "archive"),
                ActionKind::Trash => (roles::TRASH, "trash"),
                _ => (roles::SPAM, "spam"),
            };
            // Gmail-style fallback: archiving with no Archive folder moves to All Mail.
            let target = folder_of(&tx, account_id, target_role)?
                .or(if kind == ActionKind::Archive {
                    folder_of(&tx, account_id, roles::ALL)?
                } else {
                    None
                })
                .ok_or_else(|| CoreError::NotFound(format!("no {target_role} folder")))?;
            for (id, f, u, _r, _s, role) in &msgs {
                let movable = match kind {
                    ActionKind::Archive => role == roles::INBOX || role == roles::DRAFTS,
                    // Custom IMAP folders have no special-use role but are
                    // valid move sources too. Compare concrete folder ids.
                    _ => *f != Some(target),
                };
                if movable && f.is_some() {
                    let aid =
                        enqueue_move(&tx, account_id, thread_id, *id, *f, *u, target, kind_str)?;
                    out.push((aid, account_id));
                }
            }
            // Archiving also clears snooze.
            repo::snoozes::clear(&tx, thread_id)?;
        }
        ActionKind::Unarchive | ActionKind::NotSpam => {
            let target = folder_of(&tx, account_id, roles::INBOX)?
                .ok_or_else(|| CoreError::NotFound("no inbox folder".into()))?;
            let from_role = if kind == ActionKind::Unarchive {
                roles::ARCHIVE
            } else {
                roles::SPAM
            };
            for (id, f, u, _r, _s, role) in &msgs {
                if (role == from_role || (kind == ActionKind::Unarchive && role == roles::ALL))
                    && f.is_some()
                {
                    let aid = enqueue_move(
                        &tx,
                        account_id,
                        thread_id,
                        *id,
                        *f,
                        *u,
                        target,
                        kind.as_str(),
                    )?;
                    out.push((aid, account_id));
                }
            }
        }
        ActionKind::Move => {
            let target = params
                .and_then(|p| p.target_folder_id)
                .ok_or_else(|| CoreError::Other("move requires targetFolderId".into()))?;
            for (id, f, u, _r, _s, _role) in &msgs {
                if f.is_some() && *f != Some(target) {
                    let aid =
                        enqueue_move(&tx, account_id, thread_id, *id, *f, *u, target, "move")?;
                    out.push((aid, account_id));
                }
            }
        }
        ActionKind::Snooze => {
            let wake_at = params
                .and_then(|p| p.wake_at)
                .ok_or_else(|| CoreError::Other("snooze requires wakeAt".into()))?;
            let orig = msgs.iter().find_map(|(_, f, ..)| *f);
            repo::snoozes::set(&tx, thread_id, account_id, wake_at, orig)?;
            let aid = repo::actions::enqueue(
                &tx,
                account_id,
                "snooze",
                None,
                Some(thread_id),
                &serde_json::json!({ "wakeAt": wake_at }),
                None,
            )?;
            out.push((aid, account_id));
        }
        ActionKind::Unsnooze => {
            repo::snoozes::clear(&tx, thread_id)?;
            let aid = repo::actions::enqueue(
                &tx,
                account_id,
                "unsnooze",
                None,
                Some(thread_id),
                &serde_json::json!({}),
                None,
            )?;
            out.push((aid, account_id));
        }
        ActionKind::AddLabel | ActionKind::RemoveLabel => {
            let label_id = params
                .and_then(|p| p.label_id)
                .ok_or_else(|| CoreError::Other("label action requires labelId".into()))?;
            let label = repo::labels::get(&tx, label_id)?
                .ok_or_else(|| CoreError::NotFound(format!("label {label_id}")))?;
            let add = kind == ActionKind::AddLabel;
            for (id, ..) in &msgs {
                let mut payload = action_identity_payload(&tx, *id)?;
                payload["labelId"] = serde_json::json!(label_id);
                payload["keyword"] = serde_json::json!(label.keyword);
                if add {
                    repo::labels::add_to_message(&tx, *id, label_id)?;
                } else {
                    repo::labels::remove_from_message(&tx, *id, label_id)?;
                }
                // Auto labels are local-only: mutate membership but never push
                // their keyword to IMAP (server reconcile also skips them).
                if label.is_auto {
                    continue;
                }
                let aid = repo::actions::enqueue(
                    &tx,
                    account_id,
                    kind.as_str(),
                    Some(*id),
                    Some(thread_id),
                    &payload,
                    None,
                )?;
                out.push((aid, account_id));
            }
        }
        ActionKind::Send => {
            return Err(CoreError::Other("use queue_send for sending".into()));
        }
    }

    repo::threads::recompute(&tx, thread_id)?;
    tx.commit()?;
    Ok(out)
}

/// Inverse of an action: cancel if pending, revert the local mutation, and
/// enqueue a compensating remote action when the original already ran.
/// Returns the affected thread id.
fn revert_action(
    conn: &mut rusqlite::Connection,
    action: &repo::actions::PendingAction,
) -> Result<Option<i64>> {
    if let Some(tid) = action.thread_id {
        trash::ensure_not_deleting(conn, tid)?;
    }
    let was_pending = repo::actions::try_cancel(conn, action.id)?;
    let tx = conn.transaction()?;
    let thread_id = action.thread_id;

    match action.kind.as_str() {
        "mark_read" | "mark_unread" => {
            if let Some(mid) = action.message_id {
                repo::messages::set_read(&tx, mid, action.kind == "mark_unread")?;
                if !was_pending {
                    let inverse = if action.kind == "mark_read" {
                        "mark_unread"
                    } else {
                        "mark_read"
                    };
                    repo::actions::enqueue(
                        &tx,
                        action.account_id,
                        inverse,
                        Some(mid),
                        thread_id,
                        &action_identity_payload(&tx, mid)?,
                        None,
                    )?;
                }
            }
        }
        "star" | "unstar" => {
            if let Some(mid) = action.message_id {
                repo::messages::set_starred(&tx, mid, action.kind == "unstar")?;
                if !was_pending {
                    let inverse = if action.kind == "star" {
                        "unstar"
                    } else {
                        "star"
                    };
                    repo::actions::enqueue(
                        &tx,
                        action.account_id,
                        inverse,
                        Some(mid),
                        thread_id,
                        &action_identity_payload(&tx, mid)?,
                        None,
                    )?;
                }
            }
        }
        "archive" | "trash" | "spam" | "move" | "unarchive" | "not_spam" => {
            if let Some(mid) = action.message_id {
                let src_folder = action.payload["srcFolderId"].as_i64();
                let src_uid = action.payload["srcUid"].as_i64();
                let cur_folder = action.payload["targetFolderId"].as_i64();
                if let Some(src) = src_folder {
                    if was_pending {
                        // Remote never changed; restore the original mapping.
                        repo::messages::set_uid_and_folder(&tx, mid, src, src_uid)?;
                    } else {
                        // Remote moved; move it back.
                        repo::messages::set_uid_and_folder(&tx, mid, src, None)?;
                        let payload = move_identity_payload(&tx, mid, cur_folder, None, src)?;
                        repo::actions::enqueue(
                            &tx,
                            action.account_id,
                            "move",
                            Some(mid),
                            thread_id,
                            &payload,
                            None,
                        )?;
                    }
                }
            }
        }
        "add_label" | "remove_label" => {
            if let (Some(mid), Some(label_id)) =
                (action.message_id, action.payload["labelId"].as_i64())
            {
                let was_add = action.kind == "add_label";
                // Restore the local membership to its pre-action state.
                if was_add {
                    repo::labels::remove_from_message(&tx, mid, label_id)?;
                } else {
                    repo::labels::add_to_message(&tx, mid, label_id)?;
                }
                if !was_pending {
                    // Remote already got the keyword; enqueue the inverse push.
                    let inverse = if was_add { "remove_label" } else { "add_label" };
                    let mut payload = action_identity_payload(&tx, mid)?;
                    payload["labelId"] = action.payload["labelId"].clone();
                    payload["keyword"] = action.payload["keyword"].clone();
                    repo::actions::enqueue(
                        &tx,
                        action.account_id,
                        inverse,
                        Some(mid),
                        thread_id,
                        &payload,
                        None,
                    )?;
                }
            }
        }
        "snooze" => {
            if let Some(tid) = thread_id {
                repo::snoozes::clear(&tx, tid)?;
            }
        }
        "unsnooze" => { /* nothing sensible to restore */ }
        "send" => { /* cancel already handled if pending; sent mail can't be unsent */ }
        _ => {}
    }

    if let Some(tid) = thread_id {
        repo::threads::recompute(&tx, tid)?;
    }
    tx.commit()?;
    Ok(thread_id)
}

#[cfg(test)]
mod remove_account_failpoint_tests {
    use super::*;
    use crate::db::testutil;

    /// Serialises this module's tests: the failpoint flags are one-shot
    /// globals and `COMAIL_CREDENTIALS_INSECURE_FILE` is process-wide, so two
    /// of these running at once would steal each other's injections.
    async fn failpoint_lock() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        LOCK.lock().await
    }

    /// A minimal `Core` over a fresh tempdir DB, with the account's full task
    /// set running (sync actor + caldav + carddav) and a stored credential -
    /// the state `remove_account` must restore on every pre-commit failure.
    async fn test_core() -> (Core, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let paths = crate::config::Paths::for_tests(root.path());
        paths.ensure().unwrap();
        // The shared per-process file convention the OAuth tests use; the
        // account id keeps the entry isolated from theirs.
        unsafe {
            std::env::set_var(
                "COMAIL_CREDENTIALS_INSECURE_FILE",
                std::env::temp_dir().join(format!(
                    "comail-tokens-test-creds-{}.json",
                    std::process::id()
                )),
            )
        };
        let core = Core {
            db: Db::open(&paths.db_file()).unwrap(),
            bus: EventBus::new(),
            paths: Arc::new(paths),
            tokens: TokenProvider::new(),
            handles: Arc::new(RwLock::new(HashMap::new())),
            cal_handles: Arc::new(RwLock::new(HashMap::new())),
            contacts_handles: Arc::new(RwLock::new(HashMap::new())),
            attachment_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            account_lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            embed: Arc::new(embed::EmbedState::new()),
            oauth_cancel: Arc::new(tokio::sync::Notify::new()),
            ui_ready: Arc::new(tokio::sync::Notify::new()),
            ai_router_lock: Arc::new(tokio::sync::Mutex::new(())),
            mcp: Arc::new(mcp::McpManager::default()),
        };
        core.db
            .write(|conn| {
                testutil::seed_account(conn);
                // Indexed messages spanning more than one sweep batch, plus
                // one message with a cached body indexed through the real
                // `index_message` path (its body text is what repair must
                // reproduce identically).
                testutil::seed_bulk_messages(conn, 1, 6_001, "bulkterm");
                let (_t, m) = testutil::seed_message(conn, "s@t.dev", "hdrterm", false);
                conn.execute(
                    "INSERT INTO message_bodies (message_id, text_body)
                     VALUES (?1, 'bodyonlyterm rest of the body')",
                    [m],
                )?;
                repo::search::index_message(conn, m)?;
                repo::caldav::upsert_config(
                    conn,
                    &repo::caldav::CaldavConfig {
                        account_id: 1,
                        kind: "generic".into(),
                        base_url: "https://cal.invalid".into(),
                        username: Some("u".into()),
                        principal_url: None,
                        home_set_url: None,
                        enabled: true,
                        last_error: None,
                    },
                )?;
                repo::carddav::upsert_config(
                    conn,
                    &repo::carddav::CarddavConfig {
                        account_id: 1,
                        base_url: "https://card.invalid".into(),
                        username: Some("u".into()),
                        principal_url: None,
                        home_set_url: None,
                        enabled: true,
                        last_error: None,
                        last_synced_at: None,
                    },
                )?;
                Ok(())
            })
            .await
            .unwrap();
        credentials::store_async(1, Slot::Password, "pass".into())
            .await
            .unwrap();
        let cfg = core
            .db
            .read(|conn| Ok(repo::accounts::get_config(conn, 1)?.unwrap()))
            .await
            .unwrap();
        core.spawn_actor(cfg).await;
        core.spawn_cal_task(1).await;
        core.spawn_contacts_task(1).await;
        (core, root)
    }

    /// What every pre-commit failure must leave behind: the account row, its
    /// credentials, and all three task groups running again.
    async fn assert_fully_usable(core: &Core) {
        assert!(
            core.handles.read().await.contains_key(&1),
            "sync actor must be running again"
        );
        assert!(
            core.cal_handles.read().await.contains_key(&1),
            "calendar task must be running again"
        );
        assert!(
            core.contacts_handles.read().await.contains_key(&1),
            "contacts task must be running again"
        );
        assert!(
            core.db
                .read(|conn| Ok(repo::accounts::get(conn, 1)?.is_some()))
                .await
                .unwrap(),
            "account row must be intact"
        );
        assert_eq!(
            credentials::load_async(1, Slot::Password).await.unwrap(),
            "pass",
            "credentials must survive a rolled-back removal"
        );
        // The repair path must leave the search index COMPLETE, not merely
        // present: every swept row re-indexed, body-only terms matching the
        // cached body again (same content index_message wrote), the negative
        // predicate search relies on correct, and the marker cleared.
        core.db
            .read(|conn| {
                let fts: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM messages_fts fts
                     WHERE fts.rowid IN (SELECT id FROM messages WHERE account_id = 1)",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(fts, 6_002, "every swept FTS row must be re-indexed");
                let hits: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'bodyonlyterm'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(hits, 1, "body-only term must match the cached body again");
                let not_indexed: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM messages m
                     WHERE m.account_id = 1
                       AND m.id NOT IN (SELECT rowid FROM messages_fts)",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(
                    not_indexed, 0,
                    "search's NOT-IN predicate must exclude nothing"
                );
                assert!(
                    repo::accounts::removal_markers(conn)?.is_empty(),
                    "marker must be cleared after a repaired rollback"
                );
                Ok(())
            })
            .await
            .unwrap();
    }

    /// A failing writer-thread barrier is a pre-commit failure: teardown is
    /// undone and the account is usable again, not left taskless.
    #[tokio::test]
    async fn barrier_failure_restores_the_whole_task_set() {
        let _guard = failpoint_lock().await;
        let (core, _root) = test_core().await;
        REMOVE_FAIL_BARRIER.store(true, std::sync::atomic::Ordering::SeqCst);
        let err = core.remove_account(1).await.unwrap_err();
        assert!(err.to_string().contains("barrier"), "{err}");
        assert_fully_usable(&core).await;
    }

    /// A delete-transaction failure rolls the account data back and restarts
    /// every task group - credentials were not purged yet at that point.
    #[tokio::test]
    async fn delete_tx_failure_restores_the_whole_task_set() {
        let _guard = failpoint_lock().await;
        let (core, _root) = test_core().await;
        REMOVE_FAIL_TX.store(true, std::sync::atomic::Ordering::SeqCst);
        let err = core.remove_account(1).await.unwrap_err();
        assert!(err.to_string().contains("injected delete"), "{err}");
        assert_fully_usable(&core).await;
    }

    /// The lifecycle lock excludes account creation from the id-recycle
    /// window: while it is held a removal can run everything up to the
    /// delete commit but cannot finish. Releasing it lets it complete.
    #[tokio::test]
    async fn removal_cannot_finish_while_the_lifecycle_lock_is_held() {
        let _guard = failpoint_lock().await;
        let (core, _root) = test_core().await;
        // Stop the tasks first so the removal does not burn the test window
        // waiting on the stop deadline against unreachable hosts.
        let handle = core.handles.read().await.get(&1).cloned().unwrap();
        handle.send(SyncCmd::Shutdown);

        let lifecycle = core.account_lifecycle.lock().await;
        let spawned = {
            let core = core.clone();
            tokio::spawn(async move { core.remove_account(1).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            !spawned.is_finished(),
            "remove_account finished while the lifecycle lock was held"
        );
        drop(lifecycle);
        spawned.await.unwrap().unwrap();
        assert!(core.account_lifecycle.try_lock().is_ok());
    }

    /// The lifecycle lock is the only thing that makes `account_id` still
    /// mean "the account being removed" - so every cleanup step keyed by it
    /// (credential purge) or by recyclable message ids (vector eviction)
    /// must finish before the lock is released. Hold a removal inside its
    /// locked section, queue an add behind the lock, and prove the new
    /// account - which recycles the id - keeps its password and a vector
    /// pushed on a recycled message id.
    #[tokio::test]
    async fn id_keyed_cleanup_finishes_before_the_lifecycle_lock_releases() {
        let _guard = failpoint_lock().await;
        let (core, _root) = test_core().await;
        // Stop the tasks so the removal does not spend the window on the
        // stop deadline against unreachable hosts.
        let handle = core.handles.read().await.get(&1).cloned().unwrap();
        handle.send(SyncCmd::Shutdown);
        // A vector on one of account 1's messages - the eviction must drop it.
        let old_mid: i64 = core
            .db
            .read(|conn| {
                conn.query_row(
                    "SELECT id FROM messages WHERE account_id = 1 LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        {
            let mut idx = core.embed.index.write().await;
            idx.reset(3, "m");
            idx.push(old_mid, 0, &[1.0, 0.0, 0.0]);
        }

        REMOVE_PAUSE_FOR_ADD.store(true, std::sync::atomic::Ordering::SeqCst);
        let spawned = {
            let core = core.clone();
            tokio::spawn(async move { core.remove_account(1).await })
        };
        // The flag clears when the removal reaches the gate inside the
        // locked section - post-commit, before the id-keyed cleanup.
        while REMOVE_PAUSE_FOR_ADD.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        // Queue the add's locked section. The real add paths
        // (add_account_password, finish_oauth) hold account_lifecycle across
        // insert + credential store; they can't run here because
        // test_connection needs a real TLS IMAP handshake, so this spawns
        // exactly their locked steps on the same mutex and repo calls.
        let add = {
            let core = core.clone();
            tokio::spawn(async move {
                let _lifecycle = core.account_lifecycle.lock().await;
                let id = core
                    .db
                    .write(|conn| {
                        repo::accounts::insert(
                            conn,
                            &repo::accounts::NewAccount {
                                email: "new@test.dev",
                                display_name: None,
                                provider: Provider::Imap,
                                auth_kind: AuthKind::Password,
                                username: "new",
                                imap_host: "h",
                                imap_port: 993,
                                smtp_host: "h",
                                smtp_port: 587,
                            },
                        )
                    })
                    .await
                    .unwrap();
                credentials::store_async(id, Slot::Password, "newpass".into())
                    .await
                    .unwrap();
                // A vector on a recycled message id of the new account.
                core.embed
                    .index
                    .write()
                    .await
                    .push(old_mid, 0, &[0.0, 1.0, 0.0]);
                id
            })
        };
        // Let the add reach its lock wait, then release the removal: purge
        // and eviction run while the lock is still held.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        REMOVE_RESUME_GATE.notify_one();
        spawned.await.unwrap().unwrap();
        let new_id = add.await.unwrap();
        assert_eq!(new_id, 1, "the add must recycle the removed account's id");
        // ...so the purge could only have deleted the OLD credentials; the
        // new account's password - stored after the lock released - is intact.
        assert_eq!(
            credentials::load_async(1, Slot::Password).await.unwrap(),
            "newpass"
        );
        // And the vector pushed on the recycled message id survived the
        // removal's eviction, which ran before the add could even insert.
        let hits = {
            let idx = core.embed.index.read().await;
            idx.search(&[0.0, 1.0, 0.0], 5)
        };
        assert_eq!(
            hits.iter().map(|h| h.0).collect::<Vec<_>>(),
            vec![old_mid],
            "the recycled-id vector must survive; the old one was evicted"
        );
    }
}

#[cfg(test)]
mod ai_model_routing_tests {
    use super::*;

    #[test]
    fn blank_tier_falls_back_to_legacy_model() {
        let mut s = Settings::default();
        s.ai_model = "legacy".into();
        // Tiers default (ask/draft=intelligent, summarize=instant, voice=cheap)
        // but no tier model is set, so every scenario uses the legacy model.
        for sc in [
            Scenario::Ask,
            Scenario::Draft,
            Scenario::Summarize,
            Scenario::Voice,
        ] {
            assert_eq!(resolve_ai_model(&s, sc), "legacy");
        }
    }

    #[test]
    fn each_scenario_uses_its_tier_model() {
        let mut s = Settings::default();
        s.ai_model = "legacy".into();
        s.ai_model_instant = "fast".into();
        s.ai_model_cheap = "mid".into();
        s.ai_model_intelligent = "smart".into();
        // Defaults: ask/draft -> intelligent, summarize -> instant, voice -> cheap.
        assert_eq!(resolve_ai_model(&s, Scenario::Ask), "smart");
        assert_eq!(resolve_ai_model(&s, Scenario::Draft), "smart");
        assert_eq!(resolve_ai_model(&s, Scenario::Summarize), "fast");
        assert_eq!(resolve_ai_model(&s, Scenario::Voice), "mid");
    }

    #[test]
    fn scenario_can_be_repointed_to_another_tier() {
        let mut s = Settings::default();
        s.ai_model = "legacy".into();
        s.ai_model_instant = "fast".into();
        s.ai_tier_ask = "instant".into(); // route Ask to the instant tier
        assert_eq!(resolve_ai_model(&s, Scenario::Ask), "fast");
    }
}

#[cfg(test)]
mod attachment_ext_tests {
    use super::*;

    #[test]
    fn calendar_mime_maps_to_ics() {
        assert_eq!(ext_for_mime("text/calendar"), Some("ics"));
        // MIME parameters (e.g. method=REQUEST) and casing are tolerated.
        assert_eq!(ext_for_mime("text/calendar; method=REQUEST"), Some("ics"));
        assert_eq!(ext_for_mime("TEXT/CALENDAR"), Some("ics"));
    }

    #[test]
    fn unknown_mime_has_no_extension() {
        assert_eq!(ext_for_mime("application/x-unknown"), None);
    }

    #[test]
    fn safe_filename_strips_bidi_controls() {
        // Right-to-left override disguising an app as a PDF.
        assert_eq!(safe_filename("invoice\u{202E}fdp.app"), "invoicefdp.app");
        let every = "a\u{061C}\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\
                     \u{2066}\u{2067}\u{2068}\u{2069}b.txt";
        assert_eq!(safe_filename(every), "ab.txt");
        // Removing them can't expose a leading dot or leave an empty name.
        assert_eq!(safe_filename("\u{202E}.hidden"), "hidden");
        assert_eq!(safe_filename("\u{202E}\u{2066}"), "attachment");
    }

    #[test]
    fn safe_filename_blocks_traversal_and_controls() {
        assert_eq!(safe_filename("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(safe_filename("a\\b\0c\nd.pdf"), "a_b_c_d.pdf");
        assert_eq!(safe_filename(" .. "), "attachment");
        assert_eq!(safe_filename("résumé 2026.pdf"), "résumé 2026.pdf");
        assert_eq!(safe_filename(&"x".repeat(300)).chars().count(), 200);
    }

    #[test]
    fn safe_filename_stays_inside_the_attachment_dir_on_windows() {
        // Drive-relative names would replace the base directory on join.
        assert_eq!(safe_filename("C:evil.dll"), "C_evil.dll");
        assert_eq!(safe_filename("a:b.txt"), "a_b.txt");
        assert_eq!(safe_filename("x<y>z|w?v*u\"t.pdf"), "x_y_z_w_v_u_t.pdf");
        let dir = std::path::Path::new("attachments").join("42");
        for name in ["C:evil.dll", "D:", "\\\\server\\share\\x", "/etc/passwd"] {
            let path = dir.join(safe_filename(name));
            assert_eq!(path.parent(), Some(dir.as_path()), "{name}");
        }
    }

    #[test]
    fn safe_filename_avoids_windows_device_names() {
        assert_eq!(safe_filename("CON"), "_CON");
        assert_eq!(safe_filename("con.pdf"), "_con.pdf");
        assert_eq!(safe_filename("LPT1.txt"), "_LPT1.txt");
        assert_eq!(safe_filename("COM¹.txt"), "_COM¹.txt");
        assert_eq!(safe_filename("CONTRACT.pdf"), "CONTRACT.pdf");
        assert_eq!(safe_filename("COM10.txt"), "COM10.txt");
        // Truncation can't leave a trailing dot or space behind.
        let long = format!("{}. tail", "x".repeat(199));
        assert_eq!(safe_filename(&long), "x".repeat(199));
    }

    #[test]
    fn display_filename_strips_bidi_controls() {
        assert_eq!(display_filename("invoice\u{202E}fdp.app"), "invoicefdp.app");
        assert_eq!(display_filename("résumé.pdf"), "résumé.pdf");
    }
}
