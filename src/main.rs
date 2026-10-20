// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Trade8:Risk
// SPDX-License-Identifier: Apache-2.0

//! Trade8:Risk service binary - synchronous pre-trade authorization gate.
//!
//! Design: `../risk/DESIGN.md`.
//! Core logic in `core.rs`; this shell wires the tokio HTTP/TLS surface.

#![allow(dead_code)]

mod admin_ui;
mod consumers;
mod core;
mod openapi;
mod registration;
mod store;

use sqlx::Acquire;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};

use trade8::contracts::risk::AuthorizeRequest;
use trade8::contracts::TraderState;

/// Service state.
pub struct RiskState {
    pub core: sentin8::shell::ServiceCore,
    pub engine: std::sync::Arc<core::RiskEngine>,
}

fn extend_router(app: Router<Arc<RiskState>>, _state: Arc<RiskState>) -> Router<Arc<RiskState>> {
    app.route("/v1/authorize", post(authorize))
        .route("/v1/trader-state", get(trader_state).post(set_trader_state))
        .route("/v1/trader-state/{usr_id}", get(trader_state_one))
        .route("/v1/limits", get(list_limits).post(create_limit))
        // Admin RFW pages.
        .route("/v1/admin/ui/{*page}", get(admin_ui::get_admin_ui))
        // ── Shield policy-admin API (shared
        // implementation; handlers generic over this state via HasPolicyAdmin).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<Arc<RiskState>>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<Arc<RiskState>>)
                .put(sentin8::shield::admin::put_policy_set::<Arc<RiskState>>)
                .delete(sentin8::shield::admin::delete_policy_set::<Arc<RiskState>>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<Arc<RiskState>>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<Arc<RiskState>>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<Arc<RiskState>>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<Arc<RiskState>>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<Arc<RiskState>>)
                .put(sentin8::shield::admin::put_relation::<Arc<RiskState>>)
                .delete(sentin8::shield::admin::delete_relation::<Arc<RiskState>>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<Arc<RiskState>>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<Arc<RiskState>>)
                .put(sentin8::shield::admin::put_attribute::<Arc<RiskState>>)
                .delete(sentin8::shield::admin::delete_attribute::<Arc<RiskState>>),
        )
        .route("/v1/admin/limits", get(admin_ui::admin_limits))
        .route("/v1/admin/traders", get(admin_ui::admin_traders))
        .route("/v1/admin/restrictions", get(admin_ui::admin_restrictions))
        .route("/v1/admin/levels", get(admin_ui::admin_levels))
        .route("/v1/admin/exposure", get(admin_ui::admin_exposure))
        .route(
            "/v1/health",
            // Carries the binary's build identity (`version`/`build`,
            // BUILDID-1) so captain's monitor populates `make status`'s
            // VERSION column - the consuming BINARY's identity.
            get(|| async { Json(serde_json::json!({"status": "ok", "service": "trade8:risk", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash()})) }),
        )
}
// ── Typed response DTOs (OAPEC-9) ──────────────────────────────────────

/// Liveness/build identity (OAPEC-9 typed body).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct HealthInfo {
    /// Always `ok` while serving.
    pub status: String,
    /// The service identifier.
    pub service: String,
    /// The build version.
    pub version: String,
    /// The build hash.
    pub build: String,
}

/// One trader-state row.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct TraderStateRow {
    /// The trader principal.
    pub usr_id: String,
    /// The state document.
    pub state: trade8::contracts::TraderState,
}

/// All trader states.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct TraderStatesResponse {
    /// The trader rows.
    pub traders: Vec<TraderStateRow>,
}

/// One trader state read.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct TraderStateResponse {
    /// The trader principal.
    pub usr_id: String,
    /// The state.
    pub state: trade8::contracts::TraderState,
}

/// Set-state request.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct SetTraderStateRequest {
    /// The trader.
    pub usr_id: String,
    /// The new state.
    pub state: trade8::contracts::TraderState,
    /// Manual comment (audit only).
    #[serde(default)]
    pub reason: Option<String>,
}

/// Limits envelope.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct LimitsResponse {
    /// The configured limits.
    pub limits: Vec<trade8::contracts::risk::LimitRow>,
}

/// Limits mutation ack.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CreateLimitAck {
    /// The created limit id.
    pub id: uuid::Uuid,
    /// Always `ok`.
    pub status: String,
}

#[utoipa::path(
    post,
    path = "/v1/authorize",
    request_body = trade8::contracts::risk::AuthorizeRequest,
    responses(
        (status = 200, description = "Authorization verdict", body = trade8::contracts::risk::AuthorizeVerdict),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "risk",
)]

/// The hot-path authorize call. M2M-only (Desk / Func) - the BFF does not
/// proxy this route; scope check enforces the service scope.
pub(crate) async fn authorize(
    State(st): State<Arc<RiskState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AuthorizeRequest>,
) -> Result<Json<trade8::contracts::risk::AuthorizeVerdict>, (axum::http::StatusCode, String)> {
    let _a = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:authorize"),
    )
    .await?;
    let verdict = st.engine.authorize(&req);
    Ok(Json(verdict))
}
#[utoipa::path(
    get,
    path = "/v1/trader-state",
    responses(
        (status = 200, description = "Trader states", body = TraderStatesResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "risk",
)]

pub(crate) async fn trader_state(
    State(st): State<Arc<RiskState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<TraderStatesResponse>, (axum::http::StatusCode, String)> {
    let _a = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:limits:read"),
    )
    .await?;
    let snap = st.engine.current();
    let traders: Vec<TraderStateRow> = snap
        .trader_states
        .iter()
        .map(|(k, v)| TraderStateRow {
            usr_id: k.clone(),
            state: v.clone(),
        })
        .collect();
    Ok(Json(TraderStatesResponse { traders }))
}

#[utoipa::path(
    get,
    path = "/v1/trader-state/{usr_id}",
    responses(
        (status = 200, description = "Trader state", body = TraderStateResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "risk",
)]
pub(crate) async fn trader_state_one(
    State(st): State<Arc<RiskState>>,
    headers: axum::http::HeaderMap,
    Path(usr_id): Path<String>,
) -> Result<Json<TraderStateResponse>, (axum::http::StatusCode, String)> {
    let _a = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:limits:read"),
    )
    .await?;
    let snap = st.engine.current();
    let state = snap.trader_state(&usr_id);
    Ok(Json(TraderStateResponse { usr_id, state }))
}

#[utoipa::path(
    post,
    path = "/v1/trader-state",
    responses(
        (status = 200, description = "State set", body = TraderStateResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "risk",
)]
pub(crate) async fn set_trader_state(
    State(st): State<Arc<RiskState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SetTraderStateRequest>,
) -> Result<Json<TraderStateResponse>, (axum::http::StatusCode, String)> {
    let auth = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:trader:state:write"),
    )
    .await?;
    let env = auth.env_id();
    let usr = body.usr_id.as_str();
    let state: TraderState = body.state;
    let reason = body.reason.as_deref();
    // DB write + outbox event, then the snapshot swap (DESIGN.md §2).
    let mut conn = st
        .core
        .pool
        .acquire()
        .await
        .map_err(sentin8::shell::err_db)?;
    sentin8::shell::set_tenant_context(&mut conn, env).await;
    // RLS context is transaction-local (DESIGN.md §5) -
    // begin() pins the tenant context to the SAME tx as the DML/reads.
    let mut tx = match conn.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "risk: tenant tx begin failed");
            return Err(sentin8::shell::err_db(e));
        }
    };
    store::persist_trader_state(&mut tx, env, usr, state, reason, &auth.claims.sub)
        .await
        .map_err(sentin8::shell::err_db)?;
    let mut snap = (*st.engine.current()).clone();
    snap.trader_states.insert(usr.to_string(), state);
    st.engine.publish(snap);
    tracing::info!(usr, ?state, actor = %auth.claims.sub, "trader state changed");
    tx.commit().await.ok(); // dropping an uncommitted tx rolls back
    Ok(Json(TraderStateResponse {
        usr_id: usr.to_string(),
        state,
    }))
}
#[utoipa::path(
    get,
    path = "/v1/limits",
    responses(
        (status = 200, description = "Configured limits", body = LimitsResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "risk",
)]

pub(crate) async fn list_limits(
    State(st): State<Arc<RiskState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<LimitsResponse>, (axum::http::StatusCode, String)> {
    let _a = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:limits:read"),
    )
    .await?;
    let snap = st.engine.current();
    Ok(Json(LimitsResponse {
        limits: snap.limits.clone(),
    }))
}
#[utoipa::path(
    post,
    path = "/v1/limits",
    request_body = trade8::contracts::risk::LimitRow,
    responses(
        (status = 200, description = "Limit created", body = CreateLimitAck),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "risk",
)]

pub(crate) async fn create_limit(
    State(st): State<Arc<RiskState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<trade8::contracts::risk::LimitRow>,
) -> Result<Json<CreateLimitAck>, (axum::http::StatusCode, String)> {
    let auth = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:limits:write"),
    )
    .await?;
    let env = auth.env_id();
    // DB write + `limit:updated` outbox event, then the snapshot swap (DESIGN.md §2).
    let mut conn = st
        .core
        .pool
        .acquire()
        .await
        .map_err(sentin8::shell::err_db)?;
    sentin8::shell::set_tenant_context(&mut conn, env).await;
    // RLS context is transaction-local (DESIGN.md §5) -
    // begin() pins the tenant context to the SAME tx as the DML/reads.
    let mut tx = match conn.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "risk: tenant tx begin failed");
            return Err(sentin8::shell::err_db(e));
        }
    };
    let id = store::persist_limit(&mut tx, env, &body, &auth.claims.sub)
        .await
        .map_err(sentin8::shell::err_db)?;
    let mut snap = (*st.engine.current()).clone();
    snap.limits.push(body);
    st.engine.publish(snap);
    tx.commit().await.ok(); // dropping an uncommitted tx rolls back
    Ok(Json(CreateLimitAck {
        id,
        status: "ok".into(),
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("trade8:risk", "TRADE8_RISK")
            .with_registration(registration::print)
            .with_own_health()
            .with_state(|core| async move {
                let engine = core::RiskEngine::new();
                // Snapshot bootstrap: limits/states/restrictions for
                // the boot env; absent env (local dev) leaves defaults.
                if let Ok(env_slug) = std::env::var("TRADE8_RISK_ENV") {
                    if let Ok(env_id) = uuid::Uuid::parse_str(&env_slug) {
                        let mut conn = core.pool.acquire().await?;
                        let snap = store::bootstrap_snapshot(&mut conn, env_id).await;
                        engine.publish(snap);
                    }
                }
                let engine = std::sync::Arc::new(engine);
                // Bus consumers (risk design §7): desk
                // (reservations/open orders), router (positions), feed
                // (uptick mirror), pnl (ladder). Certificate-presenting
                // Bus clients; each group runs the platform ack/nack loop.
                consumers::spawn_consumers(
                    &core.config.sentin8_bus_url,
                    &core.config.sentin8_auth_issuer,
                    engine.clone(),
                    std::sync::Arc::new(consumers::ReservationJournal::default()),
                );
                Ok(Arc::new(RiskState { core, engine }))
            })
            .with_router(extend_router),
    )
    .await
}

/// Shared policy-admin surface accessor: the shell boot
/// loaded the engine into `core.admin`; the shared handlers extract it via
/// `HasPolicyAdmin` so the admin surface and the request path evaluate the
/// SAME cache.
impl sentin8::shield::admin::HasPolicyAdmin for RiskState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.core.admin
    }
}
