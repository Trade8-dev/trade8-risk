// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Trade8:Risk
// SPDX-License-Identifier: Apache-2.0

//! Trade8:Risk admin UI - RFW page definitions + data endpoints.
//!
//! Pages at `GET /v1/admin/ui/{page}` rendered by Sentin8:Dash. The
//! trader-state board is step-up-auth-gated at the BFF; here the
//! `trade8:risk:trader:state:write` scope holds for mutations.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use sentin8::rfw::page::AdminPage;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;

use crate::RiskState;

fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}
fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}
fn table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 25,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions: vec![],
    })
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    responses(
        (status = 200, description = "OK", body = sentin8::rfw::AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "trade8-admin",
)]

/// `GET /v1/admin/ui/{page}` - RFW definitions.
pub async fn get_admin_ui(
    State(_st): State<std::sync::Arc<RiskState>>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    let _a = sentin8::shell::verify_token(&_st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &_st.core.admin.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:limits:read"),
    )
    .await?;
    let def = match page.as_str() {
        "limits" => AdminPage::new("Risk Limits")
            .widget(table(
                vec![
                    cols("usr_id", "Trader"),
                    cols("office_id", "Office"),
                    cols("kind", "Kind"),
                    cols("value", "Value"),
                    cols("override_value", "Override"),
                    cols("disabled", "Disabled"),
                ],
                "/v1/admin/limits",
            ))
            .build(),
        "traders" => AdminPage::new("Trader State Board")
            .widget(card(
                "Trader States",
                "Step-up auth required at the BFF for state changes; this board shows current states.",
            ))
            .widget(table(
                vec![
                    cols("usr_id", "Trader"),
                    cols("state", "State"),
                    cols("reason", "Reason"),
                    cols("set_by", "Set By"),
                    cols("at", "At"),
                ],
                "/v1/admin/traders",
            ))
            .build(),
        "restrictions" => AdminPage::new("Restrictions")
            .widget(table(
                vec![
                    cols("level", "Level"),
                    cols("level_id", "Scope"),
                    cols("restriction", "Restriction"),
                    cols("symbol_id", "Symbol"),
                    cols("destination_id", "Destination"),
                    cols("disabled", "Disabled"),
                ],
                "/v1/admin/restrictions",
            ))
            .build(),
        "levels" => AdminPage::new("Risk Level Ladder")
            .widget(table(
                vec![
                    cols("level_id", "Level"),
                    cols("threshold", "Day-Net Loss Trigger"),
                    cols("actions", "Actions"),
                ],
                "/v1/admin/levels",
            ))
            .build(),
        "exposure" => AdminPage::new("Live Exposure")
            .widget(card(
                "Exposure",
                "Reserved notional, open orders, and positions vs limits from the current snapshot.",
            ))
            .widget(table(
                vec![
                    cols("usr_id", "Trader"),
                    col("reserved_notional", "Reserved Notional"),
                    col("open_orders", "Open Orders"),
                ],
                "/v1/admin/exposure",
            ))
            .build(),
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };
    Ok(Json(AdminUiResponse::page(def)))
}

type Qp = std::collections::HashMap<String, String>;
#[utoipa::path(
    get,
    path = "/v1/admin/limits",
    responses(
        (status = 200, description = "Admin rows", body = Vec<serde_json::Value>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "trade8-admin",
)]

/// `GET /v1/admin/limits` - limit rows from the DB (source of truth).
pub async fn admin_limits(
    State(st): State<std::sync::Arc<RiskState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (axum::http::StatusCode, String)> {
    let a = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:limits:read"),
    )
    .await?;
    let env = a.env_id();
    let mut conn = st
        .core
        .pool
        .acquire()
        .await
        .map_err(sentin8::shell::err_db)?;
    sentin8::shell::set_tenant_context(&mut conn, env).await;
    type AdminLimitRow = (
        Option<String>,
        Option<String>,
        String,
        i64,
        Option<i64>,
        bool,
    );
    let rows: Vec<AdminLimitRow> = sqlx::query_as(
        r#"SELECT usr_id, office_id, kind, value, override_value, disabled
           FROM risk.limit WHERE env_id = $1 ORDER BY kind, usr_id NULLS LAST"#,
    )
    .bind(env)
    .fetch_all(&mut *conn)
    .await
    .map_err(sentin8::shell::err_db)?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(usr_id, office_id, kind, value, override_value, disabled)| {
                    serde_json::json!({
                        "usr_id": usr_id, "office_id": office_id, "kind": kind,
                        "value": value, "override_value": override_value, "disabled": disabled,
                    })
                },
            )
            .collect::<Vec<_>>(),
    ))
}
#[utoipa::path(
    get,
    path = "/v1/admin/traders",
    responses(
        (status = 200, description = "Admin rows", body = Vec<serde_json::Value>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "trade8-admin",
)]

/// `GET /v1/admin/traders` - trader risk states.
pub async fn admin_traders(
    State(st): State<std::sync::Arc<RiskState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (axum::http::StatusCode, String)> {
    let a = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:limits:read"),
    )
    .await?;
    let env = a.env_id();
    let mut conn = st
        .core
        .pool
        .acquire()
        .await
        .map_err(sentin8::shell::err_db)?;
    sentin8::shell::set_tenant_context(&mut conn, env).await;
    type AdminTraderRow = (
        String,
        String,
        Option<String>,
        String,
        chrono::DateTime<chrono::Utc>,
    );
    let rows: Vec<AdminTraderRow> = sqlx::query_as(
        r#"SELECT usr_id, state, reason, set_by, at
               FROM risk.trader_state WHERE env_id = $1 ORDER BY usr_id"#,
    )
    .bind(env)
    .fetch_all(&mut *conn)
    .await
    .map_err(sentin8::shell::err_db)?;
    Ok(Json(
        rows.into_iter()
            .map(|(usr_id, state, reason, set_by, at)| {
                serde_json::json!({
                    "usr_id": usr_id, "state": state, "reason": reason,
                    "set_by": set_by, "at": at,
                })
            })
            .collect::<Vec<_>>(),
    ))
}
#[utoipa::path(
    get,
    path = "/v1/admin/restrictions",
    responses(
        (status = 200, description = "Admin rows", body = Vec<serde_json::Value>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "trade8-admin",
)]

/// `GET /v1/admin/restrictions` - execution restriction rows.
pub async fn admin_restrictions(
    State(st): State<std::sync::Arc<RiskState>>,
    headers: HeaderMap,
    Query(q): Query<Qp>,
) -> Result<Json<Vec<serde_json::Value>>, (axum::http::StatusCode, String)> {
    let a = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:limits:read"),
    )
    .await?;
    let env = a.env_id();
    let limit = q
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(200)
        .min(1000);
    let mut conn = st
        .core
        .pool
        .acquire()
        .await
        .map_err(sentin8::shell::err_db)?;
    sentin8::shell::set_tenant_context(&mut conn, env).await;
    type AdminRestrictionRow = (
        String,
        Option<String>,
        String,
        Option<uuid::Uuid>,
        Option<uuid::Uuid>,
        bool,
    );
    let rows: Vec<AdminRestrictionRow> = sqlx::query_as(
        r#"SELECT level, level_id, restriction, symbol_id, destination_id, disabled
               FROM risk.execution_restriction WHERE env_id = $1
               ORDER BY restriction LIMIT $2"#,
    )
    .bind(env)
    .bind(limit)
    .fetch_all(&mut *conn)
    .await
    .map_err(sentin8::shell::err_db)?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(level, level_id, restriction, symbol_id, destination_id, disabled)| {
                    serde_json::json!({
                        "level": level, "level_id": level_id, "restriction": restriction,
                        "symbol_id": symbol_id, "destination_id": destination_id,
                        "disabled": disabled,
                    })
                },
            )
            .collect::<Vec<_>>(),
    ))
}
#[utoipa::path(
    get,
    path = "/v1/admin/levels",
    responses(
        (status = 200, description = "Admin rows", body = Vec<serde_json::Value>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "trade8-admin",
)]

/// `GET /v1/admin/levels` - risk level ladder + actions.
pub async fn admin_levels(
    State(st): State<std::sync::Arc<RiskState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (axum::http::StatusCode, String)> {
    let a = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:limits:read"),
    )
    .await?;
    let env = a.env_id();
    let mut conn = st
        .core
        .pool
        .acquire()
        .await
        .map_err(sentin8::shell::err_db)?;
    sentin8::shell::set_tenant_context(&mut conn, env).await;
    let rows: Vec<(i32, i64, String)> = sqlx::query_as(
        r#"SELECT l.level_id, l.threshold,
                  COALESCE(string_agg(a.action, ',' ORDER BY a.action), '') AS actions
           FROM risk.level l
           LEFT JOIN risk.level_action la ON la.env_id = l.env_id AND la.level_id = l.level_id
           LEFT JOIN risk.action a ON a.env_id = la.env_id AND a.action_id = la.action_id AND a.enabled
           WHERE l.env_id = $1
           GROUP BY l.level_id, l.threshold
           ORDER BY l.level_id"#,
    )
    .bind(env)
    .fetch_all(&mut *conn)
    .await
    .map_err(sentin8::shell::err_db)?;
    Ok(Json(
        rows.into_iter()
            .map(|(level_id, threshold, actions)| {
                serde_json::json!({
                    "level_id": level_id, "threshold": threshold,
                    "actions": actions.split(',').collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>(),
    ))
}
#[utoipa::path(
    get,
    path = "/v1/admin/exposure",
    responses(
        (status = 200, description = "Admin rows", body = Vec<serde_json::Value>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "trade8-admin",
)]

/// `GET /v1/admin/exposure` - snapshot live exposure.
pub async fn admin_exposure(
    State(st): State<std::sync::Arc<RiskState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (axum::http::StatusCode, String)> {
    let _a = sentin8::shell::verify_token(&st.core.config, &headers).await?;
    sentin8::shell::policy::require(
        &st.core.admin.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("trade8:risk:limits:read"),
    )
    .await?;
    let snap = st.engine.current();
    let mut traders: Vec<String> = snap.reserved_notional.keys().cloned().collect();
    traders.extend(snap.open_orders.keys().cloned());
    traders.sort();
    traders.dedup();
    let rows: Vec<_> = traders
        .into_iter()
        .map(|usr| {
            serde_json::json!({
                "usr_id": usr,
                "reserved_notional": snap.reserved_notional.get(&usr).copied().unwrap_or(0),
                "open_orders": snap.open_orders.get(&usr).copied().unwrap_or(0),
            })
        })
        .collect();
    Ok(Json(rows))
}
