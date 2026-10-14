// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Trade8:Risk
// SPDX-License-Identifier: Apache-2.0

//! Risk DB persistence — snapshot bootstrap + limit/trader-state writes
//! with `limit:updated` / `trader:state` outbox events.
//!
//! The authorize hot path never touches the DB (arc-swap snapshot); this
//! module feeds the snapshot at startup and publishes writes through the
//! outbox so consumers invalidate their caches (risk design §4).

use sqlx::PgConnection;
use trade8::contracts::risk::LimitRow;
use trade8::contracts::{events, RiskLimitKind, TraderState};
use uuid::Uuid;

use crate::core::RiskSnapshot;

fn kind_str(k: RiskLimitKind) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "buying_power".into())
}

fn kind_from(s: &str) -> RiskLimitKind {
    match s {
        "buying_power" => RiskLimitKind::BuyingPower,
        "max_order_shares" => RiskLimitKind::MaxOrderShares,
        "max_position_shares" => RiskLimitKind::MaxPositionShares,
        "max_position_value" => RiskLimitKind::MaxPositionValue,
        "max_open_orders" => RiskLimitKind::MaxOpenOrders,
        "max_notional" => RiskLimitKind::MaxNotional,
        _ => RiskLimitKind::BuyingPower,
    }
}

fn trader_state_str(s: TraderState) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "active".into())
}

fn trader_state_from(s: &str) -> TraderState {
    match s {
        "closing_only" => TraderState::ClosingOnly,
        "disabled_by_risk" => TraderState::DisabledByRisk,
        "disabled_by_compliance" => TraderState::DisabledByCompliance,
        "disabled" => TraderState::Disabled,
        "inactive" => TraderState::Inactive,
        _ => TraderState::Active,
    }
}

/// Snapshot bootstrap: limits + trader states + allowed symbols +
/// blocked symbols/destinations from the restriction tables.
/// Logged-not-fatal — an empty snapshot authorizes nothing extra.
pub async fn bootstrap_snapshot(conn: &mut PgConnection, env_id: Uuid) -> RiskSnapshot {
    match bootstrap_inner(conn, env_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "trade8:risk: snapshot bootstrap failed (empty)");
            RiskSnapshot::default()
        }
    }
}

async fn bootstrap_inner(conn: &mut PgConnection, env_id: Uuid) -> anyhow::Result<RiskSnapshot> {
    sentin8::shell::set_tenant_context(conn, env_id).await;
    let mut snap = RiskSnapshot::default();

    // Limits.
    type LimitTuple = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        i64,
        Option<i64>,
        bool,
    );
    let limits: Vec<LimitTuple> = sqlx::query_as(
        r#"SELECT usr_id, office_id, asset_class, currency, kind,
                      value, override_value, disabled
               FROM risk.limit WHERE env_id = $1 AND NOT disabled"#,
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await?;
    snap.limits = limits
        .into_iter()
        .map(
            |(usr_id, office_id, asset_class, currency, kind, value, override_value, disabled)| {
                LimitRow {
                    usr_id,
                    office_id,
                    asset_class,
                    currency,
                    kind: kind_from(&kind),
                    value: value as i128,
                    override_value: override_value.map(|v| v as i128),
                    disabled,
                }
            },
        )
        .collect();

    // Trader states.
    let states: Vec<(String, String)> =
        sqlx::query_as(r#"SELECT usr_id, state FROM risk.trader_state WHERE env_id = $1"#)
            .bind(env_id)
            .fetch_all(&mut *conn)
            .await?;
    for (usr, state) in states {
        snap.trader_states.insert(usr, trader_state_from(&state));
    }

    // Allowed symbols (per-user allowlists).
    let allowed: Vec<(String, Uuid)> =
        sqlx::query_as(r#"SELECT usr_id, symbol_id FROM risk.allowed_symbol WHERE env_id = $1"#)
            .bind(env_id)
            .fetch_all(&mut *conn)
            .await?;
    for (usr, sym) in allowed {
        snap.allowed_symbols.entry(usr).or_default().insert(sym);
    }

    // Restrictions → blocked symbols/destinations/markets + cancel-denial
    // + per-destination order-type/TIF allowlists.
    type RestrictionTuple = (
        String,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
        Option<String>,
    );
    let blocked: Vec<RestrictionTuple> = sqlx::query_as(
        r#"SELECT restriction, symbol_id, destination_id, market_id,
                      level_id, value
               FROM risk.execution_restriction
               WHERE env_id = $1 AND NOT disabled"#,
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await?;
    for (restriction, symbol_id, destination_id, market_id, level_id, value) in blocked {
        match restriction.as_str() {
            "blocked_symbol" => {
                if let Some(s) = symbol_id {
                    snap.blocked_symbols.insert(s);
                }
            }
            "blocked_destination" => {
                if let Some(d) = destination_id {
                    snap.blocked_destinations.insert(d);
                }
            }
            "blocked_market" => {
                if let Some(m) = market_id {
                    snap.blocked_markets.insert(m);
                }
            }
            "cancel_denial" => {
                // level_id carries the scope key ("*" for env-wide).
                snap.cancel_denial
                    .insert(level_id.unwrap_or_else(|| "*".into()));
            }
            "allowed_order_types" => {
                if let (Some(d), Some(v)) = (destination_id, value) {
                    let set = snap.dest_order_types.entry(d).or_default();
                    for t in v.split(',') {
                        set.insert(t.trim().to_string());
                    }
                }
            }
            "allowed_tifs" => {
                if let (Some(d), Some(v)) = (destination_id, value) {
                    let set = snap.dest_tifs.entry(d).or_default();
                    for t in v.split(',') {
                        set.insert(t.trim().to_string());
                    }
                }
            }
            _ => {}
        }
    }

    // Uptick rule mode per market (restriction value 'u'|'m'|'d').
    let uptick: Vec<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        r#"SELECT market_id, value FROM risk.execution_restriction
           WHERE env_id = $1 AND NOT disabled AND restriction = 'uptick_rule'"#,
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await?;
    for (market_id, value) in uptick {
        if let Some(m) = market_id {
            let mode = match value.as_deref() {
                Some("u") => b'u',
                Some("m") => b'm',
                _ => b'd',
            };
            snap.uptick_rule.insert(m, mode);
        }
    }

    // Short-exempt symbols.
    let exempt: Vec<(Uuid,)> =
        sqlx::query_as(r#"SELECT symbol_id FROM desk.short_exempt WHERE env_id = $1"#)
            .bind(env_id)
            .fetch_all(&mut *conn)
            .await?;
    for (s,) in exempt {
        snap.short_exempt.insert(s);
    }

    Ok(snap)
}

/// Persist a new limit row + `limit:updated` outbox event (same tx).
pub async fn persist_limit(
    conn: &mut PgConnection,
    env_id: Uuid,
    row: &LimitRow,
    actor: &str,
) -> Result<Uuid, sqlx::Error> {
    // context is transaction-local: set it on the executor this fn receives (DESIGN.md §5).
    sentin8::shell::set_tenant_context(conn, env_id).await;
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO risk.limit
           (id, env_id, usr_id, office_id, asset_class, currency, kind, value, override_value, disabled)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
    )
    .bind(id)
    .bind(env_id)
    .bind(&row.usr_id)
    .bind(&row.office_id)
    .bind(&row.asset_class)
    .bind(&row.currency)
    .bind(kind_str(row.kind))
    .bind(row.value as i64)
    .bind(row.override_value.map(|v| v as i64))
    .bind(row.disabled)
    .execute(&mut *conn)
    .await?;
    insert_outbox_event(
        conn,
        env_id,
        events::RISK_LIMIT_UPDATED,
        serde_json::json!({"id": id, "kind": kind_str(row.kind), "usr_id": row.usr_id,
                           "office_id": row.office_id, "value": row.value, "by": actor}),
    )
    .await?;
    Ok(id)
}

/// Persist a trader-state change + `trader:state` outbox event (same tx).
pub async fn persist_trader_state(
    conn: &mut PgConnection,
    env_id: Uuid,
    usr_id: &str,
    state: TraderState,
    reason: Option<&str>,
    set_by: &str,
) -> Result<(), sqlx::Error> {
    // context is transaction-local: set it on the executor this fn receives (DESIGN.md §5).
    sentin8::shell::set_tenant_context(conn, env_id).await;
    sqlx::query(
        r#"INSERT INTO risk.trader_state (env_id, usr_id, state, reason, set_by)
           VALUES ($1,$2,$3,$4,$5)
           ON CONFLICT (env_id, usr_id) DO UPDATE SET
             state = EXCLUDED.state, reason = EXCLUDED.reason,
             set_by = EXCLUDED.set_by, at = now()"#,
    )
    .bind(env_id)
    .bind(usr_id)
    .bind(trader_state_str(state))
    .bind(reason)
    .bind(set_by)
    .execute(&mut *conn)
    .await?;
    insert_outbox_event(
        conn,
        env_id,
        events::RISK_TRADER_STATE,
        serde_json::json!({"usr_id": usr_id, "state": trader_state_str(state), "by": set_by}),
    )
    .await
}

/// Outbox event insert — the shell relay drains this to the bus.
async fn insert_outbox_event(
    conn: &mut PgConnection,
    env_id: Uuid,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let row_id =
        sentin8::bus::outbox::insert_outbox_row(&mut *conn, env_id, "risk", event_type, &payload)
            .await
            .map_err(|e| match e {
                sentin8::bus::outbox::OutboxError::Db(db) => db,
                other => sqlx::Error::Configuration(other.to_string().into()),
            })?;
    let _ = row_id;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_wire_strings() {
        assert_eq!(kind_str(RiskLimitKind::BuyingPower), "buying_power");
        assert_eq!(kind_str(RiskLimitKind::MaxOpenOrders), "max_open_orders");
        assert_eq!(
            kind_from("max_position_value"),
            RiskLimitKind::MaxPositionValue
        );
        assert_eq!(trader_state_str(TraderState::ClosingOnly), "closing_only");
        assert_eq!(
            trader_state_from("disabled_by_risk"),
            TraderState::DisabledByRisk
        );
        assert_eq!(trader_state_from("active"), TraderState::Active);
    }
}
