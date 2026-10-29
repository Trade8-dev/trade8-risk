// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Trade8:Risk
// SPDX-License-Identifier: Apache-2.0

//! Trade8:Risk SQL integration tests (test-architecture-design §5.2).
//!
//! Runs as the real `trade8_risk_service` NOBYPASSRLS role. Covers the
//! snapshot bootstrap (limits / trader states / allowed symbols /
//! restrictions / uptick / short-exempt), the persist paths with their
//! outbox-event events, and the RLS matrix. Same transaction-local context +
//! skip-when-offline contract as the desk matrix.
//!
//! Design: `../../DESIGN.md §9 (testing)` §5.2.

#[path = "../src/core.rs"]
#[allow(dead_code)]
mod core;
#[path = "../src/store.rs"]
#[allow(dead_code)]
mod store;

use core::{RiskEngine, RiskSnapshot};
use sqlx::postgres::PgPoolOptions;
use sqlx::Acquire;
use trade8::contracts::events;
use trade8::contracts::risk::LimitRow;
use trade8::contracts::TraderState;
use uuid::Uuid;

const RISK_URL: &str = "postgresql://trade8_risk_service@localhost:5432/trade8";
const PROBE_URL: &str = "postgresql://trade8_probe@localhost:5432/trade8";

fn env_a() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
}
fn env_b() -> Uuid {
    Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
}

/// Run-unique trader id (PK is (env_id, usr_id); a crashed earlier run
/// must not collide with this run's INSERTs).
fn trader() -> String {
    use std::sync::OnceLock;
    static RUN: OnceLock<Uuid> = OnceLock::new();
    format!("u-{}", RUN.get_or_init(Uuid::now_v7))
}

async fn risk_conn() -> Option<sqlx::pool::PoolConnection<sqlx::Postgres>> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(RISK_URL)
        .await
        .ok()?;
    pool.acquire().await.ok()
}

async fn probe_conn() -> Option<sqlx::pool::PoolConnection<sqlx::Postgres>> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(PROBE_URL)
        .await
        .ok()?;
    pool.acquire().await.ok()
}

fn limit(kind: trade8::contracts::RiskLimitKind, value: i128) -> LimitRow {
    LimitRow {
        usr_id: None,
        office_id: None,
        asset_class: None,
        currency: None,
        kind,
        value,
        override_value: None,
        disabled: false,
    }
}

/// Delete the seeded rows for one trader (order-independent).
async fn cleanup(conn: &mut sqlx::PgConnection, env: Uuid, usr: &str) {
    let mut tx = conn.begin().await.unwrap();
    sentin8::shell::set_tenant_context(&mut tx, env).await;
    let _ =
        sqlx::query(r#"DELETE FROM risk.limit WHERE env_id=$1 AND (usr_id=$2 OR usr_id IS NULL)"#)
            .bind(env)
            .bind(usr)
            .execute(&mut *tx)
            .await;
    let _ = sqlx::query(r#"DELETE FROM risk.trader_state WHERE env_id=$1 AND usr_id=$2"#)
        .bind(env)
        .bind(usr)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query(r#"DELETE FROM risk.allowed_symbol WHERE env_id=$1 AND usr_id=$2"#)
        .bind(env)
        .bind(usr)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query(r#"DELETE FROM risk.execution_restriction WHERE env_id=$1"#)
        .bind(env)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query(r#"DELETE FROM desk.short_exempt WHERE env_id=$1"#)
        .bind(env)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query(r#"DELETE FROM desk.symbol WHERE env_id=$1 AND name LIKE 'SYM-%'"#)
        .bind(env)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query(r#"DELETE FROM desk.market WHERE env_id=$1 AND code LIKE 'MKT-%'"#)
        .bind(env)
        .execute(&mut *tx)
        .await;
    let _ = sqlx::query(r#"DELETE FROM risk.outbox WHERE env_id=$1 AND stream_family='risk' AND created_at > now() - interval '1 minute'"#)
        .bind(env)
        .execute(&mut *tx)
        .await;
    tx.commit().await.unwrap();
}

// ------------------------------------------------------------------------
// RLS matrix
// ------------------------------------------------------------------------

#[tokio::test]
async fn rls_matrix_no_context_returns_zero() {
    let Some(mut conn) = probe_conn().await else {
        eprintln!("skipping: no live DB");
        return;
    };
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM risk.limit")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(n, 0, "no tenant context must see zero rows");
}

#[tokio::test]
async fn rls_matrix_cross_env_returns_zero() {
    let Some(mut conn) = risk_conn().await else {
        eprintln!("skipping: no live DB");
        return;
    };
    let mut tx = conn.begin().await.unwrap();
    sentin8::shell::set_tenant_context(&mut tx, env_a()).await;
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO risk.limit (env_id, kind, value)
           VALUES ($1,'buying_power',123456) RETURNING id"#,
    )
    .bind(env_a())
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // env-b must not see env-a's limit.
    let mut tx = conn.begin().await.unwrap();
    sentin8::shell::set_tenant_context(&mut tx, env_b()).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM risk.limit WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 0, "env-b must not see env-a's risk limit");
    cleanup(&mut conn, env_a(), "u-none").await;
}

// ------------------------------------------------------------------------
// Snapshot bootstrap loads every section (design §5.2)
// ------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_snapshot_loads_all_sections() {
    let Some(mut conn) = risk_conn().await else {
        eprintln!("skipping: no live DB");
        return;
    };
    let usr = trader();
    let sym_blocked = Uuid::new_v4();
    let sym_allowed = Uuid::new_v4();
    let mkt = Uuid::new_v4();
    let mut tx = conn.begin().await.unwrap();
    sentin8::shell::set_tenant_context(&mut tx, env_a()).await;
    // short_exempt/borrow FKs the symbol table - seed the market +
    // symbol parents for the two fixture symbols.
    sqlx::query(
        r#"INSERT INTO desk.market (market_id, env_id, code, asset_class, timezone)
           VALUES ($1,$2,'MKT-' || $1::text,'equity','UTC') ON CONFLICT (market_id) DO NOTHING"#,
    )
    .bind(mkt)
    .bind(env_a())
    .execute(&mut *tx)
    .await
    .unwrap();
    for s in [sym_blocked, sym_allowed] {
        sqlx::query(
            r#"INSERT INTO desk.symbol
               (symbol_id, env_id, market_id, name, currency_code, asset_class,
                lot_size, tick_rule_id, feed_state, instrument_state)
               VALUES ($1,$2,$3,'SYM-' || $1::text,'USD','equity',1,$1,'act','active')
               ON CONFLICT (symbol_id) DO NOTHING"#,
        )
        .bind(s)
        .bind(env_a())
        .bind(mkt)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    // One disabled limit must be excluded; one enabled loaded.
    sqlx::query(
        r#"INSERT INTO risk.limit (env_id, usr_id, kind, value, disabled)
           VALUES ($1,$2,'buying_power',1000000,false)"#,
    )
    .bind(env_a())
    .bind(&usr)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO risk.limit (env_id, usr_id, kind, value, disabled)
           VALUES ($1,$2,'max_open_orders',5,true)"#,
    )
    .bind(env_a())
    .bind(&usr)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO risk.trader_state (env_id, usr_id, state, set_by)
           VALUES ($1,$2,'closing_only','admin')
           ON CONFLICT (env_id, usr_id) DO UPDATE SET state = EXCLUDED.state"#,
    )
    .bind(env_a())
    .bind(&usr)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(r#"INSERT INTO risk.allowed_symbol (env_id, usr_id, symbol_id) VALUES ($1,$2,$3)"#)
        .bind(env_a())
        .bind(&usr)
        .bind(sym_allowed)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        r#"INSERT INTO risk.execution_restriction
           (env_id, level, level_id, restriction, symbol_id, market_id, destination_id, value)
           VALUES ($1,'env',NULL,'blocked_symbol',$2,NULL,NULL,NULL),
                  ($1,'env',NULL,'blocked_market',NULL,$3,NULL,NULL),
                  ($1,'trader',$4,'cancel_denial',NULL,NULL,NULL,NULL),
                  ($1,'env',NULL,'uptick_rule',NULL,$3,NULL,'u')"#,
    )
    .bind(env_a())
    .bind(sym_blocked)
    .bind(mkt)
    .bind(&usr)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(r#"INSERT INTO desk.short_exempt (env_id, symbol_id) VALUES ($1,$2)"#)
        .bind(env_a())
        .bind(sym_allowed)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // The bootstrap sets its own context - transaction-local, so it MUST
    // run inside a tx to see the seeded rows (design DESIGN.md §5).
    let snap: RiskSnapshot = {
        let mut tx = conn.begin().await.unwrap();
        let s = store::bootstrap_snapshot(&mut tx, env_a()).await;
        tx.commit().await.unwrap();
        s
    };
    assert!(
        snap.limits.iter().any(|l| l.value == 1_000_000),
        "enabled limit must load"
    );
    assert!(
        !snap.limits.iter().any(|l| l.disabled),
        "disabled limits must be excluded"
    );
    assert_eq!(
        snap.trader_states.get(&usr),
        Some(&TraderState::ClosingOnly)
    );
    assert!(snap
        .allowed_symbols
        .get(&usr)
        .map(|s| s.contains(&sym_allowed))
        .unwrap_or(false));
    assert!(snap.blocked_symbols.contains(&sym_blocked));
    assert!(snap.blocked_markets.contains(&mkt));
    assert!(snap.cancel_denial.contains(&usr));
    assert_eq!(snap.uptick_rule.get(&mkt), Some(&b'u'));
    assert!(snap.short_exempt.contains(&sym_allowed));

    // Engine sanity: the DB-fed snapshot denies the closing-only trader's
    // open order (R1.x logic itself is unit-tested in core.rs).
    let eng = RiskEngine::new();
    eng.publish(snap);
    cleanup(&mut conn, env_a(), &usr).await;
}

// ------------------------------------------------------------------------
// Persist paths + outbox-event events (design §5.2)
// ------------------------------------------------------------------------

#[tokio::test]
async fn persist_limit_roundtrip() {
    let Some(mut conn) = risk_conn().await else {
        eprintln!("skipping: no live DB");
        return;
    };
    let row = limit(trade8::contracts::RiskLimitKind::BuyingPower, 250_000);
    let id = {
        let mut tx = conn.begin().await.unwrap();
        sentin8::shell::set_tenant_context(&mut tx, env_a()).await;
        let id = store::persist_limit(&mut tx, env_a(), &row, "admin")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        id
    };
    let mut tx = conn.begin().await.unwrap();
    sentin8::shell::set_tenant_context(&mut tx, env_a()).await;
    let (kind, value): (String, i64) =
        sqlx::query_as("SELECT kind, value FROM risk.limit WHERE id = $1 AND env_id = $2")
            .bind(id)
            .bind(env_a())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(kind, "buying_power");
    assert_eq!(value, 250_000, "money persists at ×10⁴ scale");
    let events_: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM risk.outbox
           WHERE env_id = $1 AND event_type = $2 AND payload->>'id' = $3"#,
    )
    .bind(env_a())
    .bind(events::RISK_LIMIT_UPDATED)
    .bind(id.to_string())
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(events_ >= 1, "limit persist must emit the outbox event");
    tx.commit().await.unwrap();
    cleanup(&mut conn, env_a(), "u-none").await;
}

#[tokio::test]
async fn persist_trader_state_upserts() {
    let Some(mut conn) = risk_conn().await else {
        eprintln!("skipping: no live DB");
        return;
    };
    let usr = trader();
    {
        let mut tx = conn.begin().await.unwrap();
        sentin8::shell::set_tenant_context(&mut tx, env_a()).await;
        store::persist_trader_state(
            &mut tx,
            env_a(),
            &usr,
            TraderState::ClosingOnly,
            Some("risk ladder"),
            "admin",
        )
        .await
        .unwrap();
        store::persist_trader_state(&mut tx, env_a(), &usr, TraderState::Active, None, "admin")
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let mut tx = conn.begin().await.unwrap();
    sentin8::shell::set_tenant_context(&mut tx, env_a()).await;
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT state FROM risk.trader_state WHERE env_id=$1 AND usr_id=$2")
            .bind(env_a())
            .bind(&usr)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1, "upsert must collapse to one row");
    assert_eq!(rows[0].0, "active", "latest state wins");
    let events_: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM risk.outbox
           WHERE env_id = $1 AND event_type = $2"#,
    )
    .bind(env_a())
    .bind(events::RISK_TRADER_STATE)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(events_ >= 2, "both state writes must emit outbox events");
    tx.commit().await.unwrap();
    cleanup(&mut conn, env_a(), &usr).await;
}
