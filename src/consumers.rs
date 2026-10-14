// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Trade8:Risk
// SPDX-License-Identifier: Apache-2.0

//! Risk bus consumers — risk design §7.
//!
//! Four consumer groups over `trade8::client::run_consumer`:
//! - **desk** family: `order:accepted/cancelled/rejected/…` → reserved-
//!   notional + open-order accounting (journaled, replayable).
//! - **router** family: `fill:*` → position/share counters (the
//!   position-limit inputs).
//! - **feed** family: `quote:updated`/`trade:printed` → uptick state
//!   mirror (last/prior print per symbol).
//! - **pnl** family: `trader:summary` → risk-level ladder evaluation →
//!   trader-state transitions per the action ladder.
//!
//! All handlers mutate a cloned snapshot and swap it in (arc-swap whole
//! generation — risk design §4). Idempotent: events carry the full
//! envelope; mutations are keyed by (usr, symbol, order id) so
//! redelivery converges.

use std::collections::HashMap;
use std::sync::Arc;

use trade8::client::{BusMessage, HandleOutcome};
use uuid::Uuid;

use crate::core::RiskEngine;

/// Track per-order reservations for release on terminal events — the
/// journaled buying-power accounting (reserved-notional accounting;
/// crash recovery by order-event replay). Shared across consumer tasks.
#[derive(Default)]
pub struct ReservationJournal {
    inner: std::sync::Mutex<JournalInner>,
}

#[derive(Default)]
struct JournalInner {
    /// order_id → (usr_id, notional).
    reserved: HashMap<Uuid, (String, i128)>,
    /// (usr, symbol) → signed net filled shares (position counters).
    positions: HashMap<(String, Uuid), i64>,
    /// symbol → (last_print_raw, prior_print_raw) uptick state.
    prints: HashMap<Uuid, (i128, i128)>,
}

/// Spawn all four consumers. Each runs `run_consumer` forever with its
/// own consumer group (2s reconnect, ack/nack→DLQ per the platform loop).
pub fn spawn_consumers(
    bus_url: &str,
    auth_issuer: &str,
    engine: Arc<RiskEngine>,
    journal: Arc<ReservationJournal>,
) {
    for family in ["desk", "router", "feed", "pnl"] {
        let bus_url = bus_url.to_string();
        let auth_issuer = auth_issuer.to_string();
        let engine = engine.clone();
        let journal = journal.clone();
        let group = format!("trade8:risk:{family}");
        tokio::spawn(async move {
            // Cert-presenting Bus client (CERTFREE-4V): the per-family
            // workload CERTIFICATE is the identity — no DCR, no token;
            // the mint retries while the fleet boots.
            let bus = loop {
                match sentin8::bus::client::BusClient::for_workload(
                    &bus_url,
                    &auth_issuer,
                    &group,
                )
                .await
                {
                    Ok(c) => break c,
                    Err(e) => {
                        tracing::debug!(error = %e, "risk bus client: certificate not ready yet");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
            };
            let bus = Arc::new(bus);
            trade8::client::run_consumer(bus, family, &group, move |msg: BusMessage| {
                let engine = engine.clone();
                let journal = journal.clone();
                async move {
                    let outcome = handle_family(family, msg, &engine, &journal).await;
                    outcome
                }
            })
            .await;
        });
    }
}

async fn handle_family(
    family: &str,
    msg: BusMessage,
    engine: &Arc<RiskEngine>,
    journal: &Arc<ReservationJournal>,
) -> HandleOutcome {
    match family {
        "desk" => handle_desk(msg, engine, journal).await,
        "router" => handle_router(msg, engine, journal).await,
        "feed" => handle_feed(msg, engine, journal).await,
        "pnl" => handle_pnl(msg, engine, journal).await,
        _ => HandleOutcome::Ack,
    }
}

/// Reserved-notional + open-order accounting from Desk lifecycle
/// events. `order:accepted` reserves price×qty; terminal events release.
async fn handle_desk(
    msg: BusMessage,
    engine: &Arc<RiskEngine>,
    journal: &Arc<ReservationJournal>,
) -> HandleOutcome {
    let payload = msg.payload.clone();
    let order_id = payload["order_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok());
    let Some(order_id) = order_id else {
        return HandleOutcome::Ack; // not an order event — nothing to do
    };
    let usr = payload["usr_id"].as_str().unwrap_or_default().to_string();
    let qty = payload["qty"].as_u64().unwrap_or(0) as i128;
    let price = payload["price_raw"]
        .as_i64()
        .or_else(|| {
            payload["price"]
                .as_str()
                .and_then(|p| p.parse::<i64>().ok())
        })
        .map(i128::from);
    match msg.event_type.as_str() {
        "trade8:desk:order:accepted" => {
            // Idempotent: a redelivered accept for an already-reserved
            // order is a no-op (journaled key).
            let notional = price.map(|p| p * qty).unwrap_or(0);
            let mut j = journal.inner.lock().unwrap();
            if !j.reserved.contains_key(&order_id) && !usr.is_empty() {
                j.reserved.insert(order_id, (usr.clone(), notional));
                let mut snap = (*engine.current()).clone();
                *snap.reserved_notional.entry(usr.clone()).or_insert(0) += notional;
                *snap.open_orders.entry(usr).or_insert(0) += 1;
                engine.publish(snap);
            }
        }
        "trade8:desk:order:cancelled"
        | "trade8:desk:order:rejected"
        | "trade8:desk:order:replaced"
        | "trade8:desk:order:routed" => {
            // Terminal-ish states release the reservation + decrement the
            // open-order count (routed stays open at the venue but leaves
            // the Desk book — counts Desk-book orders).
            let released = {
                let mut j = journal.inner.lock().unwrap();
                j.reserved.remove(&order_id)
            };
            if let Some((usr, notional)) = released {
                let mut snap = (*engine.current()).clone();
                *snap.reserved_notional.entry(usr.clone()).or_insert(0) -= notional;
                let open = snap.open_orders.entry(usr).or_insert(0);
                *open = open.saturating_sub(1);
                engine.publish(snap);
            }
        }
        _ => {}
    }
    HandleOutcome::Ack
}

/// Router fills → position counters (the max-position inputs).
async fn handle_router(
    msg: BusMessage,
    _engine: &Arc<RiskEngine>,
    journal: &Arc<ReservationJournal>,
) -> HandleOutcome {
    if msg.event_type != "trade8:router:fill:executed" {
        return HandleOutcome::Ack;
    }
    let p = msg.payload;
    let Some(usr) = p["usr_id"].as_str().map(str::to_string) else {
        return HandleOutcome::Ack;
    };
    let Some(symbol_id) = p["symbol_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return HandleOutcome::Ack;
    };
    let qty = p["qty"].as_i64().unwrap_or(0);
    let buy = p["side"].as_str() == Some("b");
    let delta = if buy { qty } else { -qty };
    let key = (usr, symbol_id);
    let mut j = journal.inner.lock().unwrap();
    *j.positions.entry(key).or_insert(0) += delta;
    HandleOutcome::Ack
}

/// Feed prints → uptick mirror: last/prior print per (usr-agnostic)
/// symbol. The Desk passes its print view; this is the platform mirror.
async fn handle_feed(
    msg: BusMessage,
    engine: &Arc<RiskEngine>,
    journal: &Arc<ReservationJournal>,
) -> HandleOutcome {
    if msg.event_type != "trade8:feed:trade:printed" {
        return HandleOutcome::Ack;
    }
    let p = msg.payload;
    let Some(symbol_id) = p["symbol_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return HandleOutcome::Ack;
    };
    let Some(last) = p["price_raw"]
        .as_i64()
        .or_else(|| p["price"].as_str().and_then(|s| s.parse::<i64>().ok()))
    else {
        return HandleOutcome::Ack;
    };
    let key = symbol_id;
    let mut snap = (*engine.current()).clone();
    let prior = {
        let mut j = journal.inner.lock().unwrap();
        let prior = j.prints.get(&key).map(|(l, _)| *l).unwrap_or(last as i128);
        j.prints.insert(key, (last as i128, prior));
        prior
    };
    // The snapshot carries the mirror for the authorize path.
    snap.prints.insert(symbol_id, (last as i128, prior));
    // Halt mirror: feed_state transitions come through quote updates.
    if let Some(halted) = p["halted"].as_bool() {
        if halted {
            snap.halted_symbols.insert(symbol_id);
        } else {
            snap.halted_symbols.remove(&symbol_id);
        }
    }
    engine.publish(snap);
    HandleOutcome::Ack
}

/// Pnl summaries → risk-level ladder: day-net loss crosses a
/// threshold → fire the ladder actions (notify / close-only / disable /
/// flatten). Close-only/disable transition the trader state (persisted by
/// the risk-level event consumer via the same path as the admin action).
async fn handle_pnl(
    msg: BusMessage,
    engine: &Arc<RiskEngine>,
    journal: &Arc<ReservationJournal>,
) -> HandleOutcome {
    if msg.event_type != "trade8:pnl:trader:summary" {
        return HandleOutcome::Ack;
    }
    let p = msg.payload;
    let Some(usr) = p["usr_id"].as_str().map(str::to_string) else {
        return HandleOutcome::Ack;
    };
    let day_net = p["day_net"].as_i64().unwrap_or(0);
    let _ = journal;
    // The ladder thresholds live in trade8.risk_level; the snapshot does
    // not carry them (they are NOT hot-path data). The engine hook below
    // reads them from the payload's embedded ladder when the Pnl event
    // carries it; otherwise the Cron daily ladder pass owns evaluation.
    if let Some(ladder) = p.get("ladder").and_then(|l| l.as_array()) {
        let mut snap = (*engine.current()).clone();
        for level in ladder {
            let Some(threshold) = level["threshold"].as_i64() else {
                continue;
            };
            // day_net is negative on losses; a loss crossing is
            // day_net <= -threshold.
            if day_net <= -threshold {
                if let Some(action) = level["action"].as_str() {
                    match action {
                        "close_only" => {
                            snap.trader_states
                                .insert(usr.clone(), trade8::contracts::TraderState::ClosingOnly);
                        }
                        "disable" => {
                            snap.trader_states.insert(
                                usr.clone(),
                                trade8::contracts::TraderState::DisabledByRisk,
                            );
                        }
                        _ => {} // notify/flatten are other services' jobs
                    }
                }
            }
        }
        engine.publish(snap);
        tracing::info!(usr = %usr, day_net, "risk: ladder evaluated from pnl summary");
    }
    HandleOutcome::Ack
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(event: &str, payload: serde_json::Value) -> BusMessage {
        BusMessage {
            message_id: "1-1".into(),
            event_type: event.into(),
            env_id: "00000000-0000-0000-0000-000000000001".into(),
            payload,
            correlation_id: String::new(),
            idempotency_key: Some("k".into()),
        }
    }

    #[tokio::test]
    async fn reserved_notional_release_cycle() {
        let engine = Arc::new(RiskEngine::new());
        let journal = Arc::new(ReservationJournal::default());
        let sym = Uuid::new_v4();
        let oid = Uuid::new_v4();
        // Accept: reserve 101_000 × 100 = 10_100_000.
        handle_desk(
            msg(
                "trade8:desk:order:accepted",
                serde_json::json!({"order_id": oid, "usr_id": "u1", "qty": 100, "price_raw": 101_000}),
            ),
            &engine,
            &journal,
        )
        .await;
        assert_eq!(engine.current().reserved_notional["u1"], 10_100_000);
        assert_eq!(engine.current().open_orders["u1"], 1);
        // Cancel: release.
        handle_desk(
            msg(
                "trade8:desk:order:cancelled",
                serde_json::json!({"order_id": oid, "usr_id": "u1"}),
            ),
            &engine,
            &journal,
        )
        .await;
        assert_eq!(engine.current().reserved_notional["u1"], 0);
        assert_eq!(engine.current().open_orders["u1"], 0);
        // Redelivered cancel (at-least-once): converges, no double-release.
        handle_desk(
            msg(
                "trade8:desk:order:cancelled",
                serde_json::json!({"order_id": oid, "usr_id": "u1"}),
            ),
            &engine,
            &journal,
        )
        .await;
        assert_eq!(engine.current().reserved_notional["u1"], 0);
        let _ = sym;
    }

    #[tokio::test]
    async fn ladder_close_only_on_loss() {
        let engine = Arc::new(RiskEngine::new());
        let journal = Arc::new(ReservationJournal::default());
        handle_pnl(
            msg(
                "trade8:pnl:trader:summary",
                serde_json::json!({
                    "usr_id": "u1", "day_net": -50_000,
                    "ladder": [{"threshold": 40_000, "action": "close_only"}],
                }),
            ),
            &engine,
            &journal,
        )
        .await;
        assert_eq!(
            engine.current().trader_state("u1"),
            trade8::contracts::TraderState::ClosingOnly
        );
    }

    #[tokio::test]
    async fn uptick_mirror_tracks_prints() {
        let engine = Arc::new(RiskEngine::new());
        let journal = Arc::new(ReservationJournal::default());
        let sym = Uuid::new_v4();
        handle_feed(
            msg(
                "trade8:feed:trade:printed",
                serde_json::json!({"symbol_id": sym, "price_raw": 100_000}),
            ),
            &engine,
            &journal,
        )
        .await;
        handle_feed(
            msg(
                "trade8:feed:trade:printed",
                serde_json::json!({"symbol_id": sym, "price_raw": 99_000}),
            ),
            &engine,
            &journal,
        )
        .await;
        let (last, prior) = engine.current().prints[&sym];
        assert_eq!(last, 99_000);
        assert_eq!(prior, 100_000);
    }
}
