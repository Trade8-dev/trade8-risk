-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Trade8:Risk
-- SPDX-License-Identifier: Apache-2.0

-- Trade8:Risk — pre-trade limits, trader state, restrictions, level ladder.
--
-- Design: ../risk/DESIGN.md §6,
-- ../../DESIGN.md §3 (data model) §2.4.
-- No migration code (new platform): `sentin8-cli vertical init` applies this.

CREATE SCHEMA IF NOT EXISTS risk;

-- ---------------------------------------------------------------------------
--
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS risk.limit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 env_id UUID NOT NULL,
 usr_id TEXT, -- NULL = office/env-level row
 office_id TEXT,
 asset_class TEXT,
 currency TEXT,
 kind TEXT NOT NULL CHECK (kind IN
 ('buying_power','max_order_shares','max_position_shares',
 'max_position_value','max_open_orders','max_notional')),
 value BIGINT NOT NULL, -- shares ×1, money ×10⁴
 override_value BIGINT,
 disabled BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_t8_risklimit_env ON risk.limit (env_id, kind);
CREATE INDEX IF NOT EXISTS idx_t8_risklimit_usr ON risk.limit (env_id, usr_id);

--
-- Risk-owned data, never identity mutation).
CREATE TABLE IF NOT EXISTS risk.trader_state (
 env_id UUID NOT NULL,
 usr_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK (state IN
 ('active','closing_only','disabled_by_risk',
 'disabled_by_compliance','disabled','inactive')),
 reason TEXT,
 set_by TEXT NOT NULL,
 at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (env_id, usr_id)
);

--
CREATE TABLE IF NOT EXISTS risk.execution_restriction (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 env_id UUID NOT NULL,
 level TEXT NOT NULL CHECK (level IN ('trader','office','env')),
 level_id TEXT, -- usr_id or office_id; NULL = env
 restriction TEXT NOT NULL, -- blocked_symbol|blocked_destination|
 -- blocked_market|closing_only|…
 symbol_id UUID,
 market_id UUID,
 destination_id UUID,
 value TEXT,
 disabled BOOLEAN NOT NULL DEFAULT false
);

--
CREATE TABLE IF NOT EXISTS risk.max_orders_restriction (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 env_id UUID NOT NULL,
 level TEXT NOT NULL CHECK (level IN ('trader','office','env')),
 level_id TEXT,
 symbol_id UUID,
 destination_id UUID,
 max_orders INT NOT NULL,
 interval_s INT NOT NULL DEFAULT 60,
 disabled BOOLEAN NOT NULL DEFAULT false
);

--
CREATE TABLE IF NOT EXISTS risk.allowed_symbol (
 env_id UUID NOT NULL,
 usr_id TEXT NOT NULL,
 symbol_id UUID NOT NULL,
 PRIMARY KEY (env_id, usr_id, symbol_id)
);

--
CREATE TABLE IF NOT EXISTS risk.level (
 env_id UUID NOT NULL,
 level_id INT NOT NULL,
 threshold BIGINT NOT NULL, -- day-net loss trigger (×10⁴)
 PRIMARY KEY (env_id, level_id)
);

CREATE TABLE IF NOT EXISTS risk.action (
 env_id UUID NOT NULL,
 action_id INT NOT NULL,
 action TEXT NOT NULL CHECK (action IN
 ('notify','close_only','disable','flatten')),
 enabled BOOLEAN NOT NULL DEFAULT true,
 PRIMARY KEY (env_id, action_id)
);

CREATE TABLE IF NOT EXISTS risk.level_action (
 env_id UUID NOT NULL,
 level_id INT NOT NULL,
 action_id INT NOT NULL,
 PRIMARY KEY (env_id, level_id, action_id)
);

-- ---------------------------------------------------------------------------
-- RLS (architecture-principles.md §4.3)
-- ---------------------------------------------------------------------------
DO $$
DECLARE tbl TEXT;
DECLARE pol TEXT;
BEGIN
 FOREACH tbl IN ARRAY ARRAY[
 'risk.limit', 'risk.trader_state',
 'risk.execution_restriction', 'risk.max_orders_restriction',
 'risk.allowed_symbol', 'risk.level',
 'risk.action', 'risk.level_action'
 ] LOOP
 BEGIN
 pol := replace(split_part(tbl, '.', 2), '"', '');
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
 EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);
 -- Suffix BEFORE %I quoting: `limit` alone is fine but the concatenation
 -- `"limit"_select` is invalid SQL — build 'limit_select' unquoted
 -- (desk-store DO-block memory: reserved-word table names are the
 -- classic failure class).
 EXECUTE format('DROP POLICY IF EXISTS %1$I ON %2$s;
CREATE POLICY %1$I ON %2$s FOR SELECT USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', pol || '_select', tbl);
 EXECUTE format('DROP POLICY IF EXISTS %1$I ON %2$s;
CREATE POLICY %1$I ON %2$s FOR INSERT WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', pol || '_insert', tbl);
 EXECUTE format('DROP POLICY IF EXISTS %1$I ON %2$s;
CREATE POLICY %1$I ON %2$s FOR UPDATE USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', pol || '_update', tbl);
 EXECUTE format('DROP POLICY IF EXISTS %1$I ON %2$s;
CREATE POLICY %1$I ON %2$s FOR DELETE USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', pol || '_delete', tbl);
 EXCEPTION WHEN OTHERS THEN
 RAISE NOTICE 'RLS setup failed for %: %', tbl, SQLERRM;
 END;
 END LOOP;
END $$;

-- Local outbox + audit journal (DBX §6.7 / §6.8 — shell-generated DDL).
CREATE TABLE IF NOT EXISTS risk.outbox (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 env_id UUID NOT NULL,
 event_type TEXT NOT NULL,
 stream_family TEXT NOT NULL,
 payload JSONB NOT NULL,
 publisher_id_token TEXT,
 publisher_subject TEXT,
 relayed BOOLEAN NOT NULL DEFAULT false,
 relayed_at TIMESTAMPTZ,
 relay_attempts INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_outbox_unrelayed
 ON risk.outbox (created_at) WHERE relayed = false;
ALTER TABLE risk.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON risk.outbox;
CREATE POLICY outbox_select ON risk.outbox FOR SELECT
 USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON risk.outbox;
CREATE POLICY outbox_insert ON risk.outbox FOR INSERT
 WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON risk.outbox;
CREATE POLICY outbox_update ON risk.outbox FOR UPDATE
 USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION risk.risk_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
 PERFORM pg_notify('risk_outbox_changed', '');
 RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON risk.outbox;
CREATE TRIGGER outbox_notify_trigger
 AFTER INSERT ON risk.outbox
 FOR EACH ROW
 EXECUTE FUNCTION risk.risk_notify_outbox();

CREATE TABLE IF NOT EXISTS risk.audit_journal (
 id UUID PRIMARY KEY,
 env_id UUID NOT NULL,
 action TEXT NOT NULL,
 target_resource_type TEXT,
 target_resource_id TEXT,
 actor_user_id TEXT,
 actor_subject_type TEXT,
 severity TEXT NOT NULL DEFAULT 'info',
 correlation_id TEXT,
 before_state JSONB,
 after_state JSONB,
 details JSONB,
 pushed BOOLEAN NOT NULL DEFAULT false,
 pushed_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_risk_audit_journal_unpushed
 ON risk.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE risk.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON risk.audit_journal;
CREATE POLICY audit_journal_dml ON risk.audit_journal
 USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
 WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ---------------------------------------------------------------------------
-- Per-service role grants + search_path (bank8-ledger pattern; the CLI
-- creates the role BEFORE this SQL — grant-before-role incident rule).
-- Grants live in db trade8 (this database); the scope→role map row is
-- upserted by `vertical enroll` from --section=pg_roles.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trade8_risk_service') THEN
  ALTER ROLE trade8_risk_service SET search_path = risk, public;
  GRANT USAGE ON SCHEMA risk TO trade8_risk_service;
  GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA risk TO trade8_risk_service;
  GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA risk TO trade8_risk_service;
  ALTER DEFAULT PRIVILEGES FOR ROLE sentin8 IN SCHEMA risk
   GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO trade8_risk_service;
  ALTER DEFAULT PRIVILEGES FOR ROLE sentin8 IN SCHEMA risk
   GRANT USAGE, SELECT ON SEQUENCES TO trade8_risk_service;
 END IF;
END $$;
-- Declared cross-schema reads (SELECT-only) — mirrors registration.rs
-- PgRole.cross_schema_grants; `vertical enroll` owns their application,
-- this block only re-asserts them idempotently after a role recreation.
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trade8_risk_service') THEN
  GRANT USAGE ON SCHEMA desk TO trade8_risk_service;
  GRANT SELECT ON desk.short_exempt TO trade8_risk_service;
 END IF;
END $$;
