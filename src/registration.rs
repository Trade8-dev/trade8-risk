// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Trade8:Risk
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Trade8:Risk.
//!
//! Output via `--print-registration` (platform
//! `sentin8-service-self-registration-design.md`). Scopes per master
//! design §9; pages per risk design §8.

use utoipa::OpenApi;

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, CrossSchemaGrant, ErrorCode, M2mGrant, PgRole, PolicySetDecl,
    Registration, RelationDecl, SqlMigration,
};

/// The Shield text of the declared scope-mirror set - public so the
/// policy wiring tests assert against the REAL seed.
pub const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"trade8:risk:authorize\", resource) when { principal.scopes.contains(\"trade8:risk:authorize\") };\npermit(principal, action == Action::\"trade8:risk:authorize\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"trade8:risk:authorize\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"trade8:risk:authorize\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"trade8:risk:limits:read\", resource) when { principal.scopes.contains(\"trade8:pnl:office:read\") };\npermit(principal, action == Action::\"trade8:risk:limits:read\", resource) when { principal.scopes.contains(\"trade8:risk:limits:read\") };\npermit(principal, action == Action::\"trade8:risk:limits:read\", resource) when { principal.scopes.contains(\"trade8:risk:limits:write\") };\npermit(principal, action == Action::\"trade8:risk:limits:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"trade8:risk:limits:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"trade8:risk:limits:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"trade8:risk:limits:write\", resource) when { principal.scopes.contains(\"trade8:risk:limits:write\") };\npermit(principal, action == Action::\"trade8:risk:limits:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"trade8:risk:limits:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"trade8:risk:limits:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"trade8:risk:trader:state:write\", resource) when { principal.scopes.contains(\"trade8:risk:trader:state:write\") };\npermit(principal, action == Action::\"trade8:risk:trader:state:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"trade8:risk:trader:state:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"trade8:risk:trader:state:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };";

/// Default declarative policy set (Sentin8:Policy design §3.2/§3.4,
/// seeded by `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set - the
/// exact mirror of the gates this service's handlers evaluate in step 5
/// (policy design §4.3). Enforced: step 5 is the only gate; shadow is
/// the emergency one-UPDATE rollback lever only.
const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for trade8:risk over the LIVE effective scope set (design §3.1d). Enforced - step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples (design §3.1c) - none declared by this
/// service today; env admins author their own graph (office/trader,
/// entitlement edges) via the relations admin API.
const RELATIONS: &[RelationDecl] = &[];

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "trade8:risk:authorize,trade8:risk:limits:read,trade8:risk:limits:write,trade8:risk:trader:state:write",
    role: "trade8_risk_service",
    bypass_rls: false,
    database: "trade8",
        // Declared SELECT-only reads (enroll applies them in a post-loop
        // pass - never blanket schema grants; data-model §1.1).
    cross_schema_grants: &[
        CrossSchemaGrant { schema: "desk", table: "short_exempt", privilege: "SELECT" },
    ],
}];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "trade8:admin",
        scope: "trade8:risk:authorize",
    },
    AdminScope::Typed {
        role: "trade8:admin",
        scope: "trade8:risk:limits:read",
    },
    AdminScope::Typed {
        role: "trade8:admin",
        scope: "trade8:risk:limits:write",
    },
    AdminScope::Typed {
        role: "trade8:admin",
        scope: "trade8:risk:trader:state:write",
    },
    AdminScope::Typed {
        role: "trade8:admin",
        scope: "trade8:risk:symbol:block",
    },
    AdminScope::Typed {
        role: "trade8:admin",
        scope: "trade8:risk:levels:read",
    },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed {
        role: "trade8:risk:admin",
        scope: "trade8:risk:policy:read",
    },
    AdminScope::Typed {
        role: "trade8:risk:admin",
        scope: "trade8:risk:policy:write",
    },
];

const ERROR_CODES: &[ErrorCode] = &[ErrorCode {
    enum_name: "Trade8RiskDenied",
    error_code: "trade8_risk_denied",
    status_code: 422,
}];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "limits",
        label: "Limits",
        ui_endpoint: "/v1/admin/ui/limits",
        data_endpoint: "/v1/admin/limits",
        icon: "0xe06d",
    },
    AdminUiPage {
        route: "traders",
        label: "Trader States",
        ui_endpoint: "/v1/admin/ui/traders",
        data_endpoint: "/v1/admin/trader-state",
        icon: "0xe7fd",
    },
    AdminUiPage {
        route: "restrictions",
        label: "Restrictions",
        ui_endpoint: "/v1/admin/ui/restrictions",
        data_endpoint: "/v1/admin/restrictions",
        icon: "0xe14b",
    },
    AdminUiPage {
        route: "levels",
        label: "Risk Levels",
        ui_endpoint: "/v1/admin/ui/levels",
        data_endpoint: "/v1/admin/levels",
        icon: "0xe002",
    },
    AdminUiPage {
        route: "exposure",
        label: "Exposure",
        ui_endpoint: "/v1/admin/ui/exposure",
        data_endpoint: "/v1/admin/exposure",
        icon: "0xe9f5",
    },
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "relations",
        label: "Relations",
        ui_endpoint: "/v1/admin/ui/relations",
        data_endpoint: "/v1/admin/relations",
        icon: "0xe572",
    },
    AdminUiPage {
        route: "attributes",
        label: "Attributes",
        ui_endpoint: "/v1/admin/ui/attributes",
        data_endpoint: "/v1/admin/attributes",
        icon: "0xe8d3",
    },
];

/// Workload scope grants (self-registration design §3.11). One
/// entry per workload this service presents a certificate for - the
/// fail-closed registry map admits only these. Scope values use the
/// full vocabulary form (bare `bus:consume` fails the map's superset
/// check).
const M2M_GRANTS: &[M2mGrant] = &[
    // The service's own workload identity: the shell 8b outbox relay +
    // the direct callers. Colon + short spellings both granted - the
    // registry map looks up the exact workload name each call site
    // presents a certificate for.
    M2mGrant {
        workload: "trade8:risk",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
        ],
    },
    M2mGrant {
        workload: "risk",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
        ],
    },
    // Shell audit-journal pusher workload (audit crate §6.8; boot step 8c).
    M2mGrant {
        workload: "risk-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    // Shield hot-reload consumer (policy crate `policy_bus_client`,
    // full colon identity) + stat emitter (stat_emit short form).
    M2mGrant {
        workload: "trade8:risk-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "risk-policy",
        scopes: &["sentin8:stat:measure"],
    },
    // (VDC §VDC.7): the database-free HostContextResolver's
    // resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    M2mGrant {
        workload: "trade8-risk-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
    // Per-family bus consumers (risk design §7; BUSPOLICY-1b): the
    // consumers spawn one cert-presenting client per family and use the
    // family name as the workload identity (`trade8:risk:{family}`) -
    // certificate identity is authorized by the enroll-published registry
    // map, so every runtime-presented identity must be declared here.
    M2mGrant {
        workload: "trade8:risk:desk",
        scopes: &["sentin8:bus:consume"],
    },
    M2mGrant {
        workload: "trade8:risk:router",
        scopes: &["sentin8:bus:consume"],
    },
    M2mGrant {
        workload: "trade8:risk:feed",
        scopes: &["sentin8:bus:consume"],
    },
    M2mGrant {
        workload: "trade8:risk:pnl",
        scopes: &["sentin8:bus:consume"],
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

fn empty_openapi() -> serde_json::Value {
    serde_json::to_value(crate::openapi::RiskOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "trade8:risk",
        subdomain: "trade8-risk",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Risk",
            icon: "0xe8e5",
            service_flag: "trade8-risk",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: empty_openapi,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
    };
    sentin8::registration::print_registration(section, &reg, empty_openapi)
}
