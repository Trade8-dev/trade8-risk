# Trade8:Risk - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Trade8:Risk **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

- Protect the firm's capital: **no order mutates a position without passing
  the pre-trade gate** - buying-power, exposure, and share-count limits are
  enforced before acceptance, not reconciled after.
- Give supervisors **instant control over a trader's ability to trade**
  (closing-only, disabled-by-risk/compliance) without touching their identity
  or credentials.
- Guarantee **explainable denials**: every refusal carries the itemized check
  trace, journaled by the order desk, ready for supervision and client
  dispute resolution.
- Keep the gate **fast enough to sit on every order**: authorization must
  never be the reason a desk trades on stale prices.

## 2. Business Scope (What the Service Provides)

| Capability | Description |
|---|---|
| Pre-trade authorization | One `authorize` call returning allow/deny with a per-check trace |
| Buying power control | Order notional vs (limit − reserved notional), with journaled reservation accounting |
| Exposure limits | Max shares per order, max position shares (projected), max position value, max notional |
| Trading-rate control | Max open-order count (plus configurable max-orders-per-interval rows) |
| Trading-state control | Closing-only / disabled-by-risk / disabled-by-compliance / disabled / inactive per trader |
| Restriction enforcement | Blocked symbols/destinations/markets, per-trader symbol allowlists |
| Order-form control | Per-destination allowed order types and time-in-force values |
| Cancel-denial windows | Deny cancellations by listed users/offices during defined windows |
| Short-sale controls | Short-exempt bypass list; uptick rule (`up` / `updown`) evaluation off the live print mirror |
| Market-halt enforcement | Halt mirror from feed events blocks orders in halted symbols |
| Loss-ladder actions | Day-loss thresholds triggering close-only/disable transitions (and notify/flatten by the owning services) |
| Limit administration | Runtime limit CRUD, effective immediately, fully audited |
| Admin workspace | RFW pages: limits, traders, restrictions, levels, exposure |
| Verdict audit support | Deny traces persisted by Desk for regulatory review |

### What the service does NOT own (business boundary)

| Concern | Owned by |
|---|---|
| Order lifecycle/state | Trade8:Desk |
| Locate pool administration (ETB/HTB, blocks) | Trade8:Desk (Risk enforces via the exempt list + Desk's reservation) |
| Fills, executions, fees | Trade8:Router |
| Position/P&L computation | Trade8:Pnl (Risk consumes its summaries) |
| Market data and halt sources | Trade8:Feed |
| Notifications (ladder `notify`) | Sentin8:Post/notifiers |
| Order flattening execution | Trade8:Desk + Sentin8:Func |
| Sign-in, identity, credentials | Sentin8:Auth + Shield |

## 3. Business Capabilities

| Area | Capability | Business rule |
|---|---|---|
| Authorization | Trader state gate | An inactive/disabled trader cannot open or close; closing-only may only reduce exposure |
| Authorization | Buying power | Reserved + new order notional must fit the trader's (or office's, or env's) buying-power limit |
| Authorization | Order size | Shares per order and per projected position capped per limit kind |
| Authorization | Trading pace | Open-order count capped; configurable order-rate rows for burstier control |
| Authorization | Instrument access | Blocked symbols denied; allowlisted traders limited to their list |
| Authorization | Venue access | Blocked destinations/markets denied; allowed order types/TIFs per destination enforced |
| Authorization | Uptick rule | Under `up`: short opens require the last print above the prior; under `updown`: at-or-above; exempt symbols bypass |
| Authorization | Halt handling | Halted symbols are untradeable at the gate |
| Supervision | Trader lockout | Supervisors set closing-only/disable states instantly, with reason + attribution |
| Supervision | Loss ladder | Crossing a configured day-loss threshold flips the trader (close-only or disabled) per the ladder action |
| Administration | Immediate limits | A created limit applies to the next authorization via cache swap |
| Audit | Explainable deny | Each deny enumerates failed checks with limits, reserved and order values |

## 4. Business Events (Outbound)

| Event | Fires when |
|---|---|
| `trade8:risk:limit:updated` | A limit row is created/changed |
| `trade8:risk:trader:state` | A trading state transitions (supervisor or ladder) |

**Consumed (business view):** desk order lifecycle (reservation/open-order
accounting), router fills (position counters), feed prints (uptick +
halt mirrors), pnl trader summaries (loss-ladder evaluation).

## 5. Business Rules & Invariants

1. Every order acceptance is preceded by an allow verdict from Risk -
   enforced by Desk, which fails closed if Risk is unreachable.
2. A deny always explains itself with the failed checks; the trace is
   retained with the rejected order.
3. Denied-then-retried orders re-run all checks; a limit change takes
   effect for the next authorization.
4. Buying-power accounting converges exactly once per order lifecycle
   (reserve on accept; release on cancel/reject/replace/routed-leave).
5. Trading-state changes never alter credentials or sign-in - they gate
   tradeability only.
6. The gate is reachable only by services (M2M), never by end-user tokens.
7. Restrictions bind at the most specific scope (user > office > env);
   disabled rows are inert.
8. Uptick decisions use the freshest print view available to the caller;
   missing prints do not block.

## 6. Target-User Roles & Use Cases

| Persona | Use cases |
|---|---|
| Risk manager | Maintain limits (per trader/office/env), review the exposure board |
| Trading supervisor | Stop a rogue trader with one action (closing-only/disable), with reason |
| Compliance officer | Define cancel-denial windows; rely on deny traces for reports |
| Desk operations | Verify why an order was denied (trace via blotter) |
| Systems (Desk) | Call authorize before every acceptance - sub-ms verdict |
| Systems (Pnl) | Emit summaries that drive the loss ladder |

## 7. KPIs / Success Criteria

- Authorization latency: µs-class engine math, in-envelope 99th percentile
  far below the order-acceptance budget (latency harnesses cover the
  workspace P50/P99 budget).
- Zero un-authorized order acceptances platform-wide (Desk fail-closed
  contract).
- Every deny trace persisted (audit completeness).
- Limit/state mutation → next authorize reflects the change within one
  cache swap (sub-second worst case).
- Reservation accounting convergence under at-least-once redelivery.

## 8. Dependencies & Reliance on Other Services

| Dependency | Why the business relies on it |
|---|---|
| Trade8:Desk | Sole caller for order authorizations; journals denies |
| Trade8:Router | Fill events keep position counters honest |
| Trade8:Feed | Print/halt mirrors keep uptick + halt decisions current |
| Trade8:Pnl | Day summaries drive the loss ladder |
| Trade8:Desk (short pool) | Locate reservation happens Desk-side; Risk enforces exempt/uptick rules |
| Sentin8:Auth + Shield | Live role grants decide who may invoke/administer |
| Sentin8:Bus | Event feeds for all mirrors; fan-out of limit/state changes |
| Sentin8:Sys | Audit journal delivery |

## 9. Acceptance Criteria

1. A supervisor can lock a trader out of opening positions within a second;
   the trader can still reduce exposure if closing-only.
2. A trader exceeding buying power, share, position, or open-order limits is
   denied with the specific reason and remains denied until limits change.
3. Denied orders appear in the blotter with their full check trace.
4. A blocked symbol, halted market, or disallowed order type cannot be
   traded by anyone lacking an explicit bypass.
5. A day-loss ladder crossing flips the affected trader automatically.
6. All limit/state administration is audited and effective immediately.

## 10. Open Business Questions

- Should environments be able to opt into **deny-by-default** trading
  (unknown traders treated as inactive) instead of the current
  active-by-default?
- Multi-currency buying power: single-pool vs per-currency limits with
  conversion - which is the intended first-class behavior?
- Should the loss ladder include automated *flattening* execution (currently
  delegated to desk tooling via strategies), and under whose approval?
- What supervision UX should wrap cancel-denial windows (pre-market events,
  news windows) - timed windows or manual toggles?

---

**Architecture & Design:** trade8:risk and its underlying concepts were designed by [Hamid Jahanzad](https://www.linkedin.com/in/hamidjahanzad/).
