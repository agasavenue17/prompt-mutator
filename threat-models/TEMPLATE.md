# Threat model - TEMPLATE

Fill this in per target before running the mutator. The mutator grounds
every variant in the surfaces and scope listed here. Keep it factual and
short: one bullet per surface, asset, or rule.

Target: <project name>

Project type: <web2 | web3-contract | wallet>
<!-- The type adapts the prompts: lens wording and attacker starting
     positions change per type. web2 = app/API, web3-contract = smart
     contracts, wallet = mobile/desktop wallet app. Unknown = web2. -->

## Priority angle - max 3 classes (highest impact first)

<!-- REQUIRED before mutate. Classes are decided up front, here,
     not by the mutator. The mutator only expands variants inside
     the classes you pick.
     DYNAMIC RULE: the top 3 differ per engagement, depending on
     project type. Do not copy the top 3 from another type. Pick
     max 3 from the candidate list for this project type in
     priority-classes.json, then REORDER for this project: highest
     reward, scope opened up, and evidence or findings already on
     record. Class 4 and beyond are dropped from this run, not
     deleted from your notes. They go into the next round if signals
     from the top 3 run dry.
     Class format: one ### heading per class, class name after "-".
     The mutator reads the heading and auto-selects the lenses mapped
     to that class (see priority-classes.json, the lenses field per
     class). To force your own lenses, use the --lenses flag at
     mutate time.
     Candidates per type (pick max 3, reorder per project):
     - web2: Tenant isolation & IDOR | Business logic: payment /
       pricing / payout | Auth, session & privilege escalation |
       File upload / download & access | Workflow / state-machine
       bypass | Integration / webhook / OAuth
     - web3-contract: Settlement accounting: mint / burn / fund
       conservation | Oracle / price / fee manipulation |
       Attestation / signature replay & idempotency | Executor /
       solver claiming & access | Admin / roles & upgrade |
       Token behaviour & external calls
     - wallet: Key & seed | Signing & transaction display |
       Auth, recovery & backup | Entry paths: deep link / QR /
       WebView / WalletConnect | Platform & supply chain -->

### Class 1 - <highest-impact class name for this project>

- <what to look for in this class, 1-3 bullets>
- <existing findings in this class, if any>

### Class 2 - <second-highest-impact class name>

- <what to look for in this class, 1-3 bullets>

### Class 3 - <third-highest-impact class name>

- <what to look for in this class, 1-3 bullets>

## Use cases

<!-- One bullet per real user flow. Variants name the use case they target,
     so prompts follow the project's actual flows instead of generic text. -->
- <e.g. merchant creates and approves a payout>
- <e.g. user connects a dApp and signs a transaction>

## Scope

- <what is in scope, e.g. web app + API at app.example.com>
- <any limits, e.g. test accounts only>

## Out of scope

- <e.g. brute force / DoS / rate limiting on payment systems>
- <e.g. automated scanning is prohibited; manual testing only>
- <e.g. third-party subdomains>

## Surfaces / assets / entry points

- <e.g. merchant dashboard: payout creation>
- <e.g. API: POST /v1/payouts>
- <e.g. onboarding / KYC flow: identity verification>
- <e.g. auth: login, session, password reset>
- <e.g. webhooks: inbound event handling>

## Trust boundaries

- <e.g. unauthenticated visitor vs authenticated merchant>
- <e.g. merchant A vs merchant B (tenant isolation)>
- <e.g. merchant vs platform admin>

## Auth / identity

- <e.g. session token, role: merchant / admin>
- <e.g. payout requires verified identity>

## State model

- <e.g. payment lifecycle: created -> authorized -> captured -> settled>
- <e.g. payout lifecycle: requested -> approved -> paid>
