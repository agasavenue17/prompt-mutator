# Threat model — TEMPLATE

Fill this in per target before running the mutator. The mutator grounds
every variant in the surfaces and scope listed here. Keep it factual and
short: one bullet per surface, asset, or rule.

Target: <project name>

Project type: <web2 | web3-contract | wallet>
<!-- The type adapts the prompts: lens wording and attacker starting
     positions change per type. web2 = app/API, web3-contract = smart
     contracts, wallet = mobile/desktop wallet app. Unknown = web2. -->

## Angle prioritas — max 3 kelas (urut impact tertinggi)

<!-- WAJIB diisi sebelum mutate. Kelas ditentukan di awal, di sini,
     bukan oleh mutator. Mutator cuma ngembangin varian di dalam kelas
     yang lu pilih.
     ATURAN DINAMIS: top 3 beda tiap engagement, tergantung project type.
     Jangan copy top 3 dari tipe lain. Pilih max 3 dari daftar kandidat
     tipe project ini di priority-classes.json, lalu URUT ULANG
     berdasarkan project ini: reward tertinggi, scope yang dibuka,
     dan bukti / temuan yang sudah ada. Kelas ke-4 dan seterusnya
     dicopot dari run ini, bukan dihapus dari catatan — masuk round
     berikutnya kalau signals dari top 3 kering.
     Format kelas: satu heading ### per kelas, nama kelas setelah "—".
     Mutator baca heading ini dan auto-pilih lensa yang cocok dengan
     kelas itu (lihat priority-classes.json, field lenses per kelas).
     Kalau mau paksa lensa sendiri, pakai flag --lenses saat mutate.
     Kandidat per tipe (pilih max 3, urut ulang per project):
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

### Kelas 1 — <nama kelas impact tertinggi di project ini>

- <apa yang dicari di kelas ini, 1-3 bullet>
- <temuan yang sudah ada di kelas ini, kalau ada>

### Kelas 2 — <nama kelas impact tertinggi kedua>

- <apa yang dicari di kelas ini, 1-3 bullet>

### Kelas 3 — <nama kelas impact tertinggi ketiga>

- <apa yang dicari di kelas ini, 1-3 bullet>

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
- <e.g. merchant vs platform operator>

## Auth / identity

- <e.g. session token, role: merchant / admin>
- <e.g. payout requires verified identity>

## State model

- <e.g. payment lifecycle: created -> authorized -> captured -> settled>
- <e.g. payout lifecycle: requested -> approved -> paid>
