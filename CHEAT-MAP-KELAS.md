# Bug-class cheat map per lane - for the mutator

Use it to pick a priority angle before `mutate`. Lane = `Project type`
in the threat model: `web2`, `web3-contract`, or `wallet`.

## How to use (4 steps)

1. Pick the lane from the project type.
2. Pick **max 3 classes** from that lane, highest impact first for this
   project (reward, scope opened up, existing evidence). Do not copy
   another lane's top 3.
3. Write the class names exactly as below into the threat model,
   `## Priority angle` section, format `### Class N - <class name>`.
   The mutator reads the name and auto-selects the lenses mapped to
   that class (see `priority-classes.json`).
4. Run `mutate`. To force classes without editing the threat model:
   `mutate --classes <class-id-1>,<class-id-2>` (ids are listed with
   each class).

Rule: 1-2 classes is ideal for depth, 3 classes is the ceiling.
Class 4 and beyond are dropped from this run and go into the next
round if signals from the top 3 run dry.

## The easy formula (2 classes)

Each bug theme has 2 to 5 ways to hunt. Pick 2 themes and the hunting
methods merge into one set. A method shared by both themes counts
once, not twice.

1. Merge the hunting methods from both themes, drop the duplicates.
   Usually 5 to 10 methods.
2. Multiply by 3. Each method becomes 3 question versions.

So 2 themes usually become 15 to 30 questions. Example: theme A has
5 methods, theme B has 5 methods, 1 method is shared. Total methods
= 5 + 5 - 1 = 9. Questions = 9 times 3 = 27.

Note the difference: classes here group by **impact**, not by
technique. A technique (SSRF, XSS, SQLi, RCE, race, and so on) is how
the violation happens, and one technique can sit in several classes.
Lenses (L01-L13) are the hunting angles. An invariant is a property
that must always hold, and a bug breaks it.

---

## Technique -> Lens

A technique is how the violation happens. A class is what gets
violated. One technique can sit in several classes.

| Technique | Lens | Why that lens |
|---|---|---|
| IDOR / BOLA (Tenant isolation) | L01, L02, L03, L06, L07, L11 | No ownership check, check only on one path, ID trusted as-is, same object with different permissions, owner can be moved, old access still works. |
| SSRF | L01, L03, L05, L06, L07, L09 | URL fetched with no allowlist, URL trusted without a check, combined with another feature it reaches internal systems, another path is looser, internal identity is used, check order can be skipped. |
| ATO / Auth bypass | L01, L02, L03, L07, L11 | No check, check only on one endpoint, token trusted without a check, account can be linked to an attacker, old session still works. |
| XSS | L01, L03, L05, L06, L09 | Input not checked, data trusted without encoding, combined with another feature, renders differently in each place, render order can be skipped. |
| SQLi | L01, L03, L04, L09 | Input not checked, query trusted as-is, undocumented database behavior, validation order can be skipped. |
| RCE | L01, L03, L04, L05, L06 | No check at the execution sink, input trusted, undocumented parser behavior, combined with upload or template, another path is looser. |
| Business Logic | L03, L05, L09, L10, L13 | Numbers trusted, combined steps become a bypass, step order skipped, side effects still run, two states contradict each other. |
| Race Condition | L05, L09, L10, L13 | Two requests at once, check-and-use order can flip, side effects do not roll back, dual state contradicts itself. |
| File Upload / Traversal | L01, L06, L08, L12 | File type not checked, download path has different permissions, failed file still stored, file can be cancelled or replaced by another party. |
| Host Header / Reset Poisoning | L02, L03, L07 | Host checked in one place only, host from the request trusted, reset link can be moved to an attacker account. |
| Prototype Pollution | L03, L04, L05 | Merged objects trusted without a check, undocumented merge behavior, combined with a gadget it becomes RCE or XSS. |
| Request Smuggling | L02, L04, L09, L13 | Front end and back end read the request differently, undocumented parser behavior, request order can be flipped, two readings contradict each other. |
| Subdomain Takeover | L02, L03, L06, L07 | Check only in one place, CNAME trusted without a check, subdomain usable through another path, cookie or OAuth can be moved. |
| Blind Signing | L02, L03, L05, L08, L09 | What is shown differs from what is signed, data trusted without a check, combined with a malicious request, prompt still appears after failure, review order can be skipped. |
| Oracle / Replay | L03, L04, L07, L09, L10, L13 | Price or signature trusted without a check, undocumented oracle behavior, identity can be moved, order can be flipped, effects do not roll back, two states contradict each other. |

## Chaining

Do not throw away a small finding, check its chain first. The chain
patterns that most often raise severity:

- API / IDOR -> Auth / ATO -> RCE
- API / BFLA -> Auth / ATO -> Admin
- SSRF -> RCE -> Auth / cloud
- SSRF -> internal API -> Auth / ATO
- XSS -> Auth / ATO -> API
- SQLi -> Auth -> RCE
- Host header -> Auth / ATO (reset poisoning)
- Request smuggling -> Auth / cache -> XSS
- Prototype pollution -> RCE / XSS
- Prototype pollution -> SSRF
- Subdomain takeover -> Auth / OAuth -> ATO
- File upload -> XSS / RCE
- File download IDOR -> Tenant isolation
- Business logic -> Race -> double benefit
- Workflow skip -> Business logic / payment
- Fake webhook -> Workflow bypass
- OAuth -> Auth / ATO
- Oracle -> Settlement accounting
- Attestation replay -> Settlement accounting
- Executor claiming -> Settlement accounting
- Admin / roles -> all other classes
- Token behaviour -> Settlement accounting
- Entry paths -> Signing -> Key & seed
- Leaked backup -> Key & seed
- Auth bypass -> Signing

Chain rule: if one link above is proven, do not close it at the first
class. Move to the next class in that chain before writing the report,
because severity follows the final impact of the chain, not the first
link.

## Lane A - web2

Project type: `web2`.

### A1. Tenant isolation & IDOR - id: `tenant-isolation` - lenses: L01, L02, L03, L06, L07, L11

Invariant: user A cannot read / change / delete objects owned by user B.
Derivatives:
- BOLA / IDOR: change `id`, `uuid`, `project_id`, `account_id` in path /
  body / query, get objects from another tenant (project, file, payout, balance).
- BFLA: admin endpoints callable by a plain customer role.
- Mass assignment: `owner_id`, `tenant_id`, `role` fields can be set
  through the request body.
- IDOR through another path: an object that is safe in the UI but open
  through an old API, export, preview, webhook, or batch endpoint (L06).
- Objects still accessible after revoke / tenant move (L11).
Signals: an endpoint accepts an ID with no ownership check; object lists
are filtered in the UI only, not in the query.
Chain: another tenant's data -> ATO (if a session / reset token leaks)
-> BFLA (if an admin function leaks).

### A2. Business logic: payment / pricing / payout - id: `payment-logic` - lenses: L03, L05, L09, L10, L13

Invariant: money / value only moves by the business rules; totals,
prices, and destinations cannot be changed one-sidedly; 1 payment = 1 benefit.
Derivatives:
- Client-computed totals: price, discount, tax, fee computed on the
  client and then trusted by the server.
- Payout / refund destination swap: payout or refund destination changed
  to an attacker account.
- Quota / limit bypass: rollover, budget, quota, trial used past the
  limit (negative numbers, 0, overflow, forced reset).
- State skip: approve / verify / pay steps skipped, straight to
  settled / approved state.
- Double benefit: 1 payment / coupon / claim used twice (needs a race,
  see chain).
- Currency / amount confusion: amount, currency, or decimals
  manipulated.
Signals: numbers / destinations / statuses that come from the client;
a lifecycle that can be jumped.
Chain: logic flaw + race -> double spend; logic flaw + IDOR -> someone
else's payout.

### A3. Auth, session & privilege escalation - id: `auth-session` - lenses: L01, L02, L07, L11

Invariant: only the rightful account owner / role can act; sessions
and tokens die after logout / revoke / password reset.
Derivatives:
- ATO through password reset: reset token guessable, reusable, or
  usable on another account (host header poisoning, token leaked in URL).
- Session fixation / session not invalidated: old session still works
  after password change or logout.
- Privilege escalation: role changed in body / cookie / JWT, high-role
  endpoints callable by a low role.
- 2FA bypass: the 2FA step can be skipped, bypassed through another
  endpoint, or is not enforced on the API.
- OAuth / SSO binding: an account can be linked to an attacker account
  without owner verification (L07).
Signals: reset / login / session handled by separate endpoints that do
not share the same checks (L02).
Chain: ATO -> tenant isolation (read all victim objects) -> BFLA.

### A4. File upload / download & access - id: `file-handling` - lenses: L01, L06, L08, L12

Invariant: files are only accessible to their owner; an uploaded file
cannot become code or escape the allowed folder.
Derivatives:
- IDOR download: change `file_id` / path, download another customer's
  file / asset.
- Path traversal: `../` in a file name or download parameter.
- Dangerous upload: file type not checked on the server (UI only),
  SVG / HTML upload becomes stored XSS, file becomes RCE through a parser.
- SSRF through a file: file URL / metadata makes the server fetch an
  internal URL.
- Failed / rejected files still stored and accessible (L08).
Signals: upload / download accepts a file name, path, or ID from the client.
Chain: upload -> XSS / RCE; download IDOR -> tenant isolation.

### A5. Workflow / state-machine bypass - id: `workflow-state` - lenses: L05, L09, L10, L12, L13

Invariant: state only moves through allowed transitions, in the right
order, by the right role; dual states must not contradict each other.
Derivatives:
- Step skip: approval, review, or verification skipped (L09).
- Undo / cancel by an unauthorized party: cancel a payout, revoke an
  approval, or revert someone else's state (L12).
- Rollback leak: a failed transaction still leaves side effects
  (notification sent, balance changed, file created) (L10).
- Dual state: status in the DB differs from status in another service
  (cache, queue, payment provider), and the gap is usable (L13).
- Safe combination becomes dangerous: two actions that are safe alone
  combine into a bypass (L05).
Signals: a multi-step lifecycle (draft -> review -> approve ->
final) checked in the UI only.
Chain: workflow skip + race -> double benefit; workflow skip ->
payment logic.

### A6. Integration / webhook / OAuth - id: `integration` - lenses: L02, L03, L04, L06

Invariant: events / tokens from an integration are only trusted when
their origin is verified; one integration cannot act for another tenant.
Derivatives:
- Webhook with no signature verification: fake events sent to the
  webhook endpoint change status / payments.
- OAuth redirect / token swap: `redirect_uri` or `code` used across
  accounts / tenants.
- Third-party behavior assumed: integration payloads trusted
  without validation (L03, L04).
- Old integration path: a legacy integration endpoint with looser
  checks than the main endpoint (L02, L06).
Signals: a webhook, OAuth, or import from a URL exists.
Chain: fake webhook -> workflow bypass; OAuth -> ATO.

---

## Lane B - web3-contract

Project type: `web3-contract`.

### B1. Settlement accounting: mint / burn / fund conservation - id: `settlement-accounting` - lenses: L01, L03, L05, L10, L13

Invariant: total mint is less than or equal to real escrow / deposits;
1 deposit = 1 settlement; funds out cannot exceed funds in.
Derivatives:
- Mint without backing: Hub / token mint with no matching deposit.
- Double-settle: 1 deposit settled twice (fill + refund, fill + fast
  fill, two executions with different idempotency keys).
- Accounting drift: internal balance differs from the real token
  balance (fee-on-transfer, rebasing, wrong decimals).
- Burn / release without a check: burn does not reduce the claim, or
  release runs with no valid proof.
- Deposit credited to the wrong order: a sweep lands on the wrong order.
Signals: mint, burn, escrow, and settlement exist in two places
(on-chain vs off-chain).
Chain: accounting + attestation replay -> drain; accounting + oracle
-> settle at the wrong price.

### B2. Oracle / price / fee manipulation - id: `oracle-pricing` - lenses: L03, L04, L09, L13

Invariant: the price / fee used to settle must be fresh, from a
verified source, and not pickable one-sidedly by a solver.
Derivatives:
- Stale price: an old price is used because `maxAge` is not checked
  on-chain.
- Solver-supplied price: a solver-signed price trusted with no
  on-chain verification.
- Fee / rate limiter bypass: zero fee, negative fee, or limiter
  bypassed through another path / split transactions.
- Price-impact check uses the wrong price: the input price does not
  reflect the real execution price.
Signals: prices come from off-chain, from a signer, or from a
single source with no fallback.
Chain: oracle -> settlement accounting (cheap settle, expensive claim).

### B3. Attestation / signature replay & idempotency - id: `attestation-replay` - lenses: L03, L07, L09, L10

Invariant: 1 authorization = 1 execution; a signature cannot be reused
across orders, chains, or actions.
Derivatives:
- Replay across orders: the same signature used for two different
  orders (nonce is only part of the hash, not a one-time marker).
- Replay across chains: a domain without `chainId` (EIP-712 / Permit)
  accepted on another chain.
- Fake idempotency: different `idempotencyKey` values but identical
  economic actions, both succeed.
- Signature malleability / parameter swap: recipient, amount, or
  chainId changed without invalidating the signature.
Signals: EIP-712, Permit, attestation, or off-chain proof exists.
Chain: replay -> settlement accounting (double-settle); replay ->
executor claiming.

### B4. Executor / solver claiming & access - id: `executor-claim` - lenses: L01, L02, L06, L07

Invariant: only the chosen solver / resolver may execute that order;
one solver cannot claim another solver's fill.
Derivatives:
- Resolver not bound: the oracle signature does not bind a specific
  `callResolver`, so anyone can execute.
- Someone else's fill claimed: another solver's Hub balance / reward
  taken through another execution path.
- Withdrawal to any address: withdrawal address / destination
  changeable one-sidedly with no timelock.
- Alternative execution path: another function / contract reaches the
  same assets with looser checks (L06).
Signals: a solver, executor, resolver, and withdrawal exist.
Chain: executor -> settlement accounting; executor -> attestation
(if execution needs a signature).

### B5. Admin / roles & upgrade - id: `admin-roles` - lenses: L01, L07, L11, L12

Invariant: admin functions are only callable by the admin role; a
revoked role cannot be used again; critical changes are not instant
without a timelock / 2-step process.
Derivatives:
- Missing role check: admin / config function with no `onlyOwner` /
  role check (L01).
- Role taken over: owner / beneficiary / delegate can be re-bound to
  an attacker address (L07).
- Revoke does not work: a revoked role / allowance is still usable
  because the check reads a cache / old state (L11).
- Instant change: destination, oracle, or critical parameter changed
  one-sidedly with no timelock (L12).
Signals: a multisig, owner, config, or upgrade exists.
Chain: admin -> all other classes (admin is the key to accounting,
oracle, and executor).

### B6. Token behaviour & external calls - id: `token-behaviour` - lenses: L04, L05, L08

Invariant: the contract must not assume token / third-party behavior
that is not guaranteed.
Derivatives:
- Fee-on-transfer / rebasing: the amount received differs from the
  amount sent, accounting breaks.
- Hook / callback: a token or third party calls back into the contract
  mid-execution (reentrancy through an unexpected path).
- Failed call but changed state: an external call reverts but the side
  effect already ran (L08).
- Combination: approve + transfer + mint that are safe alone become
  dangerous combined in 1 transaction (L05).
Signals: an unknown token, callback, or external call sits inside a
critical function.
Chain: token behaviour -> settlement accounting.

---

## Lane C - wallet

Project type: `wallet`.

### C1. Key & seed - id: `key-seed` - lenses: L01, L03, L06, L11, L13

Invariant: no outsider can obtain the private key or recovery phrase;
a key is only accessible after auth; a key does not leak through
another path.
Derivatives:
- Key in the wrong storage: plaintext key in a file / `UserDefaults` /
  log, not in Keychain / Secure Enclave.
- Key without auth: a key can be read / used with no PIN / biometric.
- Key leaked through backup / log / crash dump / clipboard / screenshot.
- Key alive after logout / revoke: key / session not invalidated
  after logout (L11).
- Conflicting duplicate keys: the key in Keychain differs from the key
  in cloud backup, and the gap is usable (L13).
- Key through another path: a key that is safe in the UI but reachable
  through a deep link, backup restore, or export (L06).
Signals: a vault / envelope, PIN, and local storage exist.
Chain: leaked key -> signing abused; leaked key -> all funds on
all chains lost.

### C2. Signing & transaction display - id: `signing` - lenses: L02, L03, L05, L08, L09

Invariant: what the user sees is what actually gets signed; 1 approve
= 1 displayed action; a signature cannot be reused.
Derivatives:
- Blind signing: destination / calldata not shown, user approves blind.
- Display mismatch: amount / recipient / network shown differ from
  what is signed.
- Permit / EIP-712: signed fields hidden, domain without `chainId`
  replayable across chains.
- Address poisoning: a lookalike fake address is shown so the user
  sends to the wrong place.
- Tampering before signing: amount / recipient / fee changed after the
  review screen but before signing (L09).
- Failed request but the signing prompt still appears (L08).
Signals: a review screen, WalletConnect, EIP-712, or Permit exists.
Chain: signing -> key (if signing runs without proper auth);
signing -> entry paths (a malicious request comes in through a dApp).

### C3. Auth, recovery & backup - id: `auth-recovery` - lenses: L01, L03, L06, L11

Invariant: backup / export / recovery only run after re-auth; the
recovery phrase does not leak; revoked auth cannot be used again.
Derivatives:
- Export without re-auth: a backup is exported from an unlocked device
  with no PIN / biometric.
- Weak backup: weak backup encryption, minimum password with no
  strength check, backup file openable offline.
- PIN brute-forced offline: a 6-digit PIN can be guessed offline
  because throttling is only in the app, not in hardware.
- Recovery phrase handling: seed shown / kept in memory / storage
  with no protection, or exported through the wrong path.
- Import overwrite: an imported backup overwrites the victim wallet
  with no check.
Signals: a cloud backup, export, import, PIN, and biometric exist.
Chain: leaked backup -> key & seed; auth bypass -> signing.

### C4. Entry paths: deep link / QR / WebView / WalletConnect - id: `entry-paths` - lenses: L02, L03, L05, L06

Invariant: outside requests only run when their origin and content are
verified; one entry path must not have looser checks than another path.
Derivatives:
- Deep link abuse: deep link scheme / WalletConnect URI used to inject
  a signing request or change state.
- Malicious QR payload: a QR code holds a recovery / privateKey /
  WalletConnect URI that executes directly with no proper confirmation.
- WebView / JS bridge: bridge exposed to web content, XSS in the WebView
  can reach wallet functions.
- WalletConnect: session proposal / signing request from a malicious
  dApp, origin check anchored to an attacker-claimed URL.
- SIWE / TON Connect: origin spoof, login used for access it was not
  meant for.
Signals: a deep link, QR scanner, WebView, or WalletConnect exists.
Chain: entry path -> signing (malicious request gets approved); entry
path -> key (recovery / privateKey payload).

### C5. Platform & supply chain - id: `platform-supply` - lenses: L04, L06

Invariant: a website / dependency must not become a path into the
wallet; unassumed dependency behavior must be proven to matter for
this project, not just by version.
Derivatives:
- Website IDOR / session: an account on the website can access
  another account's data.
- Dependency used dangerously: RNG / KDF in an unverifiable binary,
  an SDK trusted without a check.
- Undocumented SDK behavior changes and a check is skipped (L04).
Signals: a website, help center, or binary dependency exists.
Chain: platform -> key / signing if the website or SDK can trigger
a wallet action. This class has the lowest priority, drop it first
when a run already has 3 classes.

---
