# Cheat map kelas bug per lane — buat mutator

Dipakai buat nentuin Angle prioritas sebelum `mutate`. Lane = `Project type`
di threat model: `web2`, `web3-contract`, atau `wallet`.

## Cara pakai (4 langkah)

1. Tentuin lane dari project type.
2. Pilih **max 3 kelas** dari lane itu, urut impact tertinggi di project ini
   (reward, scope yang dibuka, bukti yang sudah ada). Jangan copy top 3
   lane lain.
3. Tulis nama kelasnya persis seperti di bawah ini ke threat model,
   section `## Angle prioritas`, format `### Kelas N — <nama kelas>`.
   Mutator baca nama itu dan auto-pilih lensa yang dipetakan ke kelas itu
   (lihat `priority-classes.json`).
4. Jalanin `mutate`. Kalau mau paksa kelas tanpa edit threat model:
   `mutate --classes <id-kelas-1>,<id-kelas-2>` (id ada di tiap kelas).

Aturan: 1-2 kelas = ideal buat depth, 3 kelas = ceiling. Kelas ke-4+
dicopot dari run ini, masuk round berikutnya kalau signals top 3 kering.

## Rumus gampang (2 kelas)

Tiap tema bug punya 2 sampai 5 cara nyari. Kalau lu pilih 2 tema,
cara nyarinya digabung jadi satu. Cara yang sama di dua tema cuma
dihitung sekali, jangan dihitung dua kali.

1. Gabung cara nyari dari 2 tema, buang yang kembar. Hasilnya
   biasanya 5 sampai 10 cara nyari.
2. Kali 3. Tiap cara nyari dibikin 3 versi pertanyaan.

Jadi 2 tema biasanya jadi 15 sampai 30 pertanyaan. Contoh: tema A
punya 5 cara, tema B punya 5 cara, 1 cara sama di keduanya. Total
cara nyari = 5 + 5 - 1 = 9. Pertanyaan = 9 kali 3 = 27.

Catatan beda: kelas di sini itu **pengelompokan berdasarkan impact**,
bukan teknik. Teknik (SSRF, XSS, SQLi, RCE, race, dsb) itu cara
pelanggarannya, dan satu teknik bisa masuk ke beberapa kelas. Lensa
(L01-L13) itu sudut pandang nyarinya. Invariant itu properti yang
harus selalu benar dan dilanggar kalau ada bug.

---

## Teknik -> Lensa

Teknik itu cara pelanggarannya. Kelas di atas itu apa yang dilanggar.
Satu teknik bisa masuk ke beberapa kelas.

| Teknik | Lensa | Kenapa lensa itu |
|---|---|---|
| IDOR / BOLA (Tenant isolation) | L01, L02, L03, L06, L07, L11 | Tidak ada cek kepemilikan, cek cuma di satu jalur, ID dipercaya begitu saja, objek sama izin beda, owner bisa dipindah, akses lama masih hidup. |
| SSRF | L01, L03, L05, L06, L07, L09 | Fetch URL tanpa allowlist, URL dipercaya tanpa cek, digabung dengan fitur lain jadi jalan ke internal, jalur lain lebih longgar, identitas internal dipakai, urutan cek bisa dilewati. |
| ATO / Auth bypass | L01, L02, L03, L07, L11 | Tidak ada cek, cek cuma di satu endpoint, token dipercaya tanpa cek, akun bisa di-link ke attacker, sesi lama masih hidup. |
| XSS | L01, L03, L05, L06, L09 | Input tidak dicek, data dipercaya tanpa encode, digabung dengan fitur lain, tampil beda di tiap tempat, urutan render bisa dilewati. |
| SQLi | L01, L03, L04, L09 | Input tidak dicek, query dipercaya begitu saja, perilaku database yang tidak tertulis, urutan validasi bisa dilewati. |
| RCE | L01, L03, L04, L05, L06 | Tidak ada cek di sink eksekusi, input dipercaya, perilaku parser tidak tertulis, digabung dengan upload atau template, jalur lain lebih longgar. |
| Business Logic | L03, L05, L09, L10, L13 | Angka dipercaya, gabungan langkah jadi bypass, urutan langkah dilewati, efek samping tetap jalan, dua state bertentangan. |
| Race Condition | L05, L09, L10, L13 | Dua request bersamaan, urutan cek dan pakai bisa dibalik, efek samping tidak ikut batal, state ganda bertentangan. |
| File Upload / Traversal | L01, L06, L08, L12 | Tipe file tidak dicek, jalur download beda izinnya, file gagal tetap tersimpan, file bisa dibatalkan atau diganti pihak lain. |
| Host Header / Reset Poisoning | L02, L03, L07 | Host dicek di satu tempat saja, host dari request dipercaya, link reset bisa dipindah ke akun attacker. |
| Prototype Pollution | L03, L04, L05 | Objek merge dipercaya tanpa cek, perilaku merge tidak tertulis, digabung dengan gadget jadi RCE atau XSS. |
| Request Smuggling | L02, L04, L09, L13 | Front-end dan back-end beda cara baca request, perilaku parser tidak tertulis, urutan request bisa dibalik, dua cara baca bertentangan. |
| Subdomain Takeover | L02, L03, L06, L07 | Cek cuma di satu tempat, CNAME dipercaya tanpa cek, subdomain bisa dipakai lewat jalur lain, cookie atau OAuth bisa dipindah. |
| Blind Signing | L02, L03, L05, L08, L09 | Yang tampil beda dari yang di-sign, data dipercaya tanpa cek, digabung dengan request jahat, prompt tetap muncul walau gagal, urutan review bisa dilewati. |
| Oracle / Replay | L03, L04, L07, L09, L10, L13 | Harga atau signature dipercaya tanpa cek, perilaku oracle tidak tertulis, identitas bisa dipindah, urutan bisa dibalik, efek tidak ikut batal, dua state bertentangan. |

## Chaining

Satu temuan kecil jangan dibuang, cek dulu rantainya. Pola rantai yang
paling sering naik severity:

- API / IDOR -> Auth / ATO -> RCE
- API / BFLA -> Auth / ATO -> Admin
- SSRF -> RCE -> Auth / cloud
- SSRF -> API internal -> Auth / ATO
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
- Webhook palsu -> Workflow bypass
- OAuth -> Auth / ATO
- Oracle -> Settlement accounting
- Attestation replay -> Settlement accounting
- Executor claiming -> Settlement accounting
- Admin / roles -> semua kelas lain
- Token behaviour -> Settlement accounting
- Entry paths -> Signing -> Key & seed
- Backup bocor -> Key & seed
- Auth bypass -> Signing

Aturan rantai: kalau satu link di atas terbukti, jangan tutup di kelas
pertama. Lanjut ke kelas berikutnya di rantai itu sebelum nulis laporan,
karena severity ikut impact akhir rantai, bukan link pertama.

## Lane A — web2

Project type: `web2`.

### A1. Tenant isolation & IDOR — id: `tenant-isolation` — lensa: L01, L02, L03, L06, L07, L11

Invariant: user A tidak bisa baca / ubah / hapus objek milik user B.
Turunan:
- BOLA / IDOR: ganti `id`, `uuid`, `project_id`, `account_id` di path /
  body / query, dapat objek tenant lain (project, file, payout, balance).
- BFLA: endpoint admin / operator bisa dipanggil role customer biasa.
- Mass assignment: field `owner_id`, `tenant_id`, `role` bisa di-set
  lewat body request.
- IDOR lewat jalur lain: objek yang aman di UI tapi kebuka lewat API
  lama, export, preview, webhook, atau batch endpoint (L06).
- Objek setelah revoke / pindah tenant masih bisa diakses (L11).
Sinyal: endpoint terima ID tanpa cek kepemilikan; daftar objek cuma
difilter di UI, bukan di query.
Chain: dapat data tenant lain -> ATO (kalau dapat session / reset token)
-> BFLA (kalau dapat fungsi admin).

### A2. Business logic: payment / pricing / payout — id: `payment-logic` — lensa: L03, L05, L09, L10, L13

Invariant: uang / nilai cuma bergerak sesuai aturan bisnis; total,
harga, dan tujuan tidak bisa diubah sepihak; 1 bayar = 1 manfaat.
Turunan:
- Client-computed totals: harga, diskon, pajak, fee dihitung di client
  lalu dipercaya server.
- Payout / refund destination swap: tujuan payout atau refund diganti
  ke rekening / akun attacker.
- Quota / limit bypass: rollover, budget, kuota, trial dipakai
  melebihi batas (angka negatif, 0, overflow, reset paksa).
- State skip: langkah approve / verifikasi / bayar dilewati, langsung
  ke state settled / approved.
- Double benefit: 1 pembayaran / kupon / klaim dipakai 2x (butuh race,
  lihat chain).
- Currency / amount confusion: amount, mata uang, atau desimal
  dimanipulasi.
Sinyal: ada angka / tujuan / status yang datang dari client; ada
lifecycle yang bisa dilompati.
Chain: logic flaw + race -> double spend; logic flaw + IDOR -> payout
milik orang lain.

### A3. Auth, session & privilege escalation — id: `auth-session` — lensa: L01, L02, L07, L11

Invariant: cuma pemilik akun / role yang sah yang bisa bertindak;
sesi dan token mati setelah logout / revoke / reset password.
Turunan:
- ATO lewat password reset: token reset bisa ditebak, dipakai ulang,
  atau dipakai di akun lain (host header poisoning, token leak di URL).
- Session fixation / session tidak invalid: sesi lama tetap hidup
  setelah ganti password atau logout.
- Privilege escalation: role di body / cookie / JWT diubah, endpoint
  role tinggi bisa dipanggil role rendah.
- 2FA bypass: langkah 2FA bisa dilewati, di-skip lewat endpoint lain,
  atau tidak ditegakkan di API.
- OAuth / SSO binding: akun bisa di-link ke akun attacker tanpa
  verifikasi pemilik (L07).
Sinyal: reset / login / session dipegang endpoint terpisah yang tidak
berbagi cek yang sama (L02).
Chain: ATO -> tenant isolation (baca semua objek korban) -> BFLA.

### A4. File upload / download & access — id: `file-handling` — lensa: L01, L06, L08, L12

Invariant: file cuma bisa diakses pemiliknya; file yang di-upload
tidak bisa jadi kode atau jalan keluar dari folder yang diizinkan.
Turunan:
- IDOR download: ganti `file_id` / path, download file final / asset
  customer lain.
- Path traversal: `../` di nama file atau parameter download.
- Upload berbahaya: tipe file tidak dicek di server (hanya di UI),
  SVG / HTML upload jadi stored XSS, file jadi RCE lewat parser.
- SSRF lewat file: URL / metadata file bikin server fetch URL
  internal.
- File yang gagal / ditolak tetap tersimpan dan bisa diakses (L08).
Sinyal: upload / download terima nama file, path, atau ID dari client.
Chain: upload -> XSS / RCE; download IDOR -> tenant isolation.

### A5. Workflow / state-machine bypass — id: `workflow-state` — lensa: L05, L09, L10, L12, L13

Invariant: state cuma pindah lewat transisi yang diizinkan, dalam
urutan yang benar, oleh peran yang benar; state ganda tidak boleh
bertentangan.
Turunan:
- Step skip: approval, review, atau verifikasi dilewati (L09).
- Undo / cancel oleh pihak yang tidak berhak: cancel payout, batalkan
  approval, atau kembalikan state orang lain (L12).
- Rollback bocor: transaksi gagal tapi efek sampingnya jalan
  (notifikasi terkirim, saldo berubah, file terbuat) (L10).
- Dual state: status di DB beda dengan status di layanan lain
  (cache, queue, payment provider), dan celahnya bisa dipakai (L13).
- Kombinasi aman jadi berbahaya: dua aksi yang aman sendiri-sendiri
  digabung jadi bypass (L05).
Sinyal: ada lifecycle multi-langkah (draft -> review -> approve ->
final) yang dicek di UI saja.
Chain: workflow skip + race -> double benefit; workflow skip ->
payment logic.

### A6. Integration / webhook / OAuth — id: `integration` — lensa: L02, L03, L04, L06

Invariant: event / token dari integrasi cuma dipercaya kalau asalnya
terverifikasi; 1 integrasi tidak bisa bertindak atas nama tenant lain.
Turunan:
- Webhook tanpa verifikasi signature: event palsu dikirim ke endpoint
  webhook, status / pembayaran diubah.
- OAuth redirect / token swap: `redirect_uri` atau `code` dipakai
  lintas akun / tenant.
- Perilaku pihak ketiga diasumsikan: payload integrasi dipercaya
  tanpa validasi (L03, L04).
- Jalur lama integrasi: endpoint integrasi lama / legacy punya cek
  yang lebih longgar dari endpoint utama (L02, L06).
Sinyal: ada webhook, OAuth, atau import dari URL.
Chain: webhook palsu -> workflow bypass; OAuth -> ATO.

---

## Lane B — web3-contract

Project type: `web3-contract`.

### B1. Settlement accounting: mint / burn / fund conservation — id: `settlement-accounting` — lensa: L01, L03, L05, L10, L13

Invariant: Σ mint ≤ escrow / deposit riil; 1 deposit = 1 settle;
dana keluar tidak boleh lebih besar dari dana masuk.
Turunan:
- Mint tanpa backing: mint Hub / token tanpa deposit yang setara.
- Double-settle: 1 deposit di-settle 2x (fill + refund, fill + fast
  fill, dua Execution dengan idempotencyKey berbeda).
- Accounting drift: balance internal beda dengan balance token
  sebenarnya (fee-on-transfer, rebasing, desimal salah).
- Burn / release tanpa cek: burn tidak mengurangi hak klaim, atau
  release jalan tanpa bukti yang sah.
- Deposit address salah atribusi: sweep masuk ke order yang salah.
Sinyal: ada mint, burn, escrow, dan settlement di dua tempat
(on-chain vs off-chain).
Chain: accounting + attestation replay -> drain; accounting + oracle
-> settle dengan harga salah.

### B2. Oracle / price / fee manipulation — id: `oracle-pricing` — lensa: L03, L04, L09, L13

Invariant: harga / fee yang dipakai buat settle harus fresh, dari
sumber terverifikasi, dan tidak bisa dipilih sepihak oleh solver.
Turunan:
- Stale price: harga basi dipakai karena `maxAge` tidak dicek
  on-chain.
- Solver-supplied price: harga yang di-sign solver dipercaya tanpa
  verifikasi on-chain.
- Fee / rate limiter bypass: fee 0, fee negatif, atau limiter
  dilewati lewat jalur lain / pecah transaksi.
- Price-impact check pakai harga yang salah: harga masuk tidak
  merefleksikan harga eksekusi sebenarnya.
Sinyal: harga datang dari off-chain, dari signer, atau dari
satu sumber tanpa fallback.
Chain: oracle -> settlement accounting (settle murah, klaim mahal).

### B3. Attestation / signature replay & idempotency — id: `attestation-replay` — lensa: L03, L07, L09, L10

Invariant: 1 otorisasi = 1 eksekusi; signature tidak bisa dipakai
ulang lintas order, chain, atau aksi.
Turunan:
- Replay lintas order: signature yang sama dipakai buat dua order
  berbeda (nonce cuma bagian dari hash, bukan penanda sekali pakai).
- Replay lintas chain: domain tanpa `chainId` (EIP-712 / Permit)
  diterima di chain lain.
- Idempotency palsu: `idempotencyKey` berbeda tapi aksi ekonomi
  identik, keduanya sukses.
- Signature malleability / parameter swap: recipient, amount, atau
  chainId diganti tanpa membatalkan signature.
Sinyal: ada EIP-712, Permit, attestation, atau proof off-chain.
Chain: replay -> settlement accounting (double-settle); replay ->
executor claiming.

### B4. Executor / solver claiming & access — id: `executor-claim` — lensa: L01, L02, L06, L07

Invariant: cuma solver / resolver yang dipilih yang boleh eksekusi
order itu; 1 solver tidak bisa klaim fill solver lain.
Turunan:
- Resolver tidak terikat: oracle signature tidak mengikat
  `callResolver` tertentu, siapa saja bisa eksekusi.
- Fill orang lain diklaim: Hub balance / reward solver lain
  diambil lewat jalur eksekusi lain.
- Withdrawal ke alamat sembarang: withdrawal address / destinasi
  bisa diubah sepihak tanpa timelock.
- Jalur eksekusi alternatif: fungsi / kontrak lain mencapai aset
  yang sama dengan cek yang lebih longgar (L06).
Sinyal: ada solver, executor, resolver, dan withdrawal.
Chain: executor -> settlement accounting; executor -> attestation
(kalau eksekusi butuh signature).

### B5. Admin / roles & upgrade — id: `admin-roles` — lensa: L01, L07, L11, L12

Invariant: fungsi admin cuma bisa dipanggil role admin; role yang
dicabut tidak bisa dipakai lagi; perubahan kritis tidak instan
tanpa timelock / 2-step.
Turunan:
- Missing role check: fungsi admin / config tanpa `onlyOwner` /
  role check (L01).
- Role direbut: owner / beneficiary / delegate bisa di-rebind ke
  alamat attacker (L07).
- Revoke tidak efektif: role / allowance yang dicabut masih bisa
  dipakai karena cek baca cache / state lama (L11).
- Perubahan instan: destinasi, oracle, atau parameter kritis diubah
  sepihak tanpa timelock (L12).
Sinyal: ada multisig, owner, config, atau upgrade.
Chain: admin -> semua kelas lain (admin adalah kunci ke accounting,
oracle, dan executor).

### B6. Token behaviour & external calls — id: `token-behaviour` — lensa: L04, L05, L08

Invariant: kontrak tidak boleh mengasumsikan perilaku token /
pihak luar yang tidak dijamin.
Turunan:
- Fee-on-transfer / rebasing: jumlah yang diterima beda dari jumlah
  yang dikirim, accounting salah.
- Hook / callback: token atau pihak luar manggil balik kontrak di
  tengah eksekusi (reentrancy lewat jalur yang tidak diduga).
- Call gagal tapi state berubah: external call revert tapi efek
  samping sudah jalan (L08).
- Kombinasi: approve + transfer + mint yang aman sendiri-sendiri
  jadi berbahaya kalau digabung dalam 1 transaksi (L05).
Sinyal: ada token yang tidak dikenal, callback, atau external call
di tengah fungsi kritis.
Chain: token behaviour -> settlement accounting.

---

## Lane C — wallet

Project type: `wallet`.

### C1. Key & seed — id: `key-seed` — lensa: L01, L03, L06, L11, L13

Invariant: operator / pihak luar tidak bisa dapat private key atau
recovery phrase; key cuma bisa diakses setelah auth; key tidak
bocor lewat jalur lain.
Turunan:
- Key di storage yang salah: key plaintext di file / `UserDefaults` /
  log, bukan Keychain / Secure Enclave.
- Key tanpa auth: key bisa dibaca / dipakai tanpa PIN / biometrik.
- Key bocor lewat backup / log / crash dump / clipboard / screenshot.
- Key hidup setelah logout / revoke: key / sesi tidak invalid
  setelah logout (L11).
- Key ganda bertentangan: key di Keychain beda dengan key di cloud
  backup, dan celahnya bisa dipakai (L13).
- Key lewat jalur lain: key yang aman di UI tapi bisa diambil lewat
  deep link, backup restore, atau export (L06).
Sinyal: ada vault / envelope, PIN, dan penyimpanan lokal.
Chain: key bocor -> signing disalahgunakan; key bocor -> semua dana
di semua chain hilang.

### C2. Signing & transaction display — id: `signing` — lensa: L02, L03, L05, L08, L09

Invariant: yang tampil ke user = yang benar-benar di-sign; 1 approve
= 1 aksi yang tampil; signature tidak bisa dipakai ulang.
Turunan:
- Blind signing: destination / calldata tidak tampil, user approve
  buta.
- Display mismatch: amount / recipient / network yang tampil beda
  dari yang di-sign.
- Permit / EIP-712: field yang di-sign tersembunyi, domain tanpa
  `chainId` bisa replay lintas chain.
- Address poisoning: alamat palsu yang mirip ditampilkan supaya
  user salah kirim.
- Manipulasi sebelum signing: amount / recipient / fee diubah
  setelah layar review tapi sebelum signing (L09).
- Request gagal tapi signing prompt tetap muncul (L08).
Sinyal: ada layar review, WalletConnect, EIP-712, atau Permit.
Chain: signing -> key (kalau signing jalan tanpa auth yang benar);
signing -> entry paths (request jahat masuk lewat dApp).

### C3. Auth, recovery & backup — id: `auth-recovery` — lensa: L01, L03, L06, L11

Invariant: backup / export / recovery cuma jalan setelah re-auth;
recovery phrase tidak bocor; auth yang dicabut tidak bisa dipakai lagi.
Turunan:
- Export tanpa re-auth: backup diekspor dari device unlocked tanpa
  PIN / biometrik.
- Backup lemah: enkripsi backup lemah, password minimum tanpa cek
  kekuatan, file backup bisa dibuka offline.
- PIN brute-force offline: PIN 6 digit bisa ditebak offline karena
  throttling cuma di app, bukan hardware.
- Recovery phrase handling: seed ditampilkan / disimpan di memory /
  storage tanpa proteksi, atau di-export lewat jalur yang salah.
- Import overwrite: import backup menimpa wallet korban tanpa cek.
Sinyal: ada backup cloud, export, import, PIN, dan biometrik.
Chain: backup bocor -> key & seed; auth bypass -> signing.

### C4. Entry paths: deep link / QR / WebView / WalletConnect — id: `entry-paths` — lensa: L02, L03, L05, L06

Invariant: request dari luar cuma jalan kalau asal dan isinya
terverifikasi; 1 jalur masuk tidak boleh punya cek yang lebih longgar
dari jalur lain.
Turunan:
- Deep link abuse: deep link scheme / WalletConnect URI dipakai buat injeksi
  request signing atau ganti state.
- QR payload jahat: QR berisi recovery / privateKey / WalletConnect
  URI yang langsung dieksekusi tanpa konfirmasi yang benar.
- WebView / JS bridge: bridge terekspos ke konten web, XSS di WebView
  bisa akses fungsi wallet.
- WalletConnect: session proposal / signing request dari dApp jahat,
  origin check berjangkar URL klaim attacker.
- SIWE / TON Connect: origin spoof, login dipakai buat akses yang
  tidak dimaksud.
Sinyal: ada deep link, QR scanner, WebView, atau WalletConnect.
Chain: entry path -> signing (request jahat di-approve); entry path
-> key (payload recovery / privateKey).

### C5. Platform & supply chain — id: `platform-supply` — lensa: L04, L06

Invariant: website / dependency tidak boleh jadi jalan ke wallet;
perilaku dependency yang tidak diasumsikan harus dibuktikan dampaknya
di project ini, bukan sekadar versi.
Turunan:
- Website IDOR / session: akun di website bisa akses data akun lain.
- Dependency dipakai dengan cara yang berbahaya: RNG / KDF di binary
  yang tidak bisa diverifikasi, SDK yang dipercaya tanpa cek.
- Perilaku SDK tidak terdokumentasi berubah dan cek terlewat (L04).
Sinyal: ada website, help center, atau dependency binary.
Chain: platform -> key / signing kalau website atau SDK bisa
memicu aksi wallet. Kelas ini paling rendah prioritasnya, dicopot
dulu kalau run sudah 3 kelas.

---
