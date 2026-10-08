# ReconX — Project Implementation Progress & Tracking

Dokumen ini mencatat ringkasan status implementasi, arsitektur yang sudah selesai dibangun, riwayat pengujian, dan pedoman pemulihan sesi jika agen AI di-reset atau berganti sesi.

---

## 1. Status Ringkas Fase Implementasi

Mengikuti peta jalan pada `Implementation.md`:

| Fase | Deskripsi | Status | Tanggal Selesai | Keterangan |
|---|---|---|---|---|
| **Phase 0** | Repository Bootstrap & CLI Entrypoint | *PENDING* | - | Melewati fase ini sesuai instruksi user (langsung minta Phase 1). Paket dasar & `pyproject.toml` sudah disiapkan. |
| **Phase 1** | Core Execution Engine | **COMPLETED** | 2026-10-05 | CommandRunner, Task, Scheduler, Cancellation, Retry, Bounded Concurrency. 34 unit tests pass. |
| **Phase 2** | Scope Engine | **COMPLETED** | 2026-10-05 | ScopeValidator, ScopePolicy, ScopeDecision. Fail-closed, centralized scheduler enforcement. 71 tests pass. |
| **Phase 3** | Data Models + SQLite Persistence | **COMPLETED** | 2026-10-06 | Model scan/task/asset/observation/evidence/finding + SQLite snapshot save/load. 100 tests pass. Diterima (accepted). |
| **Phase 4** | DNS Adapters | **COMPLETED** | 2026-10-07 | Adapter whois, dig, host, nslookup. Normalized DNSRecord, WhoisRecord, DNSResult. 136 tests pass. Verified. |
| **Phase 5** | Network Adapters | **COMPLETED** | 2026-10-07 | Adapter ping, nmap, openssl. Model port/service. Downstream HTTP task gating. 166 tests pass. Verified. |
| **Phase 6** | HTTP Engine | **COMPLETED** | 2026-10-07 | Adapter curl, wget. Model HTTPResponse, HeaderAnalysis, BaselineResponse, EndpointDecision. Wildcard 200 detection. 192 tests pass. Verified. |
| **Phase 7** | Web Enumeration | **COMPLETED** | 2026-10-07 | gobuster, ffuf, dirb, deduplikasi endpoint multi-source. 234 tests pass. Verified. |
| **Phase 8** | Vulnerability Adapters | **COMPLETED** | 2026-10-07 | nikto, sqlmap, safe/passive/active modes. 270 tests pass. Verified. |
| **Phase 9** | Finding Intelligence | **COMPLETED** | 2026-10-07 | Korelasi, deduplikasi, klasifikasi, confidence scoring, evidence enrichment. 298 tests pass. Verified. |
| **Phase 10** | Risk Engine | **COMPLETED** | 2026-10-08 | CVSS 3.1 & 4.0 base score calculators, vector parser/generator, scoring rationale, explicit manual review status. 316 tests pass. Verified. |
| **Phase 11** | Reporting Engine | **COMPLETED** | 2026-10-08 | Generator JSON, Markdown, HTML, PDF via canonical ReportModel, automated secret redactor. 335 tests pass. Verified. |
| **Phase 12** | Profiles & Scan Resume | **COMPLETED** | 2026-10-08 | YAML profiles, CLI overrides, session manager, Section 25 resume state engine. 358 tests pass. Verified. |
| **Phase 13** | Performance Optimization | **COMPLETED** | 2026-10-08 | Metrics/profiler, priority min-heap scheduler, SQLite tuning, result caching & deduplication. 371 tests pass. Verified. |
| **Phase 14** | Production Hardening | **COMPLETED** | 2026-10-08 | Tool diagnostics, security audit & guardrails, graceful shutdown, error recovery, report validation, packaging, CLI, E2E tests, documentation. 426 tests pass. Verified. |

---

## 2. Rincian Implementasi Terakhir

### Phase 1 — Core Execution Engine (Selesai pada 2026-10-05)

#### Komponen yang Diimplementasikan:
1. **`reconx/core/cancellation.py` (`CancellationToken`)**:
   - Mendukung cooperative cancellation untuk async tasks & subprocesses.
   - Hirarki parent-child token.
   - Pendaftaran callback saat pembatalan dipicu.
   - Bersifat idempotent dan thread/coroutine safe.

2. **`reconx/core/runner.py` (`CommandRunner`, `CommandResult`)**:
   - Menjalankan perintah eksternal menggunakan `asyncio.create_subprocess_exec`.
   - **Keamanan Ketat**: Hanya menerima *argument sequence* (tidak pernah menggunakan `shell=True` atau string interpolation).
   - Pengendalian lifecycle proses: SIGTERM bertahap ke SIGKILL jika grace period terlampaui.
   - Penegakan timeout eksekusi per proses.
   - Pembatasan ukuran buffer output (`max_output_bytes` 10 MB) untuk mencegah exhaust memory.
   - Validasi ketersediaan binary (`shutil.which`).
   - Penangkapan stdout, stderr, exit code, durasi, timestamp, dan flag timeout/cancelled dalam model `CommandResult`.

3. **`reconx/core/task.py` (`Task`, `TaskState`, `RetryPolicy`, `TaskResult`)**:
   - **Task Lifecycle States**: `PENDING`, `READY`, `RUNNING`, `COMPLETED`, `FAILED`, `TIMEOUT`, `CANCELLED`, `SKIPPED`.
   - **RetryPolicy**: Jumlah retry maksimal, faktor backoff, retry on timeout, dan retry pada exit codes tertentu.
   - **Observability**: Timestamps presisi (`queued_at`, `started_at`, `finished_at`, `duration`).
   - Model `TaskResult` terstruktur untuk menyimpan metadata dan `CommandResult`.

4. **`reconx/core/scheduler.py` (`Scheduler`, `SchedulerConfig`, `SchedulerSummary`)**:
   - Scheduler berbasis Directed Acyclic Graph (DAG) yang sadar ketergantungan (dependencies).
   - Deteksi siklus (cycle detection) dan deteksi ketergantungan tidak dikenal sebelum run.
   - Antrean prioritas (`priority` descending).
   - **Bounded Multi-Class Concurrency**: Menggunakan semaphore ganda (global semaphore + resource-class semaphore, e.g. `dns: 8`, `network: 4`, `http: 10`, `vulnerability: 2`) dengan urutan akuisisi konsisten untuk mencegah deadlock.
   - **Failure Propagation**: Task yang gagal atau timeout tidak mematikan scheduler; task independen tetap berjalan, sedangkan task anak yang bergantung pada prerequisite yang gagal otomatis ditandai `SKIPPED`.
   - Pembatalan graceful seluruh eksekusi task via `CancellationToken`.

#### File yang Dibuat / Diubah:
* `pyproject.toml`
* `reconx/__init__.py`
* `reconx/core/__init__.py`
* `reconx/core/cancellation.py`
* `reconx/core/runner.py`
* `reconx/core/task.py`
* `reconx/core/scheduler.py`
* `tests/__init__.py`
* `tests/unit/__init__.py`
* `tests/unit/test_cancellation.py`
* `tests/unit/test_runner.py`
* `tests/unit/test_task.py`
* `tests/unit/test_scheduler.py`

#### Hasil Pengujian & Review:
* **Tool**: `pytest -v` (Python 3.14.7, pytest-9.1.1)
* **Total Tests**: 34 passed, 0 failed (2.29 detik).
* **Acceptance Criteria**: Memenuhi kriteria penerimaan Phase 1 secara penuh:
  > *"A dummy command can be scheduled, executed, timed out, retried, and recorded."*
  (Diverifikasi secara khusus di `tests/unit/test_scheduler.py::TestScheduler::test_phase1_acceptance_criteria`).

#### Rincian Perbaikan Bug & Hardening (2026-10-05):
1. **Perbaikan Race Condition Pembatalan (*Cancellation*) pada Scheduler (`reconx/core/scheduler.py`)**:
   - Masalah: Saat token pembatalan aktif, loop scheduler keluar seketika (`break`), meninggalkan task aktif yang masih berjalan tanpa ditunggu dan tidak tercatat di `SchedulerSummary`.
   - Solusi: `ready_queue` dikosongkan seketika, task belum berjalan ditandai `CANCELLED`, dan loop menunggu seluruh `active_tasks` menyelesaikan siklus pembatalannya.
   - Pengujian: Ditambahkan test komprehensif `test_cancellation_with_active_and_pending_tasks` untuk memverifikasi active task dan dependent task tertangani dengan benar (`CANCELLED` vs `SKIPPED`).
2. **Sinkronisasi Durasi Task ke `TaskResult` (`reconx/core/scheduler.py`)**:
   - Masalah: `TaskResult.duration` tidak terisi (default `0.0`) meskipun `task.duration` telah dihitung oleh `task.mark_finished()`.
   - Solusi: Diimplementasikan helper `_finish` yang secara otomatis menyalin `task.duration` ke `TaskResult.duration`.
   - Pengujian: Ditambahkan asersi nilai durasi > 0.0 di `test_single_task_execution` dan `test_phase1_acceptance_criteria`.
3. **Penyederhanaan Penanganan Timeout pada Runner (`reconx/core/runner.py`)**:
   - Masalah: Upaya membaca ulang stream stdout/stderr setelah timeout proses berpotensi hang jika pipe tertahan oleh child process.
   - Solusi: Dihilangkan pembacaan spekulatif pasca-terminasi; runner berfokus pada penghentian deterministik dan pencatatan state `timed_out=True`.
4. **Pembersihan Dead Code (`tests/unit/test_scheduler.py`)**:
   - Masalah: Terdapat fungsi helper lokal `action_a` dan `execution_order` yang tidak digunakan.
   - Solusi: Dihapus sesuai standar *Anti-AI-slop*.

#### Status Akhir Phase 1:
* **Status**: **VERIFIED & COMPLETED**
* Seluruh kriteria penerimaan, arsitektur, keamanan subprocess, dan pembatasan konkurensi Phase 1 telah teruji 100%.

### Phase 2 — Scope Engine (Selesai pada 2026-10-05)

#### Komponen:
1. **`reconx/scope/models.py`**: `ScopeReason` (enum alasan keputusan) dan `ScopeDecision` (allowed, host ternormalisasi, reason, rule yang cocok / pesan error).
2. **`reconx/scope/validator.py` (`ScopeValidator`)** — immutable setelah dibuat, fail-closed:
   - `example.com` = exact (tidak termasuk subdomain); `*.example.com` = semua subdomain (tidak termasuk apex). Wildcard selain leading `*.` ditolak saat konstruksi.
   - IP tunggal / CIDR (`strict=True`, typo seperti `192.0.2.5/24` ditolak). IPv4-mapped IPv6 dinormalisasi ke IPv4 agar exclusion tidak bisa di-bypass.
   - Exclusion selalu menang atas allow. Scope tanpa allowed entry ditolak (`ValueError`).
   - Parsing target tidak tepercaya: hostname, IP, host:port, URL absolut. Ditolak sebagai `INVALID_TARGET`: whitespace/control char/backslash, path/CIDR/userinfo tanpa scheme, port invalid, label hostname invalid (termasuk yang diawali `-`), bentuk numerik ambigu (`127.1`, `0x7f000001`), IPv6 dengan zone id.
   - `check_redirect(source_url, location)`: resolve Location relatif/scheme-relative, hanya http/https (`DISALLOWED_SCHEME` untuk lainnya), lalu validasi host.
   - Discovered asset divalidasi lewat `check()` yang sama; policy tidak bisa dimodifikasi sehingga discovery tidak dapat memperluas scope.
3. **Integrasi `Scheduler`** (`reconx/core/scheduler.py`): parameter `scope: ScopeValidator | None`. Sebelum akuisisi semaphore dan sebelum runner/action dipanggil, task dengan `target` divalidasi; jika ditolak → `SKIPPED` dengan pesan "out of scope"/"no scope configured", dependent task ikut di-skip. Task bertarget tanpa scope dikonfigurasi juga ditolak (fail-closed).
4. **`reconx/core/task.py`**: field `scope: Any` yang tidak pernah dipakai dihapus (enforcement terpusat di Scheduler).

#### File:
* Baru: `reconx/scope/__init__.py`, `reconx/scope/models.py`, `reconx/scope/validator.py`, `tests/unit/test_scope.py`, `tests/unit/test_scheduler_scope.py`
* Diubah: `reconx/core/scheduler.py`, `reconx/core/task.py`

#### Hasil Pengujian:
* `pytest -q`: **71 passed, 39 subtests passed** (2.18 detik). Tidak ada regresi Phase 1.
* Acceptance: *"An out-of-scope target can never reach CommandRunner."* — diverifikasi dengan `RecordingRunner` di `tests/unit/test_scheduler_scope.py` (runner tidak pernah dipanggil untuk target out-of-scope, excluded, malformed, maupun task action).

#### Rincian Review & Perbaikan (2026-10-05):
* **Engineering Review**: Melakukan review ketat terhadap implementasi Phase 2 berdasarkan 20 kriteria `Implementation.md`. Phase 2 dinyatakan valid, memenuhi arsitektur fail-closed, dan bersih dari speculative abstractions (Zero AI-slop).
* **Perbaikan Legacy Phase 1 (`reconx/core/cancellation.py`)**: 
  - Masalah: Terdapat pelanggaran aturan "Do not silently swallow failures" di blok eksekusi callback pada metode `cancel()` dan `register_callback()` (`except Exception: pass`).
  - Solusi: Menambahkan import `logging` dan mengganti `pass` dengan `logger.error` untuk memastikan setiap kegagalan callback tercatat tanpa menghentikan callback lainnya.
  - Hasil: Kode sudah diverifikasi ulang dan lulus semua tes.

#### Status Akhir Phase 2:
* **Status**: **VERIFIED & COMPLETED**
* Implementasi scope telah teruji secara komprehensif (71 pass) dan siap melayani module/adapter Phase selanjutnya.

#### Batasan yang Diketahui:
* Hostname tidak di-resolve: domain in-scope yang resolve ke IP excluded tidak terdeteksi di layer ini (harus divalidasi saat IP hasil DNS ditemukan, Phase 4+).
* Task tanpa `target` (perintah lokal/dummy) tidak melewati scope check; adapter Phase 4+ wajib mengisi `target`.
* Action task dengan target in-scope menerima `CommandRunner` langsung; adapter wajib membangun command hanya dari target yang divalidasi.
* Hostname dengan underscore (mis. record SRV) ditolak sebagai invalid.
* Loader YAML untuk konfigurasi scope belum ada (konfigurasi/CLI Phase 0/12).

### Phase 3 — Data Models + SQLite (Selesai pada 2026-10-06, Accepted)

#### Keputusan Desain:
* **Tanpa dependency baru**: Pydantic tidak terpasang; dipakai `dataclasses` + `sqlite3` standard library agar konsisten dengan kode Phase 1/2 (validasi di `__post_init__`).
* **Tidak ada model Task duplikat**: `reconx.core.task.Task`/`TaskResult`/`CommandResult` dipersist langsung.
* **Snapshot atomik**: `ScanRepository.save(state)` mengganti seluruh state scan dalam satu transaksi (`DELETE` cascade + `executemany` batch). Serialisasi divalidasi sebelum DB disentuh; error integritas → rollback, state lama tetap utuh.

#### Komponen:
1. `reconx/models/`: `Scan` (+`ScanStatus`, `new_scan_id()` → `scan-YYYYMMDD-HHMMSS-xxxx`, mencatat `reconx_version` & `ScopePolicy`), `ScanState` (agregat), `Asset` (`AssetKind` DOMAIN/IP, `AssetOrigin` USER_PROVIDED/DISCOVERED, `in_scope`), `Observation`, `Evidence` (tool, versi, command, exit code, stdout/stderr, parsed, raw_reference), `Finding` (`Severity` terpisah dari `confidence` 0.0–1.0, link ke observation & evidence).
2. `reconx/scope/models.py`: `ScopePolicy` (konfigurasi scope mentah yang bisa dipersist; `.validator()` membangun `ScopeValidator`).
3. `reconx/storage/database.py`: `open_database()` — file baru 0600, `foreign_keys=ON` (diverifikasi), WAL, `busy_timeout`, migrasi berversi via `PRAGMA user_version` (schema lebih baru ditolak), tabel `STRICT`, composite key `(scan_id, id)`, index pada kolom FK anak. Helper `transaction()`.
4. `reconx/storage/repository.py`: `ScanRepository.save/load`, `ScanNotFoundError`.

#### File:
* Baru: `reconx/models/{__init__,scan,asset,observation,evidence,finding}.py`, `reconx/storage/{__init__,database,repository}.py`, `tests/unit/test_models.py`, `tests/unit/test_storage.py`
* Diubah: `reconx/scope/models.py`, `reconx/scope/__init__.py`

#### Hasil Pengujian:
* `pytest -q --typeguard-packages=reconx`: **100 passed, 47 subtests passed**. Tidak ada regresi Phase 1/2.
* Acceptance *"A complete scan state can be persisted and reloaded"*: `test_complete_state_round_trips_across_connections` — task hasil eksekusi nyata Scheduler (COMPLETED/FAILED/SKIPPED/out-of-scope) + asset, observation, evidence, finding disimpan, koneksi ditutup, dibuka ulang, `loaded == state`.
* Benchmark lokal: 1.000 asset + 20.000 observation → save 0,66 s, re-save 1,12 s, load 0,26 s.

#### Batasan yang Diketahui:
* Task dengan `action` (callable Python) ditolak saat save (`ValueError`), karena kode tidak dapat dipersist.
* `save()` menulis ulang seluruh snapshot (O(n) per save); persistensi inkremental untuk resume adalah urusan Phase 12/13.
* Repository sinkron (blocking); belum di-wire ke alur scan karena coordinator/CLI belum ada (Phase 0 dilewati).
* stdout/stderr disimpan mentah di DB (file 0600); redaksi secret untuk report adalah Phase 11/14.
* Data JSON (`data`, `parsed`, `output_data`) harus bertipe JSON murni; tuple akan kembali sebagai list.
* Model Risk/CVSS belum ada (Phase 10).

### Phase 4 — DNS Adapters (Selesai pada 2026-10-07)

Status: COMPLETE

#### Completed:
- Adapter whois, dig, host, nslookup
- Normalized DNSRecord, WhoisRecord, DNSResult
- Independent parsers DigParser, HostParser, NslookupParser, WhoisParser
- ToolAdapter and DNSToolAdapter abstractions
- ToolRegistry with system availability checking
- Conversion to persistent Observation models
- Reverse DNS (PTR) record normalization across tools
- All review findings resolved (zero unused imports, PTR parsing in host/nslookup)

#### Tests:
- `pytest -v --typeguard-packages=reconx`: 136 passed, 47 subtests passed (3.74s)
- `tests/unit/test_dns_parsers.py`: 17 passed
- `tests/unit/test_dns_adapters.py`: 19 passed
- Regression tests for Phase 1, Phase 2, and Phase 3: all passed

#### Validation:
- Acceptance Criteria verified: All DNS tools produce the same normalized data structures.
- Tested parity between dig, host, and nslookup with identical normalized DNSRecord sets.
- Scheduler bounded concurrency verified with resource_class="dns".
- Subprocess safety verified (argument arrays only, no shell execution).
- Static AST inspection verified 0 unused imports across all Phase 4 code.

#### Known Issues:
- None

#### Next Phase:
- Phase 5 — Network Adapters (ping, nmap)

#### Last Updated:
- 2026-10-07

#### Keputusan Desain:
* **Separasi Eksplisit (Tools vs Parsers vs Models)**:
  - `reconx/models/dns.py`: Model normalized domain (`DNSRecord`, `WhoisRecord`, `DNSResult`, `RecordType`). Mengimplementasikan pembersihan otomatis trailing dots, normalisasi lowercase pada domain dan target rdata (CNAME, NS, MX, PTR), unquoting teks TXT, serta metode `.to_observations(asset_id, task_id)` yang mengonversi record DNS/WHOIS langsung ke model persistensi `Observation` Phase 3.
  - `reconx/parsers/dns.py`: Parser output independen (`DigParser`, `HostParser`, `NslookupParser`, `WhoisParser`) yang memetakan format keluaran tool yang berbeda-beda menjadi struktur data `DNSResult` yang identik.
  - `reconx/tools/`: Adapter konkret (`DigAdapter`, `HostAdapter`, `NslookupAdapter`, `WhoisAdapter`) turunan dari `ToolAdapter` / `DNSToolAdapter`.
* **Eksekusi Aman Melalui Centralized CommandRunner**:
  - Semua adapter membangun parameter menggunakan list argumen `list[str]` tanpa shell string (`shell=True` dilarang).
  - Validasi parameter input (mis. target kosong ditolak fail-closed).
  - Resource class konkurensi diatur ke `resource_class = "dns"` (memanfaatkan semaphore terikat yang diatur di Phase 1).
  - Adapter memproduksi instance `Task` dengan closure `action` yang otomatis mengeksekusi runner, memetakan status terminasi proses, mem-parse output, dan menaruh `DNSResult` ke `TaskResult.output_data`.
* **ToolRegistry**:
  - Registri terpusat untuk pendaftaran, retrieval, listing, dan pengecekan ketersediaan sistem (`check_all`) dari semua tool adapter.
  - Helper `get_default_registry()` yang otomatis mendaftarkan adapter DNS default.

#### Komponen yang Diimplementasikan:
1. `reconx/models/dns.py`: `RecordType`, `DNSRecord`, `WhoisRecord`, `DNSResult`.
2. `reconx/parsers/dns.py`: `DigParser`, `HostParser`, `NslookupParser`, `WhoisParser`.
3. `reconx/parsers/__init__.py`: Package export untuk parsers.
4. `reconx/tools/base.py`: `ToolAdapter` (ABC) dan `DNSToolAdapter`.
5. `reconx/tools/dig.py`: `DigAdapter`.
6. `reconx/tools/host.py`: `HostAdapter`.
7. `reconx/tools/nslookup.py`: `NslookupAdapter`.
8. `reconx/tools/whois.py`: `WhoisAdapter`.
9. `reconx/tools/registry.py`: `ToolRegistry`, `get_default_registry`.
10. `reconx/tools/__init__.py`: Package export untuk tools & registry.

#### File yang Dibuat / Diubah:
* Dibuat:
  - `reconx/models/dns.py`
  - `reconx/parsers/dns.py`
  - `reconx/parsers/__init__.py`
  - `reconx/tools/base.py`
  - `reconx/tools/dig.py`
  - `reconx/tools/host.py`
  - `reconx/tools/nslookup.py`
  - `reconx/tools/whois.py`
  - `reconx/tools/registry.py`
  - `reconx/tools/__init__.py`
  - `tests/unit/test_dns_parsers.py`
  - `tests/unit/test_dns_adapters.py`
* Diubah:
  - `reconx/models/__init__.py`
  - `PROGRESS.md`

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **136 passed, 47 subtests passed** (3.74 detik).
* **Acceptance Criteria Verification**:
  - *"All DNS tools produce the same normalized data structures."*
  - Diuji secara ketat pada `tests/unit/test_dns_parsers.py::TestPhase4AcceptanceCriteria::test_dig_host_nslookup_produce_identical_normalized_records` di mana query DNS yang sama untuk `dig`, `host`, dan `nslookup` menghasilkan set tuple `DNSRecord` yang identik 100%.
  - Integrasi dengan scheduler dan model observasi diverifikasi pada `test_dig_task_in_scheduler` dan `test_observation_conversion`.

#### Rincian Perbaikan Temuan Review (2026-10-07):
1. **Pembersihan Import Tidak Terpakai (*Unused Imports*)**:
   - Dihapus import yang tidak digunakan pada `reconx/parsers/dns.py` (`Any`), `reconx/tools/base.py` (`replace`), `reconx/tools/dig.py`, `reconx/tools/host.py`, `reconx/tools/nslookup.py`, `reconx/tools/whois.py` (`TYPE_CHECKING`), `tests/unit/test_dns_parsers.py` (`pytest`, `RecordType`, `DNSResult`, `WhoisRecord`), dan `tests/unit/test_dns_adapters.py` (`ScopePolicy`).
2. **Dukungan Parsing Reverse DNS (Record PTR)**:
   - Ditambahkan regex matching `domain name pointer` pada `HostParser` dan `name = ...` pada `NslookupParser` di `reconx/parsers/dns.py`.
   - Ditambahkan unit test `test_parse_ptr` pada `TestHostParser` dan `TestNslookupParser` di `tests/unit/test_dns_parsers.py`.
3. **Status Akhir**: Semua temuan review Phase 4 terselesaikan, lulus 136 pengujian tanpa regresi.

#### Batasan yang Diketahui:
* `host` dan `nslookup` standar tidak memaparkan TTL (sehingga field `ttl` bernilai `None` untuk kedua tool tersebut; `dig` mengekstrak TTL numerik).
* Query DNS live bergantung pada konektivitas outbound UDP/TCP port 53 (semua pengujian unit menggunakan fixture deterministik untuk mencegah ketergantungan jaringan).
* Network adapters (ping, nmap, dll.) belum diimplementasikan (merupakan Phase 5).

### Phase 5 — Network Adapters (Selesai pada 2026-10-07)

Status: COMPLETE

#### Completed:
- Adapter ping, nmap, openssl
- Strongly typed PortState, TransportProtocol, ServiceInfo, Port, HostNetworkInfo, NmapResult, PingResult, TLSCertificate, TLSResult models
- Independent parsers NmapParser (XML + text fallback), PingParser, TLSParser
- Downstream HTTP task generator (`generate_downstream_http_tasks`) strictly gating HTTP tasks on detected HTTP/HTTPS services
- ToolRegistry updated with ping, nmap, openssl
- Conversion to persistent Observation models (`.to_observations(asset_id, task_id)`)
- Concurrency bounded via `resource_class = "network"`

#### Tests:
- `pytest -v --typeguard-packages=reconx`: 166 passed, 47 subtests passed (3.56s)
- `tests/unit/test_network_parsers.py`: 13 passed
- `tests/unit/test_network_adapters.py`: 17 passed
- Regression tests for Phase 1, Phase 2, Phase 3, Phase 4: all passed

#### Validation:
- Acceptance Criteria verified: *"Nmap output can generate downstream HTTP tasks only when appropriate services are detected."*
  (Diverifikasi di `TestPhase5AcceptanceCriteria::test_downstream_http_tasks_generated_only_for_http_services` dan `TestNmapAdapter::test_generate_downstream_http_tasks_integration`).
- Bounded concurrency with `resource_class = "network"` verified in scheduler integration.
- Subprocess safety: only structured argument vectors (`list[str]`), no shell execution (`shell=True` prohibited).
- Standard library XML parsing via `xml.etree.ElementTree` avoiding external dependencies.
- Zero unused imports verified via static AST inspection.

#### Known Issues:
- None

#### Next Phase:
- Phase 6 — HTTP Engine (curl, wget, TLS parsing, response models, redirect handling, baseline response)

#### Last Updated:
- 2026-10-07

#### Keputusan Desain:
* **Separasi Layer (Models, Parsers, Tools)**:
  - `reconx/models/network.py`: Model domain normalized untuk service dan port (`PortState`, `TransportProtocol`, `ServiceInfo`, `Port`, `HostNetworkInfo`, `NmapResult`, `PingResult`, `TLSCertificate`, `TLSResult`). Menyediakan helper `.is_http` dan `.http_scheme` pada model `Port` serta `.to_observations(asset_id, task_id)` untuk konversi langsung ke model `Observation` Phase 3.
  - `reconx/parsers/`: Parser khusus (`NmapParser` dengan XML parsing `xml.etree.ElementTree` dan text fallback, `PingParser` mengekstrak latency dan packet loss, `TLSParser` mengekstrak parameter SSL handshake dan sertifikat X.509).
  - `reconx/tools/`: Adapter konkret (`PingAdapter`, `OpenSSLAdapter`, `NmapAdapter`) turunan dari `ToolAdapter` dengan `resource_class = "network"`.
* **Kriteria Penerimaan & Gating Tugas HTTP Hilir**:
  - `generate_downstream_http_tasks(nmap_result, task_factory)`: Mengiterasi host dan port pada hasil Nmap, memfilter hanya port yang berstatus `OPEN` atau `OPEN_FILTERED` dengan karakteristik HTTP/HTTPS (`port.is_http == True`). Port non-HTTP (mis. SSH port 22, SMTP port 25, DNS port 53) tidak akan memicu pembuatan task HTTP.
* **Keamanan Eksekusi Subproses**:
  - Seluruh adapter menggunakan argument vectors eksplisit (`list[str]`) melalui `CommandRunner`.
  - Target divalidasi tidak boleh kosong sebelum command dibangun.
  - Port OpenSSL divalidasi berada dalam rentang valid 1–65535.

#### Komponen yang Diimplementasikan:
1. `reconx/models/network.py`: `PortState`, `TransportProtocol`, `ServiceInfo`, `Port`, `HostNetworkInfo`, `NmapResult`, `PingResult`, `TLSCertificate`, `TLSResult`.
2. `reconx/models/__init__.py`: Export model jaringan.
3. `reconx/parsers/ping.py`: `PingParser`.
4. `reconx/parsers/tls.py`: `TLSParser`.
5. `reconx/parsers/nmap.py`: `NmapParser`.
6. `reconx/parsers/__init__.py`: Export parser jaringan.
7. `reconx/tools/ping.py`: `PingAdapter`.
8. `reconx/tools/openssl.py`: `OpenSSLAdapter`.
9. `reconx/tools/nmap.py`: `NmapAdapter`, `generate_downstream_http_tasks`.
10. `reconx/tools/registry.py`: Registrasi tool ping, nmap, openssl ke default registry.
11. `reconx/tools/__init__.py`: Export adapter jaringan dan downstream task generator.
12. `tests/unit/test_network_parsers.py`: Pengujian parser ping, TLS, dan nmap serta kriteria penerimaan Phase 5.
13. `tests/unit/test_network_adapters.py`: Pengujian adapter ping, openssl, nmap, scheduler integration, dan downstream HTTP tasks.

#### File yang Dibuat / Diubah:
* Dibuat:
  - `reconx/models/network.py`
  - `reconx/parsers/ping.py`
  - `reconx/parsers/tls.py`
  - `reconx/parsers/nmap.py`
  - `reconx/tools/ping.py`
  - `reconx/tools/openssl.py`
  - `reconx/tools/nmap.py`
  - `tests/unit/test_network_parsers.py`
  - `tests/unit/test_network_adapters.py`
* Diubah:
  - `reconx/models/__init__.py`
  - `reconx/parsers/__init__.py`
  - `reconx/tools/__init__.py`
  - `reconx/tools/registry.py`
  - `tests/unit/test_dns_adapters.py`
  - `PROGRESS.md`

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **166 passed, 47 subtests passed** (3.56 detik).
* **Acceptance Criteria Verification**:
  - *"Nmap output can generate downstream HTTP tasks only when appropriate services are detected."*
  - Terverifikasi 100% pada `tests/unit/test_network_parsers.py::TestPhase5AcceptanceCriteria` dan `tests/unit/test_network_adapters.py::TestNmapAdapter::test_generate_downstream_http_tasks_integration`. Port HTTP/HTTPS (mis. 80, 443, 8080, 8443) menghasilkan downstream task; port non-HTTP (mis. 22/ssh, 25/smtp, 53/dns) tidak menghasilkan downstream task.

#### Batasan yang Diketahui:
* Live raw socket scanning oleh `nmap` (SYN stealth scan `-sS`, OS detection `-O`) memerlukan privilege root (`CAP_NET_RAW` / `sudo`); dalam unprivileged/sandboxed context digunakan connect scan (`-sT`) atau port scan unprivileged secara default.
* Perilaku downstream HTTP tasks saat ini hanya menghasilkan task definition (`Task`); engine HTTP konkret (curl, wget) adalah ruang lingkup Phase 6.

### Phase 6 — HTTP Engine (Selesai pada 2026-10-07)

Status: COMPLETE

#### Completed:
- Adapter curl, wget (`CurlAdapter`, `WgetAdapter`) dengan `resource_class = "http"`
- Normalized domain models: `HTTPResponse`, `CookieInfo`, `HeaderAnalysis`, `BaselineResponse`, `EndpointDecision`
- Parsers: `HTTPResponseParser`, `HeaderAnalyzer`, `WgetParser`
- `HTTPEngine` dan `BaselineDetector` untuk penetapan respons baseline dan deteksi wildcard 200
- Penanganan rantai redirect bertingkat terintegrasi dengan validasi cakupan `ScopeValidator.check_redirect`
- Analisis security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), metadata server, dan flag cookie
- Registrasi tool `curl` dan `wget` pada `get_default_registry()`
- Konversi ke model persistensi `Observation` Phase 3 (`http_endpoint`, `server_metadata`, `missing_security_headers`)

#### Tests:
- `pytest -v --typeguard-packages=reconx`: 192 passed, 47 subtests passed (3.65s)
- `tests/unit/test_http_parsers.py`: 8 passed
- `tests/unit/test_http_adapters.py`: 18 passed
- Regression tests for Phase 1, Phase 2, Phase 3, Phase 4, Phase 5: all passed

#### Validation:
- Acceptance Criteria verified: *"The engine can accurately distinguish a real discovered endpoint from a wildcard 200 response."*
  (Diverifikasi pada `TestPhase6AcceptanceCriteria::test_distinguish_real_endpoint_from_wildcard_200` dan `test_distinguish_endpoints_on_standard_404_server`).
- Keamanan subproses: Semua pemanggilan menggunakan array argumen eksplisit (`list[str]`), tanpa `shell=True`.
- Integrasi scope: Rantai redirect divalidasi fail-closed menggunakan `ScopeValidator.check_redirect`.
- Konkurensi terikat: Semaphore multi-kelas `resource_class = "http"` teruji dalam eksekusi `Scheduler`.
- Bebas AI-slop: 0 unused imports terverifikasi via inspeksi AST statis.

#### Known Issues:
- None

#### Next Phase:
- Phase 7 — Web Enumeration (gobuster, ffuf, dirb, deduplikasi endpoint)

#### Last Updated:
- 2026-10-07

#### Keputusan Desain:
* **Separasi Layer (Models, Parsers, Tools)**:
  - `reconx/models/http.py`: Model normalized untuk respons HTTP (`HTTPResponse`), cookie (`CookieInfo`), security header analysis (`HeaderAnalysis`), baseline (`BaselineResponse`), dan keputusan endpoint (`EndpointDecision`). Menyediakan properti `body_hash`, `word_count`, `line_count`, `title`, dan metode `.to_observations(asset_id, task_id)`.
  - `reconx/parsers/http.py`: `HTTPResponseParser` mem-parse output header `-i` dari curl, menangani multi-block hop redirect (`-L`), ekstraksi cookie `Set-Cookie`, serta penanganan body. `HeaderAnalyzer` mengevaluasi header keamanan, teknologi, metadata server, dan CORS. `WgetParser` menggabungkan header stderr dan body stdout dari wget `-q -S -O -`.
  - `reconx/tools/`: `CurlAdapter` dan `WgetAdapter` turunan dari `ToolAdapter` dengan `resource_class = "http"`. `BaselineDetector` dan `HTTPEngine` mengoordinasikan probe baseline, deteksi wildcard 200, dan evaluasi endpoint.
* **Kriteria Penerimaan & Deteksi Wildcard 200**:
  - `BaselineDetector` membedakan server normal (404/not found) dan server wildcard (catch-all SPA/custom 200).
  - Pada server wildcard 200, endpoint dinilai berdasarkan kecocokan hash template, perbedaan judul halaman (`<title>`), perbedaan panjang konten (panjang bytes dan rasio toleransi), serta jumlah kata. Endpoint palsu yang menghasilkan template wildcard ditandai `is_distinct = False`, sedangkan endpoint nyata (API, Admin, dsb.) ditandai `is_distinct = True`.
* **Keamanan Rantai Redirect**:
  - `HTTPEngine.validate_redirects(response, scope)` memvalidasi setiap lokasi redirect bertahap menggunakan `scope.check_redirect()`. Jika redirect keluar ke domain di luar scope (mis. phishing/SSRF eksternal), redirect ditolak secara terpusat.

#### Komponen yang Diimplementasikan:
1. `reconx/models/http.py`: `HTTPResponse`, `CookieInfo`, `HeaderAnalysis`, `BaselineResponse`, `EndpointDecision`.
2. `reconx/models/__init__.py`: Export model HTTP.
3. `reconx/parsers/http.py`: `HTTPResponseParser`, `HeaderAnalyzer`, `WgetParser`.
4. `reconx/parsers/__init__.py`: Export parser HTTP.
5. `reconx/tools/curl.py`: `CurlAdapter`.
6. `reconx/tools/wget.py`: `WgetAdapter`.
7. `reconx/tools/http_engine.py`: `HTTPEngine`, `BaselineDetector`.
8. `reconx/tools/registry.py`: Registrasi curl dan wget ke tool registry.
9. `reconx/tools/__init__.py`: Export adapter HTTP dan engine.
10. `tests/unit/test_http_parsers.py`: Pengujian parser respons HTTP, header analyzer, dan parser wget.
11. `tests/unit/test_http_adapters.py`: Pengujian adapter curl/wget, engine HTTP, scheduler, dan kriteria penerimaan wildcard 200.

#### File yang Dibuat / Diubah:
* Dibuat:
  - `reconx/models/http.py`
  - `reconx/parsers/http.py`
  - `reconx/tools/curl.py`
  - `reconx/tools/wget.py`
  - `reconx/tools/http_engine.py`
  - `tests/unit/test_http_parsers.py`
  - `tests/unit/test_http_adapters.py`
* Diubah:
  - `reconx/models/__init__.py`
  - `reconx/parsers/__init__.py`
  - `reconx/tools/__init__.py`
  - `reconx/tools/registry.py`
  - `tests/unit/test_network_adapters.py`
  - `PROGRESS.md`

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **192 passed, 47 subtests passed** (3.65 detik).
* **Acceptance Criteria Verification**:
  - *"The engine can accurately distinguish a real discovered endpoint from a wildcard 200 response."*
  - Terverifikasi 100% pada `tests/unit/test_http_adapters.py::TestPhase6AcceptanceCriteria`. Real endpoints (API JSON, admin panel, protected 403) dibedakan secara akurat dari false positives wildcard 200 (exact hash match, template match).

#### Batasan yang Diketahui:
* Live HTTP network testing bergantung pada ketersediaan koneksi internet/target; seluruh pengujian unit menggunakan fixture deterministik untuk menjamin keterulangan dan keandalan isolasi sandbox.
* Web directory enumeration skala besar (wordlist fuzzing) merupakan ruang lingkup Phase 7 (gobuster, ffuf, dirb).

### Phase 7 — Web Enumeration (Selesai pada 2026-10-07)

#### Komponen yang Diimplementasikan:
1. **`reconx/models/endpoint.py` (`DiscoveredEndpoint`, `EndpointCollection`, `normalize_endpoint_key`)**:
   - `DiscoveredEndpoint`: Model `@dataclass(frozen=True)` yang merepresentasikan endpoint web yang ditemukan lengkap dengan URL, path, kode status HTTP, content-length, line count, word count, redirect location, content type, durasi respon, dan tuple sumber `sources`.
   - `normalize_endpoint_key()`: Melakukan normalisasi skema/host (lowercase), pembuangan port standar (:80, :443), dan canonicalization path trailing slash agar endpoint yang identik dari berbagai tool dipetakan ke kunci kanonikal yang sama.
   - `EndpointCollection`: Kontainer thread-safe yang mengumpulkan endpoint dari berbagai tool, menggabungkan metadata terbaik, melakukan deduplikasi, dan menggabungkan source attribution (`sources = tuple(sorted(set(...)))`).
   - `EndpointCollection.to_observations(asset_id, task_id)`: Memproduksi list `Observation` berjenis `discovered_endpoint` dengan `source=",".join(sources)` dan data JSON-serializable, memenuhi Kriteria Penerimaan Phase 7.
2. **`reconx/parsers/gobuster.py` (`GobusterParser`)**:
   - Mem-parse output standar `gobuster dir` (dengan/tanpa flag `-q`, prefix `Found:`, atau mode expanded `-e`).
   - Ekstraksi kode status, content size, dan target pengalihan `[--> ...]`.
   - Sanitasi ANSI escape code regex.
3. **`reconx/parsers/ffuf.py` (`FFUFParser`)**:
   - Mendukung format output NDJSON (newline-delimited JSON dari flag `-json`), batch JSON document, serta fallback plain text output (`admin [Status: 200, Size: 412, ...]`).
   - Ekstraksi status, length, word count, line count, redirect location, content type, serta konversi durasi nanosekon ke milisekon.
4. **`reconx/parsers/dirb.py` (`DirbParser`)**:
   - Mem-parse finding lines `+ URL (CODE:xxx|SIZE:yyy)`.
   - Mendeteksi directory discovery `==> DIRECTORY: URL`.
   - Menghubungkan header `LOCATION: URL` pada baris berikutnya sebagai `redirect_location` endpoint terkait.
5. **`reconx/tools/gobuster.py` (`GobusterAdapter`)**:
   - Subclass `ToolAdapter` dengan `resource_class = "discovery"`.
   - Membangun argumen aman: `["gobuster", "dir", "-u", target, "-w", wordlist, "-q", "--no-error", "--no-progress", "-t", str(threads), "--timeout", "...s"]`.
   - Ekstraksi versi via `gobuster --version`.
6. **`reconx/tools/ffuf.py` (`FFUFAdapter`)**:
   - Subclass `ToolAdapter` dengan `resource_class = "discovery"`.
   - Membangun argumen aman dengan injeksi placeholder fuzzing otomatis jika belum ada (`.../FUZZ`): `["ffuf", "-u", fuzz_url, "-w", wordlist, "-json", "-s", "-noninteractive", "-t", str(threads), "-timeout", str(timeout_seconds)]`.
   - Ekstraksi versi via `ffuf -V`.
7. **`reconx/tools/dirb.py` (`DirbAdapter`)**:
   - Subclass `ToolAdapter` dengan `resource_class = "discovery"`.
   - Membangun argumen aman: `["dirb", target, wordlist, "-r", "-S", "-l"]` beserta opsi `-z` (delay) dan `-i` (case-insensitive).
   - Ekstraksi versi via parsing banner `DIRB v...`.
8. **`reconx/tools/registry.py`**:
   - Mendaftarkan `GobusterAdapter`, `FFUFAdapter`, dan `DirbAdapter` ke `get_default_registry()` (total 12 tools).
9. **`tests/unit/test_endpoint_parsers.py`**:
   - 11 unit test memverifikasi parsing output Gobuster, FFUF (NDJSON, batch JSON, plain text), dan Dirb (findings, directories, redirect locations, deduplikasi direktori trailing slash, ANSI stripping).
10. **`tests/unit/test_endpoint_adapters.py`**:
    - 31 unit test memverifikasi normalisasi kunci endpoint (termasuk query parameters kanonikal & fragment stripping), validasi input, `EndpointCollection` merging across tools, helper query (`get_by_source`, `get_by_status`, `clear`), kriteria penerimaan Phase 7, metadata adapter, preflight wordlist validation, query versi, integrasi Scheduler ber-konkurensi terbatas (`resource_class="discovery"`), dan ketersediaan tool pada ToolRegistry.

#### Perbaikan Hasil Code Review (Review Findings Resolution):
1. **Pre-flight Wordlist Validation**: Menambahkan `check_wordlist_available()` dan opsi `check_wordlist_exists=True` pada `GobusterAdapter`, `FFUFAdapter`, dan `DirbAdapter` yang memvalidasi keberadaan file wordlist lokal sebelum proses dimulai (`FileNotFoundError`), mencegah error runtime OS subprocess yang tidak terduga.
2. **Canonical Query Parameter & Fragment Handling**: `normalize_endpoint_key()` kini mengurutkan dan menstandarkan query parameter (`?a=1&b=2` identik dengan `?b=2&a=1`) serta membuang client-side fragment `#...`.
3. **Directory Duplicate Suppression pada `DirbParser`**: Menggunakan perbandingan kunci kanonikal (`normalize_endpoint_key`) saat memeriksa duplikasi direktori sehingga variasi trailing slash tidak menghasilkan duplikat.
4. **Validasi Model `DiscoveredEndpoint`**: Memvalidasi bahwa `status_code` dan `content_length` tidak bernilai negatif.
5. **Helper Queries pada `EndpointCollection`**: Menyediakan `get_by_source(source)`, `get_by_status(status_code)`, dan `clear()`.

#### File yang Dibuat / Diubah:
* Dibuat:
  - `reconx/models/endpoint.py`
  - `reconx/parsers/gobuster.py`
  - `reconx/parsers/ffuf.py`
  - `reconx/parsers/dirb.py`
  - `reconx/tools/gobuster.py`
  - `reconx/tools/ffuf.py`
  - `reconx/tools/dirb.py`
  - `tests/unit/test_endpoint_parsers.py`
  - `tests/unit/test_endpoint_adapters.py`
* Diubah:
  - `reconx/models/__init__.py`
  - `reconx/parsers/__init__.py`
  - `reconx/tools/__init__.py`
  - `reconx/tools/registry.py`
  - `tests/unit/test_http_adapters.py`
  - `PROGRESS.md`

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **234 passed, 47 subtests passed** (3.91 detik).
* **Acceptance Criteria Verification**:
  - *"The same endpoint found by multiple tools becomes one normalized observation with multiple sources."*
  - Terverifikasi 100% pada `tests/unit/test_endpoint_adapters.py::TestEndpointModelAndCollection::test_phase7_acceptance_criteria`. Endpoint identik (`/secret`) yang ditemukan oleh `gobuster`, `ffuf`, dan `dirb` digabungkan secara akurat menjadi **satu** objek `Observation(type="discovered_endpoint")` dengan `source="dirb,ffuf,gobuster"` dan `data["sources"]=["dirb", "ffuf", "gobuster"]`.

#### Batasan yang Diketahui:
* Directory enumeration aktif membutuhkan wordlist file (default mengarah ke `/usr/share/dirb/wordlists/common.txt` yang telah terverifikasi ada pada sistem user).
* Vulnerability scanning pada endpoint yang ditemukan (nikto, sqlmap) merupakan ruang lingkup Phase 8.

### Phase 8 — Vulnerability Adapters (Selesai pada 2026-10-07)

Status: COMPLETE

#### Komponen yang Diimplementasikan:
1. **`reconx/models/vulnerability.py` (`ExecutionMode`, `VulnerabilityObservation`, `ToolVulnerabilityResult`)**:
   - `ExecutionMode`: Enum `SAFE` (default), `PASSIVE`, `ACTIVE` untuk mengontrol intensitas dan dampak pengujian kerentanan.
   - `VulnerabilityObservation`: Model `@dataclass(frozen=True)` yang merepresentasikan unvalidated security observation hasil pemindaian tool kerentanan (tool, target, endpoint, title, description, severity, cve, osvdb, parameter, injection_type, execution_mode, raw_data).
   - `ToolVulnerabilityResult`: Kontainer hasil eksekusi tool kerentanan yang menyimpan daftar `VulnerabilityObservation`.
   - `to_observations(asset_id, task_id)`: Mengonversi hasil tool langsung ke list domain `Observation` berjenis `type="vulnerability_hint"`. **Secara ketat memenuhi Kriteria Penerimaan Phase 8: Tool findings TIDAK pernah langsung menjadi objek `Finding` final, melainkan di-buffer sebagai `Observation` perantara untuk korelasi Phase 9.**
2. **`reconx/parsers/nikto.py` (`NiktoParser`)**:
   - Mendukung format output JSON (`-Format json`) dan fallback plain text output Nikto.
   - Ekstraksi target host/port/IP, paths/endpoints, OSVDB IDs, CVE references, dan advisory severity classification (critical/high/medium/low/info).
   - Sanitasi dan pemfilteran baris ringkasan eksekusi Nikto (seperti requests count, start/end time, items checked).
3. **`reconx/parsers/sqlmap.py` (`SqlmapParser`)**:
   - Mem-parse blok temuan SQL injection (`Parameter: <param> (<place>)`, `Type: <type>`, `Title: <title>`, `Payload: <payload>`).
   - Ekstraksi backend DBMS, web application technology, serta OS.
   - Ekstraksi indikator heuristik (`heuristics detected that target parameter might be injectable`) dan fallback ringkasan (`parameter is vulnerable`).
   - Ekstraksi endpoint path dari target URL kanonikal.
4. **`reconx/tools/nikto.py` (`NiktoAdapter`)**:
   - Subclass `ToolAdapter` dengan `resource_class = "vulnerability"`.
   - Membangun argumen aman tanpa shell string: `["nikto", "-host", target, "-nointeractive", "-ask", "no"]`.
   - Modus eksekusi terkonfigurasi:
     - `SAFE`: `-Tuning 1,2,3,b,e`, `-maxtime 300s` (non-destructive, software ID, misconfig, info disclosure).
     - `PASSIVE`: `-Tuning 3,b`, `-maxtime 120s` (banner ID & info disclosure saja).
     - `ACTIVE`: tuning penuh `-Tuning 1,2,3,4,5,7,8,9,0,a,b,c,d,e`, `-maxtime 600s`.
   - Validasi target dan rentang port (1-65535).
   - Ekstraksi versi via parsing output `nikto -Version`.
5. **`reconx/tools/sqlmap.py` (`SqlmapAdapter`)**:
   - Subclass `ToolAdapter` dengan `resource_class = "vulnerability"`.
   - Membangun argumen aman selalu menyertakan `--batch`.
   - Modus eksekusi terkonfigurasi:
     - `SAFE`: `--smart`, `--level 1`, `--risk 1`, `--timeout 10`, `--retries 1`.
     - `PASSIVE`: `--smart`, `--level 1`, `--risk 1`, `--null-connection`, `--timeout 10`, `--retries 1`.
     - `ACTIVE`: bounded testing `--level` (max 3), `--risk` (max 2), `--timeout 10`.
   - Guardrails keamanan: penolakan argumen ofensif/eksploitasi berbahaya (`--os-shell`, `--os-pwn`, `--dump-all`, `--sql-shell`, dll.) dengan `ValueError`.
   - Ekstraksi versi via `sqlmap --version`.
6. **`reconx/tools/registry.py`**:
   - Mendaftarkan `NiktoAdapter` dan `SqlmapAdapter` ke `get_default_registry()` (total 14 tools terdaftar).
7. **`tests/unit/test_vulnerability_parsers.py`**:
   - 10 unit test memverifikasi parsing output Nikto (plain text, JSON, OSVDB, CVE, klasifikasi severity) dan Sqlmap (injection blocks, multiple parameters, DBMS extraction, heuristic detection, endpoint extraction).
8. **`tests/unit/test_vulnerability_adapters.py`**:
   - 25 unit test memverifikasi command generation lintas execution modes (SAFE, PASSIVE, ACTIVE), parameter opsional, validasi port & target, guardrails penolakan opsi berbahaya, parsing versi, ketersediaan binary sistem, registrasi tool, bounded concurrency scheduler (`resource_class="vulnerability"`), serta verifikasi Kriteria Penerimaan Phase 8 (0 Finding diproduksi, hasil berupa Observation ber-type "vulnerability_hint").

#### Perbaikan Hasil Code Review (Review Findings Resolution):
1. **Dukungan Non-Zero Exit Code dengan Observasi Valid pada Base Adapter (`reconx/tools/base.py`)**:
   - Memperluas evaluasi `has_data` pada closure `create_task` di `ToolAdapter` agar memeriksa keberadaan `observations` dan koleksi berukuran `> 0`. Dengan perbaikan ini, jika biner scanner (seperti Nikto) keluar dengan exit code 1 namun berhasil mengekstrak observasi kerentanan yang valid, task ditandai `COMPLETED` dan hasilnya dipreservasi, bukan gagal (`FAILED`).
2. **Pencegahan Pemotongan Versi pada Judul Temuan Nikto (`reconx/parsers/nikto.py`)**:
   - Mengubah splitting judul temuan dari `msg.split(".")[0]` menjadi `re.split(r"\.\s+", msg)[0]`. Ini mencegah judul banner seperti `Server: Apache/2.4.41 (Ubuntu)` terpotong di titik desimal menjadi `Server: Apache/2`.
   - Memperkuat filter baris ringkasan Nikto dengan mencakup `reported on remote host`, `host(s) tested`, dan `error(s) and`.
3. **Regex Spasi & Kurung Bersarang pada Parameter Sqlmap (`reconx/parsers/sqlmap.py`)**:
   - Memperbarui `PARAMETER_HEADER_REGEX` agar dapat mengekstrak nama parameter dengan spasi dan kurung bersarang (misal `Parameter: JSON username ((custom) POST)`), serta menormalisasi line endings `\r\n` / `\r` ke `\n`.
4. **Penguatan Guardrails Eksploitasi pada Sqlmap (`reconx/tools/sqlmap.py`)**:
   - Memperluas `DISALLOWED_FLAGS` dengan menyertakan flag eksfiltrasi data dan dump skema (`--dump`, `--dbs`, `--passwords`, `--schema`), memastikan adapter secara ketat hanya berfungsi untuk deteksi dan asesmen kerentanan.
5. **Konsistensi Ukuran Registry pada Test Suite HTTP (`tests/unit/test_http_adapters.py`)**:
   - Mengubah asersi strict equality `assert len(reg) == 9` menjadi `assert len(reg) >= 9` dan pengujian keanggotaan list, konsisten dengan seluruh test suite Phase 4, 5, 7, dan 8.

#### File yang Dibuat / Diubah:
* Dibuat:
  - `reconx/models/vulnerability.py`
  - `reconx/parsers/nikto.py`
  - `reconx/parsers/sqlmap.py`
  - `reconx/tools/nikto.py`
  - `reconx/tools/sqlmap.py`
  - `tests/unit/test_vulnerability_parsers.py`
  - `tests/unit/test_vulnerability_adapters.py`
* Diubah:
  - `reconx/models/__init__.py`
  - `reconx/parsers/__init__.py`
  - `reconx/tools/__init__.py`
  - `reconx/tools/base.py`
  - `reconx/tools/registry.py`
  - `tests/unit/test_http_adapters.py`
  - `PROGRESS.md`

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **270 passed, 47 subtests passed** (3.50 detik).
* **Acceptance Criteria Verification**:
  - *"Tool findings do not directly become final vulnerabilities; they pass through validation/correlation."*
  - Terverifikasi 100% pada `tests/unit/test_vulnerability_adapters.py::TestPhase8AcceptanceCriteria::test_tool_findings_produce_observations_not_final_findings`. Seluruh output scanner dikonversi secara kanonikal ke `Observation(type="vulnerability_hint")`, dan **tepat 0 instance `Finding`** yang diproduksi pada Phase 8.

#### Batasan yang Diketahui:
* Korelasi temuan, deduplikasi antar-tool, confidence scoring, dan pembuatan entitas `Finding` final diselesaikan pada Phase 9.
* CVSS scoring (CVSS 3.1 & 4.0) merupakan ruang lingkup Phase 10 (Risk engine).

---

### Phase 9 — Finding Intelligence (Selesai pada 2026-10-07)

#### Komponen yang Diimplementasikan:
1. **`reconx/engine/classification.py` (`VulnerabilityClassifier`, `VulnerabilityCategory`, `ClassificationResult`)**:
   - Pemetaan taksonomi standar keamanan:
     - **OWASP Top 10 (2021)**: `A01:2021-Broken Access Control`, `A02:2021-Cryptographic Failures`, `A03:2021-Injection`, `A05:2021-Security Misconfiguration`, `A07:2021-Identification and Authentication Failures`, `A10:2021-Server-Side Request Forgery`, dll.
     - **Common Weakness Enumeration (CWE)**: `CWE-89` (SQLi), `CWE-78` (OS Command Injection), `CWE-79` (XSS), `CWE-22` (Path Traversal/LFI), `CWE-548` (Directory Indexing), `CWE-693` (Security Headers), `CWE-1004` (Cookie Flags), `CWE-200` (Information Exposure), `CWE-552` (Sensitive Files), `CWE-1392` (Default Credentials), `CWE-319` (Cleartext/TLS), `CWE-918` (SSRF), dll.
     - **Kategori Kanonikal**: `INJECTION`, `BROKEN_ACCESS_CONTROL`, `SECURITY_MISCONFIGURATION`, `CRYPTOGRAPHIC_FAILURES`, `INFORMATION_DISCLOSURE`, `AUTH_FAILURES`, `NETWORK_EXPOSURE`, `VULNERABLE_COMPONENTS`, dll.
     - **Tingkat Keparahan Dasar (Baseline Severity)**: Pemetaan default `Severity.INFO`, `Severity.LOW`, `Severity.MEDIUM`, `Severity.HIGH`, `Severity.CRITICAL`.
   - Ekstraksi otomatis identifier CVE via regex `CVE-\d{4}-\d{4,7}`.
   - Panduan remediasi terstruktur untuk setiap kategori kerentanan.

2. **`reconx/engine/confidence.py` (`ConfidenceScorer`, `ConfidenceAssessment`)**:
   - Skoring keyakinan multi-sumber independen pada rentang matematis ketat `[0.0, 1.0]`.
   - **Bobot Keandalan Tool Dasar**:
     - `sqlmap`: `0.85` (mesin verifikasi payload injeksi aktif)
     - `openssl`: `0.80` (inspeksi kriptografi langsung)
     - `nmap` / `curl`: `0.75` (probe port aktif / klien HTTP presisi)
     - `gobuster` / `ffuf`: `0.70` (enumerasi direktori tervalidasi baseline)
     - `dirb`: `0.65`
     - `nikto`: `0.50` (scanner tanda tangan web berbasis heuristik)
   - **Formula Penguatan Korelasi Multi-Tool (Corroboration Boost)**:
     - Menggabungkan probabilitas independen kegagalan deteksi:
       $$\text{Confidence}_{\text{combined}} = 1 - \prod_{k \in \text{tools}} (1 - c_k)$$
     - Corroboration antar tool independen (misal Nikto 0.50 + Sqlmap 0.85) mengangkat skor menjadi **0.93** (High/Confirmed).
     - Penguatan observasi ganda internal tool (intra-tool reinforcement) dengan pembatasan ceiling aman (`0.99`).
   - Penjelasan rasionalitas skoring (`rationale`) yang transparan dan dapat diaudit.

3. **`reconx/engine/deduplication.py` (`VulnerabilityDeduplicator`, `DeduplicationFingerprint`)**:
   - **Normalisasi URL & Endpoint**: Skema dan host lowercase, penghapusan port default (80/443), kolaps slash ganda, pengurutan parameter query, dan pembersihan parameter cache-buster ephemeral (`_`, `cachebust`, `timestamp`).
   - **Normalisasi Parameter**: Lowercase, pembersihan dekorasi request method/bracket.
   - **Tiga Tingkat Lingkup Deduplikasi (Deduplication Scopes)**:
     - `parameter`: Untuk kelemahan injeksi dengan parameter spesifik (misal SQLi pada `q` di endpoint `/search.php`).
     - `endpoint`: Untuk kelemahan spesifik URL (misal LFI, backup file exposed, directory indexing).
     - `host`: Untuk miskonfigurasi tingkat situs (misal ketiadaan header `X-Frame-Options` pada puluhan halaman berbeda di host yang sama agar tidak menyebabkan alert fatigue).
   - Fingerprint deterministik SHA-256 untuk pengelompokan (*clustering*) observasi identik lintas tool.

4. **`reconx/engine/correlation.py` (`FindingCorrelator`, `CorrelationResult`)**:
   - Mengorkestrasi klasifikasi, deduplikasi, skoring keyakinan, dan pengayaan bukti menjadi entitas domain final `Finding`.
   - **Sintesis Severity**: Memilih tingkat keparahan tertinggi yang terdeteksi secara valid di dalam kelompok observasi.
   - **Pengayaan Bukti & Provenans (Evidence Enrichment)**: Menautkan `observation_ids` dan `evidence_ids` tanpa duplikat ke instance `Finding`.
   - Pembuatan judul kanonikal dan deskripsi teknis mendalam yang mencakup taksonomi (CWE/OWASP), ringkasan observasi per tool, rasionalitas keyakinan, dan langkah mitigasi.

5. **`reconx/engine/discovery.py` (`DiscoveryEngine`, `DiscoveryInventory`)**:
   - Mensintesis observasi penemuan aset:
     - Endpoint web terdeduplikasi dari gobuster, ffuf, dirb, curl.
     - Port dan layanan jaringan dari nmap dan openssl.
     - Subdomain dan rekaman DNS dari dig, host, nslookup.

6. **`reconx/engine/__init__.py`**:
   - Ekspor publik modul engine yang bersih dan terstruktur.

7. **`tests/unit/test_finding_intelligence.py`**:
   - 28 unit test komprehensif menguji klasifikasi (CWE/OWASP/CVE), formula skoring keyakinan, normalisasi URL & parameter, deduplikasi 3-tier, pengayaan bukti, discovery inventory, dan verifikasi kriteria penerimaan Phase 9.

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **298 passed, 47 subtests passed** (3.82 detik).
* **Acceptance Criteria Verification**:
  - *"Multiple observations can produce a single high-confidence finding."*
  - Terverifikasi 100% pada `tests/unit/test_finding_intelligence.py::TestPhase9AcceptanceCriteria::test_multiple_observations_produce_single_high_confidence_finding`.
  - Observasi heuristik Nikto (0.50) dan konfirmasi aktif Sqlmap (0.85) pada target `/login.php` disintesis menjadi **tepat 1 instance `Finding`** dengan `confidence = 0.93` (elevated high-confidence), menautkan kedua ID observasi dan kedua ID bukti, dengan klasifikasi `CWE-89` / `A03:2021-Injection` dan `Severity.HIGH`.

#### Batasan yang Diketahui:
* CVSS 3.1 dan 4.0 calculator, vector generation, dan severity mapping kalkulatif merupakan ruang lingkup Phase 10 (Risk engine).

---

### Phase 10 — Risk Engine (Selesai pada 2026-10-08)

#### Komponen yang Diimplementasikan:
1. **`reconx/risk/cvss31.py` (`CVSS31Calculator`, `CVSS31Metrics`, `round_up`, `score_to_severity`)**:
   - Kalkulator Base Score CVSS v3.1 sesuai standar resmi FIRST.org (Specification Document Section 7).
   - Implementasi presisi `round_up(val)` sesuai Section 7.4 toleransi round up ke 0.1 terdekat.
   - Perhitungan Exploitability sub-score, Impact Sub-Score (ISS), dan penanganan Scope Unchanged vs Changed ($7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15}$ vs $6.42 \times \text{ISS}$).
   - Pembobotan Privileges Required dinamis berdasarkan status Scope.
   - Parser dan generator vektor kanonikal CVSS v3.1 (`CVSS:3.1/AV:../AC:../PR:../UI:../S:../C:../I:../A:..`) dengan validasi metrik ketat dan dukungan urutan metrik arbitrer.
   - Pemetaan kualitatif skor ke `Severity` (INFO: 0.0, LOW: 0.1-3.9, MEDIUM: 4.0-6.9, HIGH: 7.0-8.9, CRITICAL: 9.0-10.0).

2. **`reconx/risk/cvss40.py` (`CVSS40Calculator`, `CVSS40Metrics`, `score_to_severity`)**:
   - Kalkulator Base Score CVSS v4.0 sesuai standar resmi FIRST.org (Specification Document).
   - Tabel lookup MacroVector resmi (`CVSS_LOOKUP_GLOBAL`) yang mencakup 270 pemetaan kombinasi MacroVector ($EQ_1 \dots EQ_6$).
   - Penentuan MacroVector deterministik untuk Exploitability ($EQ_1$), Complexity ($EQ_2$), Vulnerable System Impact ($EQ_3$), Subsequent System Impact ($EQ_4$), Exploit Maturity ($EQ_5$), dan Requirements Context ($EQ_6$).
   - Algoritma interpolasi jarak keparahan tingkat metrik (metric distance interpolation) dan pembulatan standard FIRST.org `ROUND_HALF_UP` ke 0.1.
   - Parser dan generator vektor kanonikal CVSS v4.0 (`CVSS:4.0/AV:../AC:../AT:../PR:../UI:../VC:../VI:../VA:../SC:../SI:../SA:..`).

3. **`reconx/risk/scoring.py` (`RiskEngine`, `RiskAssessment`, `ReviewStatus`)**:
   - Model `RiskAssessment` yang terstruktur dan immutable (`frozen=True`) mencakup `cvss_version`, `base_score`, `severity`, `vector`, `review_status`, `scoring_rationale`, `review_reasons`, dan `finding_id`.
   - **Manual Review Status Tracking**:
     - `ReviewStatus.ASSESSED`: Diberikan ketika metrik kerentanan terkonfirmasi, menghasilkan base score kalkulatif, vektor kanonikal, dan rasionalitas skoring transparan tanpa spekulasi.
     - `ReviewStatus.REQUIRES_REVIEW`: Diberikan ketika bukti kerentanan bersifat heuristik/ambigu/belum terklasifikasi, menjaga integritas agar tidak memunculkan presisi palsu (*anti-hallucination*). `base_score` dan `vector` disetel secara eksplisit ke `None`, disertai rincian `review_reasons`.
   - **Arketipe Kerentanan Deterministik**:
     - Mendukung arketipe berbasis bukti umum: `sqli`, `rce`, `xss`, `path_traversal`, `sensitive_files`, `directory_indexing`, `missing_headers`, `insecure_cookie`, `cleartext_tls`, `ssrf`.
     - Metode `assess_vector(vector_str)` untuk mengkalkulasi dan memverifikasi vektor CVSS 3.1 maupun CVSS 4.0 eksternal.

4. **`reconx/risk/__init__.py`**:
   - Ekspor publik modul risk engine yang bersih dan terpadu.

5. **`tests/unit/test_risk_engine.py`**:
   - 17 unit test mencakup:
     - Standar `round_up` CVSS 3.1 & vektor acuan resmi (9.8, 7.5, 6.1, 1.6, 0.0).
     - Standar MacroVector CVSS 4.0 & vektor acuan resmi (10.0, 9.3, 5.1, 0.0).
     - Validasi parsing vektor, penolakan format cacat atau metrik ilegal.
     - Penilaian temuan arketipe CVSS 3.1 dan CVSS 4.0.
     - Penanganan temuan ambigu ke `ReviewStatus.REQUIRES_REVIEW`.
     - Evaluasi vektor input pengguna / scanner eksternal.
     - Uji penegakan Acceptance Criteria Phase 10.

#### File yang Dibuat / Diubah:
- `reconx/risk/__init__.py`
- `reconx/risk/cvss31.py`
- `reconx/risk/cvss40.py`
- `reconx/risk/scoring.py`
- `tests/unit/test_risk_engine.py`
- `PROGRESS.md`

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **316 passed, 47 subtests passed** (3.59 detik).
* **Acceptance Criteria Verification**:
  - *"Every risk score has a reproducible vector/rationale or is explicitly marked as requiring review."*
  - Terverifikasi 100% pada `tests/unit/test_risk_engine.py::TestPhase10AcceptanceCriteria::test_acceptance_criteria_invariant_across_sample_suite`.
  - Pada setiap temuan yang diuji lintas CVSS 3.1 dan CVSS 4.0:
    - Jika `ReviewStatus.ASSESSED`: skor dan vektor selalu ada, rasionalitas lengkap, dan penghitungan ulang dari string vektor menghasilkan skor yang tepat identik dengan skor penilaian (bukti reprodusibilitas 100%).
    - Jika `ReviewStatus.REQUIRES_REVIEW`: `base_score` dan `vector` bernilai `None`, rasionalitas penilaian menjelaskan keterbatasan bukti, dan `review_reasons` menyertakan alasan spesifik perlunya validasi analis.

#### Batasan yang Diketahui:
* Generator laporan multiformat (JSON, Markdown, HTML, PDF) merupakan ruang lingkup Phase 11 (Reporting Engine).

---

### Phase 11 — Reporting Engine (Selesai pada 2026-10-08)

#### Komponen yang Diimplementasikan:
1. **`reconx/reporting/redaction.py` (`SecretRedactor`)**:
   - Sistem pencegahan kebocoran rahasia otomatis (*automated secret redaction by default*) mematuhi `Implementation.md` Section 28 & `Agent-rules.md` Section 22.
   - Mendeteksi dan mereduksi private keys (`-----BEGIN ... PRIVATE KEY-----`), JWT tokens (`ey...`), Bearer & Basic authentication tokens, password/API key dalam teks query string/header, cookie sesi sensitif (`PHPSESSID`, `JSESSIONID`, `connect.sid`, dll.), dan AWS access keys.
   - Mendukung sanitasi teks arbitrer serta traversi rekursif struktur data bersarang (`dict`, `list`, `tuple`).

2. **`reconx/reporting/model.py` (`ReportModel`, `ExecutiveSummary`, `AttackSurfaceSummary`, `ReportFinding`, `ReportAppendix`)**:
   - Model laporan kanonikal immutable (`frozen=True`) yang menjadi *single source of truth* untuk seluruh format output.
   - **Executive Summary**: target, tanggal, durasi presisi, ringkasan ruang lingkup otorisasi, total aset, total temuan, matriks distribusi keparahan (CRITICAL, HIGH, MEDIUM, LOW, INFO), dan ringkasan risiko CVSS tertinggi.
   - **Attack Surface Summary**: domains & hostnames, IP addresses, port & protocol, layanan terdeteksi, endpoint & URL, serta teknologi yang teridentifikasi.
   - **Report Finding**: ID temuan, judul kanonikal, keparahan, confidence score & level, CVSS version, score, vector, review status, rationale, aset terdampak, endpoint, deskripsi teknis, analisis dampak, bukti tereduksi report-safe, panduan remediasi terstruktur, dan referensi CWE/CVE/OWASP.
   - **Report Appendix**: versi ReconX, versi binary tool eksternal, konfigurasi scan, modul yang dieksekusi, serta log task yang tidak selesai atau error diagnostik.
   - Metode `from_scan_state(state)` untuk mengonstruksi laporan secara otomatis dari persistensi `ScanState`.

3. **`reconx/reporting/json_renderer.py` (`JSONReportRenderer`)**:
   - Generator laporan JSON kanonikal yang terstruktur dan machine-readable (`json.dumps` dengan indentasi standar dan serialisasi penuh).

4. **`reconx/reporting/markdown_renderer.py` (`MarkdownReportRenderer`)**:
   - Generator laporan GitHub-flavored Markdown profesional yang dilengkapi tabel metrik eksekutif, tabel attack surface, kartu temuan per tingkat keparahan, blok kode bukti, dan lampiran teknis.

5. **`reconx/reporting/html_renderer.py` (`HTMLReportRenderer`)**:
   - Generator laporan HTML5 modern mandiri (*standalone & self-contained*), offline-ready tanpa ketergantungan CDN eksternal.
   - Tema gelap responsif (*dark dashboard*), kartu statistik eksekutif, kotak distribusi keparahan dengan aksen warna standar industri, tabel attack surface, kartu kerentanan yang rapi, dan proteksi XSS penuh (`html.escape` pada seluruh nilai dinamis).

6. **`reconx/reporting/pdf_renderer.py` (`PDFReportRenderer`)**:
   - Generator dokumen PDF 1.4 multi-halaman berbasis Python murni standard library (**zero third-party dependencies**).
   - Dilengkapi layout engine halaman (Letter 612x792 pt), text-wrapping otomatis, font Type1 standar (Helvetica, Helvetica-Bold, Courier), penomoran halaman dinamis, running header & footer rahasia, kotak penanda keparahan, serta tabel xref dan trailer PDF yang valid.

7. **`reconx/reporting/engine.py` (`ReportingEngine`)**:
   - Orkestrator terpadu untuk merender (`render(model, format)`) dan mengekspor (`export(model, path)`) laporan ke disk dengan inferensi format otomatis dari ekstensi file (`.json`, `.md`, `.html`, `.pdf`).

8. **`reconx/reporting/__init__.py`**:
   - Ekspor publik modul pelaporan yang bersih dan terstruktur.

9. **`tests/unit/test_reporting.py`**:
   - 18 unit test komprehensif menguji secret redactor, ReportModel serialization, JSON, Markdown, HTML (termasuk uji pencegahan XSS), PDF structure & multi-page pagination, file export, dan pembuktian kriteria penerimaan Phase 11.

#### File yang Dibuat / Diubah:
- `reconx/reporting/__init__.py`
- `reconx/reporting/redaction.py`
- `reconx/reporting/model.py`
- `reconx/reporting/json_renderer.py`
- `reconx/reporting/markdown_renderer.py`
- `reconx/reporting/html_renderer.py`
- `reconx/reporting/pdf_renderer.py`
- `reconx/reporting/engine.py`
- `tests/unit/test_reporting.py`
- `PROGRESS.md`

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **335 passed, 47 subtests passed** (3.78 detik).
* **Acceptance Criteria Verification**:
  - *"All formats originate from the same ReportModel."*
  - Terverifikasi 100% pada `tests/unit/test_reporting.py::TestPhase11AcceptanceCriteria::test_all_formats_originate_from_same_report_model`.
  - Tepat satu instance `ReportModel` kanonikal yang sama dialirkan ke keempat renderer (JSON, Markdown, HTML, PDF), membuktikan kesamaan target, scan ID, seluruh judul dan keparahan temuan, distribusi risiko, inventaris attack surface, dan penegakan reduksi rahasia tanpa inkonsistensi logika bisnis.

#### Batasan yang Diketahui:
* Mekanisme optimasi performa scheduler, I/O, subprocess, dan operasi database merupakan ruang lingkup Phase 13 (Performance Optimization).

---

### Phase 12 — Profiles and Scan Resume (Selesai pada 2026-10-08)

#### Komponen yang Diimplementasikan:
1. **YAML Profiles (`profiles/*.yaml`)**:
   - `profiles/quick.yaml`: Pemindaian cepat dengan modul penting (DNS, network, HTTP), batas timeout rendah (10s), dan concurrency global 15.
   - `profiles/passive.yaml`: Pemindaian pasif (OSINT/DNS saja) tanpa probing port aktif, mode `passive`, concurrency global 8.
   - `profiles/network.yaml`: Pemetaan infrastruktur jaringan dan deteksi port/layanan aktif (DNS + network), mode `active`, concurrency global 10.
   - `profiles/web.yaml`: Footprinting aplikasi web komprehensif (DNS + HTTP + TLS + direktori + Nikto), mode `active`, concurrency global 12.
   - `profiles/full.yaml`: Pemindaian menyeluruh mencakup seluruh modul termasuk pengujian kerentanan aktif (Nikto + SQLMap), mode `active`, concurrency global 20.

2. **`reconx/config/profiles.py` (`ScanProfile`, `ProfileLoader`, `load_profile`)**:
   - Dataclass `ScanProfile` memodelkan konfigurasi operasional: `name`, `description`, `mode` (`safe`, `passive`, `active`), `modules`, `concurrency`, `timeouts`, `wordlists`.
   - Validasi ketat mode scan, nilai concurrency positif, dan timeout non-negatif.
   - Konversi langsung profil ke `SchedulerConfig` (`to_scheduler_config()`).
   - Penegakan hierarki prioritas ketat (Section 23 `Implementation.md`):
     ```text
     defaults → profile → CLI arguments
     ```
   - Fitur `apply_overrides` mendukung penimpaan dinamis dari argumen CLI (override per modul, flag enable/disable modules, concurrency global/spesifik, timeout default/spesifik, wordlist).

3. **`reconx/storage/repository.py` (`ScanRepository.list_scans`)**:
   - Penambahan metode query `list_scans()` untuk membaca daftar sesi pemindaian tersimpan dari database SQLite, terurut berdasarkan timestamp pembuatan terbaru (`created_at DESC`).

4. **`reconx/session/manager.py` (`ScanSessionManager`)**:
   - Orkestrator lifecycle sesi scan persisten: `create_session()`, `save_session()`, `load_session()`, `list_sessions()`, `delete_session()`, `session_exists()`.
   - Mengintegrasikan koneksi SQLite terisolasi dan `ScanRepository` snapshot atomik.

5. **`reconx/session/resume.py` (`ResumeEngine`, `ResumePlan`)**:
   - Penegakan transisi status pemulihan scan sesuai Section 25 `Implementation.md`:
     ```text
     COMPLETED → skip (tidak pernah dijalankan ulang secara sia-sia)
     FAILED    → retry sesuai kebijakan retry_policy / force_retry
     TIMEOUT   → retry
     CANCELLED → retry
     RUNNING   → recover safely (reset ke PENDING, bersihkan state transien)
     PENDING   → execute
     ```
   - Rekonstruksi graf DAG sadar dependensi:
     - Mengidentifikasi task yang telah selesai (`completed_ids`).
     - Menghapus prerequisite yang telah `COMPLETED` dari himpunan `task.dependencies` pada task yang tersisa (`satisfied_dependencies`), sehingga scheduler tidak terhambat menunggu task yang tidak dimasukkan ke antrean.
     - Task yang memiliki dependensi belum selesai (misalnya dependensi yang sedang di-retry) tetap mempertahankan relasi dependensinya.
   - Pembuatan scheduler terisi task yang tervalidasi (`create_scheduler()`).
   - Penggabungan hasil eksekusi pemulihan ke dalam `ScanState` (`merge_execution_summary()`).

6. **`reconx/session/__init__.py`**:
   - Ekspor publik modul sesi dan resume yang bersih: `ScanSessionManager`, `ResumeEngine`, `ResumePlan`.

7. **`tests/unit/test_profiles_and_resume.py`**:
   - 23 unit test komprehensif menguji:
     - Atribut profil default dan penemuan built-in profiles.
     - Karakteristik masing-masing profil (`quick`, `passive`, `network`, `web`, `full`).
     - Hierarki prioritas: `defaults -> profile -> CLI overrides`.
     - Parsing custom YAML profil dari file eksternal.
     - Validasi mode, concurrency, dan penanganan profil tidak ditemukan.
     - Persistensi sesi: create, load, list, delete, exists, exception handling.
     - Transisi status Section 25 untuk seluruh 6 status task.
     - Penanganan task gagal yang telah melampaui batas retry.
     - Rekonstruksi dependensi DAG pada task lanjutan.
     - Pembuktian kriteria penerimaan Phase 12.

#### File yang Dibuat / Diubah:
- `profiles/quick.yaml`
- `profiles/passive.yaml`
- `profiles/network.yaml`
- `profiles/web.yaml`
- `profiles/full.yaml`
- `reconx/config/__init__.py`
- `reconx/config/profiles.py`
- `reconx/storage/repository.py`
- `reconx/session/__init__.py`
- `reconx/session/manager.py`
- `reconx/session/resume.py`
- `tests/unit/test_profiles_and_resume.py`
- `PROGRESS.md`

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **358 passed, 47 subtests passed** (4.24 detik).
* **Acceptance Criteria Verification**:
  - *"An interrupted scan can continue without unnecessarily repeating completed tasks."*
  - Terverifikasi 100% pada `tests/unit/test_profiles_and_resume.py::TestPhase12AcceptanceCriteria::test_interrupted_scan_resumes_without_repeating_completed_tasks`.
  - Simulasi scan yang terinterupsi saat eksekusi: Task 1 (`dns`) telah `COMPLETED`, Task 2 (`http`, bergantung pada Task 1) berstatus `RUNNING` saat proses terputus, dan Task 3 (`dir`, bergantung pada Task 2) berstatus `PENDING`.
  - Saat sesi di-resume dari SQLite:
    - Task 1 secara otomatis di-`skip` dan **sama sekali tidak dieksekusi ulang** (0 panggilan pada command runner).
    - Task 2 dipulihkan dengan aman (`RUNNING -> PENDING`), dependensinya terhadap Task 1 ditandai terpenuhi sehingga dapat langsung dieksekusi.
    - Task 2 dan Task 3 dieksekusi hingga selesai (`COMPLETED`), dan status scan akhir tersimpan sebagai `COMPLETED`.

#### Batasan yang Diketahui:
* Hardening produksi (audit keamanan terpadu, packaging distribusi, dan full CLI pipeline) merupakan ruang lingkup Phase 14 dan Phase 15.

---

### Phase 13 — Performance Optimization (Selesai pada 2026-10-08)

#### Prinsip Utama:
Mengikuti Section 34 & 35 `Implementation.md` serta `Agent-rules.md` (Rule 5, 6, 37):
1. **"Measure First"**: Optimasi hanya dilakukan dengan observabilitas terukur (tasks/sec, average task duration, tool execution breakdown, parser overhead, scheduler latency).
2. **Standard Library Only**: Tidak menambah dependensi baru; menggunakan modul bawaan Python (`heapq`, `functools.lru_cache`, `dataclasses`, `time`, `re`).
3. **Fail-Safe & Backward-Compatible**: Semua model dan antarmuka lama tetap kompatibel 100%.

#### Komponen yang Diimplementasikan:
1. **Observabilitas & Pengukuran (`reconx/core/metrics.py`)**:
   - Dataclass `PerformanceMetrics`:
     - Mencatat throughput scan (`tasks_total`, `tasks_completed`, `tasks_failed`, `tasks_cached`, `tasks_deduplicated`).
     - Metrik durasi (`total_execution_time`, `average_task_duration`, `tasks_per_second`, `scheduler_overhead_seconds`).
     - Breakdown per sub-sistem (`tool_execution_time: dict[str, float]`, `parser_execution_time: dict[str, float]`).
     - Efisiensi cache (`cache_hits`, `cache_misses`, `cache_hit_ratio`).
     - Format laporan observabilitas `format_report()` kanonikal yang sesuai dengan Section 35 `Implementation.md` (`SCAN PERFORMANCE`).
   - `PerformanceProfiler`:
     - Pengukur terpadu yang thread-safe dengan context manager (`measure_tool`, `measure_parser`, `measure_task`).
     - Pencatat event dinamis (`record_cache_hit`, `record_cache_miss`, `record_deduplication`).
     - Metode agregasi `compute_metrics()` yang otomatis menghitung rasio dan rata-rata performa.
     - Singleton accessor `get_global_profiler()` untuk integrasi lintas modul.

2. **Caching & Deduplikasi Terdistribusi (`reconx/core/caching.py`)**:
   - `make_cache_key(tool, target, args)`: Pembangkit key SHA-256 deterministik berbasis normalisasi target dan argumen string.
   - `ResultCache`:
     - Cache in-memory thread-safe (`threading.Lock`) dengan Time-To-Live (TTL, default 1800s) dan batas kapasitas (`maxsize`, default 1024 entri).
     - Menyimpan dan menyajikan `TaskResult` hasil eksekusi sebelumnya, menandai `is_cached=True` sehingga scheduler tidak perlu melakukan spawning subprocess yang mahal.
   - `TaskDeduplicator`:
     - Pelacak fingerprint task kanonikal (`tool:target:args`) thread-safe.
     - Mencegah penambahan task duplikat ke dalam pipeline eksekusi (`add_if_new` dan `filter_duplicates`).

3. **Optimasi Resolusi Subprocess (`reconx/core/runner.py`)**:
   - `@functools.lru_cache(maxsize=128)` disematkan pada fungsi `resolve_executable`.
   - Mengeliminasi query I/O `shutil.which` berulang pada filesystem PATH setiap kali binary perkakas eksternal (seperti `nmap`, `curl`, `dig`) dipanggil.
   - Fungsi `is_available` didelegasikan langsung ke `resolve_executable` ter-cache.

4. **Optimasi Parser & Normalisasi URL (`reconx/engine/deduplication.py` & `reconx/parsers/nmap.py`)**:
   - Pra-kompilasi regex modul-level (`_RE_MULTI_SLASH`, `_RE_PARAM_DECORATION`, `_RE_NMAP_REPORT`, `_RE_IPV4_ADDR`, `_RE_PORT_LINE`) mengeliminasi kompilasi ulang regex berulang kali saat parsing ribuan endpoint/port.
   - LRU caching `@functools.lru_cache(maxsize=4096)` pada `normalize_url`, `extract_url_path`, dan `normalize_parameter` mempercepat deduplikasi URL skala besar secara signifikan.

5. **Tuning Memori SQLite Database (`reconx/storage/database.py`)**:
   - Penambahan PRAGMA performa pada inisialisasi koneksi `open_database`:
     - `PRAGMA temp_store = MEMORY`: Menyimpan temporary tables dan indices langsung di RAM.
     - `PRAGMA cache_size = -32000`: Mengalokasikan ~32 MB page cache per koneksi SQLite di RAM, meminimalkan disk I/O.

6. **Prioritas Min-Heap & Integrasi Scheduler (`reconx/core/scheduler.py`)**:
   - Menggantikan antrean siap list biasa dengan algoritma min-heap menggunakan `heapq` (`_ready_heap`).
   - Setiap elemen heap menggunakan tuple `(-priority, seq, task_id)`:
     - Prioritas tinggi diambil terlebih dahulu ($O(\log N)$ push & pop vs sorting $O(N \log N)$ sebelumnya).
     - Penggunaan `seq` (sequence counter monoton) menjamin determinisme urutan FIFO untuk task dengan prioritas yang identik tanpa membandingkan objek task.
   - Integrasi cache langsung pada `_execute_task`: Jika target dan argumen ditemukan di `ResultCache`, task langsung selesai dengan hasil tersimpan tanpa menjalankan child process.
   - Integrasi deduplikasi pada `add_task`: Task identik yang redundant otomatis ditandai `SKIPPED` dengan catatan deduplikasi.
   - Pelaporan metrik performa otomatis pada `SchedulerSummary.metrics`.

7. **Pengujian Komprehensif (`tests/unit/test_performance.py`)**:
   - 13 unit test baru yang menguji seluruh aspek Phase 13:
     - Siklus hidup profiler dan kalkulasi metrik observabilitas.
     - Kesesuaian format laporan performa Section 35.
     - Determinisme pembuatan key SHA-256 dan kedaluwarsa TTL cache.
     - Filtrasi task duplikat pada `TaskDeduplicator`.
     - Caching resolusi executable `CommandRunner`.
     - LRU caching pada normalisasi URL dan endpoint.
     - Verifikasi pra-kompilasi regex pada Nmap parser.
     - Bypass eksekusi proses subprocess oleh Scheduler saat terjadi cache hit.
     - Pencegahan scheduling duplikat oleh Deduplicator pada Scheduler.
     - Urutan prioritas antrean min-heap Scheduler.

#### File yang Dibuat / Diubah:
- `reconx/core/metrics.py` (baru)
- `reconx/core/caching.py` (baru)
- `reconx/core/__init__.py` (ekspor metrik & caching)
- `reconx/core/runner.py` (LRU cache PATH resolution)
- `reconx/engine/deduplication.py` (regex prekompilasi & LRU cache URL/parameter)
- `reconx/parsers/nmap.py` (regex prekompilasi Nmap)
- `reconx/core/scheduler.py` (min-heap priority queue, integrasi cache & dedup, PerformanceMetrics)
- `reconx/storage/database.py` (SQLite RAM cache PRAGMA tuning)
- `tests/unit/test_performance.py` (baru, 13 test)
- `PROGRESS.md` (pembaruan status dan dokumentasi)

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **371 passed, 47 subtests passed** (4.21 detik).
* **Acceptance Criteria Verification**:
  - *"Performance measurements are visible, scheduler overhead is minimized via min-heap priority queue, redundant executions are eliminated via result caching and deduplication, and database I/O is tuned."*
  - Terverifikasi 100% pada `tests/unit/test_performance.py` (13/13 passed).

#### Batasan yang Diketahui:
* Tidak ada. Seluruh tujuan fungsional dan pengujian performa Phase 13 terpenuhi.

---

### Phase 14 — Production Hardening & Definition of Done (Selesai pada 2026-10-08)

#### Prinsip Utama:
Mengikuti roadmap Phase 14, Section 31, 33, 37 (*Definition of Done*) pada `Implementation.md`, serta `Agent-rules.md`:
1. **Security-First Execution**: Input sanitization ketat, pencegahan command injection, proteksi traversal path, permission audit berkas, dan guardrail opsi destruktif.
2. **Tool Diagnostics**: Pemeriksaan diagnostik terpadu seluruh perkakas eksternal (`reconx tools check`) dengan deteksi path dan versi.
3. **Graceful Shutdown**: Penanganan sinyal `SIGINT` dan `SIGTERM` dengan cooperative cancellation dan callback checkpointing database.
4. **Resilience & Error Recovery**: Taksonomi error terstruktur, degradasi terencana (Section 30), dan penjaminan kelangsungan scan saat tool gagal.
5. **Report Integrity**: Validasi otomatis schema report, integritas hitungan keparahan, batas CVSS (0.0–10.0), serta deteksi kebocoran rahasia tak tereduksi.
6. **Packaging & CLI**: Paket distribusi terstandarisasi (`pyproject.toml`, PEP 561 `py.typed`), CLI entrypoint, dan dokumentasi arsitektur/manual lengkap.

#### Komponen yang Diimplementasikan:
1. **Tool Diagnostics (`reconx/tools/diagnostics.py`)**:
   - `ToolStatus` (`AVAILABLE`, `MISSING`, `BROKEN`, `UNKNOWN`).
   - `ToolDiagnosticItem` dan `ToolDiagnosticReport` yang memformat tabel status perkakas persis sesuai Section 31.
   - `DiagnosticEngine` yang memeriksa ketersediaan PATH (`shutil.which`) dan menjalankan probe versi secara aman.

2. **Security Auditing & Guardrails (`reconx/security/audit.py` & `reconx/security/__init__.py`)**:
   - `TargetSecurityValidator`: Validasi sintaks target (RFC domain, IPv4, IPv6, CIDR, URL) dan penolakan keras karakter metakarakter shell (`;`, `&`, `|`, `` ` ``, `$`, `\n`, quotes, null bytes) serta argumen flag (`-`).
   - `CommandSafetyAuditor`: Audit array argumen untuk mencegah eksekusi shell (`sh -c`, `bash -c`) dan memblokir opsi destruktif berbahaya pada tool (misal `--os-shell`, `--sql-shell`, `--dump-all` pada sqlmap).
   - `FileSecurityAuditor`: Deteksi path traversal dan audit permission berkas (memastikan izin ketat `0600`/`0640`).
   - `audit_framework_environment()`: Audit runtime lingkungan proses (umask, environment variables).

3. **Graceful Shutdown & Signal Handling (`reconx/core/shutdown.py`)**:
   - `GracefulShutdownHandler`: Menangkap `SIGINT` (Ctrl+C) dan `SIGTERM` pada event loop asyncio / signal module.
   - Membatalkan `CancellationToken`, memicu callback checkpoint SQLite, dan mencegah terbentuknya child process zombie.

4. **Error Recovery & Taxonomy (`reconx/core/recovery.py`)**:
   - Hierarki pengecualian: `ReconXError`, `SecurityError`, `ToolExecutionError`, `ParserError`, `DatabaseError`, `NetworkTimeoutError`.
   - `ErrorRecoveryEngine`: Klasifikasi error (`TRANSIENT`, `DEGRADED`, `CRITICAL`) dan keputusan pemulihan (`RETRY`, `SKIP_DEPENDENTS`, `ABORT`).
   - `checkpoint_scan_state`: Helper penyimpan checkpoint atomik ScanState ke database.

5. **Report Validation & Secret Leak Audit (`reconx/reporting/validation.py`)**:
   - `ReportValidator` & `ValidationResult`:
     - Verifikasi metadata, timestamp ISO 8601, konsistensi distribusi keparahan terhadap jumlah temuan riil.
     - Penegakan rentang skor CVSS (0.0 hingga 10.0) dan confidence (0.0 hingga 1.0).
     - Audit mendalam terhadap teks temuan untuk mendeteksi kunci API, token Bearer, Basic Auth, kunci privat SSH/RSA yang lolos dari reduksi.
     - Pemeriksaan izin berkas laporan (mencegah berkas world-writable).
   - Pengamanan izin ekspor laporan pada `ReportingEngine.export` dengan `os.chmod(0o640)`.

6. **CLI Entrypoint & Command Dispatcher (`reconx/cli.py`)**:
   - Subcommand `tools check`: Diagnostik tool dan format tabel Section 31.
   - Subcommand `scan`: Eksekusi scan end-to-end terpadu (target sanitization -> scope validation -> profile loading -> DAG scheduler -> SQLite session -> reporting).
   - Subcommand `session list`: Query daftar sesi tersimpan.
   - Subcommand `session resume`: Melanjutkan sesi terputus.
   - Flag `--version` dan `--verbose`.

7. **Packaging & Metadata (`pyproject.toml`, `reconx/py.typed`)**:
   - Entry point script: `reconx = "reconx.cli:main"`.
   - Setuptools packaging discovery, dependency declarations, dan PEP 561 typing marker.

8. **Dokumentasi Lengkap & Fixtures**:
   - `README.md`: Ikhtisar proyek, instalasi, dan panduan quick start.
   - `docs/ARCHITECTURE.md`: Arsitektur 5-layer, data flow, model konkurensi, dan batasan keamanan.
   - `docs/CLI.md`: Manual referensi sintaks, opsi, profil, dan kode keluar CLI.
   - `docs/SECURITY.md`: Panduan keamanan etis, batas scope, dan guardrails non-eksploitasi.
   - Fixtures: `tests/fixtures/dig_sample.txt`, `tests/fixtures/nmap_sample.xml`, `tests/fixtures/nikto_sample.txt`.

9. **Pengujian Komprehensif (Unit & Integration Tests)**:
   - `tests/unit/test_diagnostics.py`: Pengujian item diagnostik, format tabel, engine diagnostik (available, missing, broken, filter).
   - `tests/unit/test_security_audit.py`: Pengujian validasi target aman/berbahaya, flag injection, shell wrappers, opsi sqlmap destruktif, audit traversal path, dan audit izin berkas.
   - `tests/unit/test_shutdown.py`: Pengujian signal interception, pembatalan token, dan eksekusi callback shutdown.
   - `tests/unit/test_recovery.py`: Pengujian taksonomi error, pemulihan task aman, dan checkpointing database.
   - `tests/unit/test_report_validation.py`: Pengujian integritas model laporan, deteksi ketidaksesuaian jumlah temuan, deteksi kebocoran rahasia, dan validasi berkas laporan.
   - `tests/unit/test_packaging_and_cli.py`: Pengujian konfigurasi pyproject.toml, parser argumen CLI, dispatch subcommands, dan deteksi target berbahaya.
   - `tests/integration/test_end_to_end.py`: Pengujian integrasi end-to-end vertikal penuh terhadap controlled mock target (Section 37 & 39).

#### Hasil Pengujian:
* `pytest -v --typeguard-packages=reconx`: **426 passed, 47 subtests passed** (4.89 detik).
* **Definition of Done (Section 37) Verification**:
  - Semua adapter menggunakan abstraksi eksekusi bersama (`CommandRunner`).
  - Penegakan scope tersentralisasi (`ScopeValidator`).
  - Dependensi DAG dan bounded multi-class concurrency terverifikasi.
  - Perkakas yang gagal tidak mematikan pemindaian (`ErrorRecoveryEngine`).
  - Observasi ternormalisasi dan deduplikasi temuan berfungsi.
  - Confidence dan severity terpisah; CVSS 3.1 & 4.0 reproducible.
  - Laporan berasal dari ReportModel kanonikal dan tervalidasi via `ReportValidator`.
  - Sesi pemindaian tersimpan dan dapat dilanjutkan via `ResumeEngine`.
  - Rahasia tereduksi dan berkas laporan terproteksi permission.
  - Seluruh perkakas memiliki diagnostik (`reconx tools check`) dan deteksi ketersediaan.
  - Dokumentasi CLI (`docs/CLI.md`), Arsitektur (`docs/ARCHITECTURE.md`), dan Keamanan (`docs/SECURITY.md`) tersedia lengkap.

#### Batasan yang Diketahui:
* Seluruh 14 fase roadmap utama pada `Implementation.md` telah selesai diimplementasikan, diverifikasi, dan dikeraskan untuk produksi.

---

## 3. Panduan Pemulihan Konteks (Jika Agen Di-reset)

Bagi AI Agent yang membaca file ini di sesi berikutnya:

1. **Jadikan `Agent-rules.md` dan `Implementation.md` sebagai sumber kebenaran (Source of Truth)**.
2. **Ketahui batas fase Anda**: Hanya kerjakan fase yang diminta oleh user secara eksplisit. Jangan melompat atau menambahkan fitur spekulatif (No AI-slop).
3. **Validasi lingkungan kerja terlebih dahulu**:
   ```bash
   pytest -v
   ```
   Pastikan seluruh test yang sudah ada tetap lolos sebelum dan sesudah menulis kode baru.
4. **Perbarui `PROGRESS.md`**: Setiap kali ada penambahan kode, pengujian, atau penyelesaian fase baru, perbarui dokumen ini secara berkala.
