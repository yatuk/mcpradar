# MCPRadar Stratejik Gelişim Yol Haritası

> **Son güncelleme:** 2026-06-25 · **Mevcut sürüm:** v1.0.0-rc3 · **Hedef:** v1.0.0 (GA)

---

## Vizyon

MCPRadar, Model Context Protocol (MCP) ekosisteminin **referans güvenlik aracı** olmayı hedefler. Her MCP sunucu geliştiricisinin CI hattında çalıştırdığı, her kurumsal güvenlik ekibinin yapay zeka ajanlarını denetlerken başvurduğu açık kaynak standart.

## Misyon

Tool poisoning, prompt injection, supply-chain rug pull ve cross-server contamination saldırılarını **LLM agent bir tool çağrısı yapmadan önce** yakalamak. Deterministik, CI-dostu, SARIF uyumlu güvenlik taramasını geliştirici iş akışının doğal bir parçası haline getirmek.

---

## Mevcut Durum — v0.1.0 (2026-05-25)

### Tamamlanan Özellikler

| Bileşen | Durum | Detay |
|---|---|---|
| Tespit kuralları | ✅ 6 kural | R001, R101, R102 (10 pattern), R103, R104, R105 |
| Transport katmanı | ✅ 3 protokol | HTTP (streamable), SSE, stdio |
| Veritabanı | ✅ SQLite (WAL) | scans, tools, prompts, resources, findings tabloları |
| Diff motoru | ✅ 3 seviye | cosmetic / behavioral / security sınıflandırma |
| Çıktı formatları | ✅ 3 format | Rich terminal, JSON, SARIF v2.1.0 |
| CI/CD | ✅ Tam matris | Python 3.11–3.13 × ubuntu/macos/windows |
| PyPI publish | ✅ OIDC | GitHub Actions → PyPI trusted publishing |
| Plugin keşif | ✅ Temel | `entry_points(group="mcpradar.rules")` otomatik yükleme |
| Cross-server analiz | ✅ 5 kural | C001–C005 (temel seviye) |
| CVE feed | ✅ Tohum veri | 2 MCP-ilgili CVE, anahtar kelime eşleştirme |
| Watch modu | ✅ Temel | Periyodik tarama + webhook/shell alert |
| Public leaderboard | ✅ GitHub Pages | Statik markdown, manuel güncelleme |
| VS Code uzantısı | ✅ Scaffold | `vscode-mcpradar/` dizini |
| Validasyon pipeline | ⚠️ Hedefler tanımlı | 10 sunucu, henüz tam çalıştırılmadı |

### OWASP MCP Top 10 (2025) Kapsam Matrisi

| OWASP ID | Kategori | Mevcut Kapsam | Seviye |
|---|---|---|---|
| **MCP01** | Token Mismanagement & Secret Exposure | — | ❌ Kapsanmıyor |
| **MCP02** | Privilege Escalation via Scope Creep | R105 (scope pairs) | 🟡 Temel |
| **MCP03** | Tool Poisoning | R001, R104, C001, C002 | 🟡 Kısmi |
| **MCP04** | Supply Chain Attacks | — | ❌ Kapsanmıyor |
| **MCP05** | Command Injection & Execution | R001 (isim eşleşmesi) | 🔴 Minimal |
| **MCP06** | Prompt Injection | R102, R103, R104 | 🟢 Güçlü |
| **MCP07** | Insufficient AuthN/AuthZ | — | ❌ Kapsanmıyor |
| **MCP08** | Lack of Audit & Telemetry | — | ❌ Kapsanmıyor |
| **MCP09** | Shadow MCP Servers | — | ❌ Kapsanmıyor |
| **MCP10** | Context Injection & Over-Sharing | C001–C005 | 🟡 Kısmi |

**Kapsam oranı: 3/10 tam kapsam, 3/10 kısmi, 4/10 kapsam dışı**

### Rakip Karşılaştırması

| Araç | Yaklaşım | MCPRadar Farkı |
|---|---|---|
| **Cisco mcp-scanner** | YARA + LLM + VirusTotal, yalnızca statik | Transport çeşitliliği, diff, SARIF, MIT lisans |
| **Snyk agent-scan** | LLM sınıflandırıcı, CI odaklı, platform-bağımlı | Platform bağımsız, çevrimdışı çalışabilir |
| **Pipelock** | Runtime proxy (Go), canlı trafik | Deterministik, runtime overhead yok |
| **Hermes** | Rust, fuzzing + probing, OWASP-uyumlu | Python ekosistemi, daha basit kural yazımı |
| **agent-audit** | SAST, 40+ kural, taint analysis | MCP transport farkındalığı |
| **MCP Guardian** | Policy-as-code, YAML kuralları, proxy | Agent'dan bağımsız, proxy zorunlu değil |
| **MCPSafetyScanner** | LLM agent ile dinamik fuzzing | Deterministik sonuçlar, CI'da tekrarlanabilir |

---

## Sprint Planı

Tüm sprint'ler 2'şer haftalıktır. Her sprint bir sürüm artışı hedefler ve belirli OWASP kapsam açıklarını kapatır.

---

### 🚀 Sprint 1: "Detection Depth" — Yeni Tespit Kuralları

**Hedef Sürüm:** v0.2.0 · **Süre:** 2 hafta · **OWASP:** MCP01, MCP04, MCP05

#### Hedef

En büyük üç OWASP kapsam açığını kapatmak: gizli kimlik bilgisi ifşası (MCP01), bağımlılık manipülasyonu (MCP04) ve parametreler üzerinden komut enjeksiyonu (MCP05). 4 yeni kural ve 1 mevcut kural iyileştirmesi.

#### Yeni Kurallar

**R106 — Secret/Token Exposure** (`Severity.CRITICAL`)
- Shannon entropi tabanlı yüksek entropili string tespiti
- 15+ bilinen gizli format regex'i: `sk-*`, `ghp_*`, `xoxb-*`, `eyJ*` (JWT), AWS access key, GitHub token, Slack token, OpenAI key, bağlantı string'leri
- Tool name, description, input_schema default değerleri, output_schema taranır
- Entropi > 4.5 VE bilinen format → CRITICAL; sadece entropi > 4.5 → HIGH

**R107 — Command Injection via Tool Parameters** (`Severity.CRITICAL`)
- `input_schema` properties'lerini recursive walk
- Shell metakarakterleri: `$()`, `backticks`, `|`, `;`, `&&`, `||`, `>`, `<`
- Tehlikeli varsayılan değerler: `"rm -rf"`, `"DROP TABLE"`, `"shutdown"`
- `pattern`/`regex` alanlarında aşırı geniş regex desenleri
- `enum` değerlerinde komut benzeri string'ler

**R108 — Supply Chain Risk Indicator** (`Severity.MEDIUM`/`HIGH`)
- Tool description'da harici paket kurulumu referansları: `pip install`, `npm install`, `cargo add`
- URL'den script çalıştırma: `curl \| bash`, `wget -O - \| sh`
- Dinamik kod yükleme: `importlib`, `require()`, `eval()`
- `curl|bash` pattern'i → HIGH, diğerleri → MEDIUM

**R109 — Schema Poisoning Indicator** (`Severity.HIGH`)
- `additionalProperties: true` (arbitrary injection'a açık)
- Tüm parametrelerde tip kısıtlaması eksikliği
- Zorunlu alan yok (boş girdi kabulü)
- Aşırı büyük `maxLength`/`maxItems` (buffer overflow riski)

**R105 İyileştirmesi — Permission Scope Mismatch v2**
- `SCOPE_PAIRS` 3 çiftten 10+ çifte genişletme (crypto/wallet, browser/system, notification/execution)
- snake_case/camelCase tool ismi ayrıştırma (`_decompose_name()` yardımcısı)
- LOW downgrade mantığını kaldır, yerine "bridge keyword" kontrolü

#### Dosya Değişiklikleri

| Dosya | İşlem |
|---|---|
| `src/mcpradar/scanner/rules.py` | R106, R107, R108, R109 sınıfları; R105 genişletme; RuleEngine kayıt |
| `tests/test_rules.py` | 4 yeni test sınıfı, 80+ test vakası |
| `src/mcpradar/output/sarif.py` | RULE_HELP dict genişletme |
| `docs/detection-rules.md` | 4 yeni kural dokümantasyonu |
| `CHANGELOG.md` | v0.2.0 girişi |

#### Tamamlanma Kriterleri

- [x] R106: 25+ parametrize test, 15+ gizli format tespiti
- [x] R107: 20+ test, shell metakarakter + tehlikeli varsayılan + recursive walk
- [x] R108: 15+ test, pip/npm/curl-bash pattern'leri
- [x] R109: 15+ test, schema poisoning vektörleri
- [x] R105: 10+ yeni scope çifti, 10+ test
- [x] mypy strict: sıfır hata
- [x] CI tam matris geçer
- [x] Yeni kod için test coverage ≥ %95

---

### 🧩 Sprint 2: "Plugin Engine" — Topluluk Kural Ekosistemi

**Hedef Sürüm:** v0.3.0 · **Süre:** 2 hafta · **OWASP:** Cross-cutting (tüm kategoriler için topluluk katkısı)

#### Hedef

Mevcut `entry_points` keşif mekanizmasını tam teşekküllü bir eklenti yaşam döngüsü yönetim sistemine dönüştürmek.

#### Yeni Modül: `src/mcpradar/plugin/`

```
src/mcpradar/plugin/
    __init__.py
    manager.py      # PluginManager: kurulum, kaldırma, listeleme, metaveri
    validator.py    # PluginValidator: şema kontrolü, uyumluluk, test çalıştırma
    scaffolder.py   # Scaffolder: şablondan eklenti paketi oluşturma
```

#### Yeni CLI Komutları

```bash
mcpradar plugin init <isim> [-o ./plugins]     # Yeni eklenti iskeleti oluştur
mcpradar plugin validate <dizin>                # Eklenti yapısını doğrula
mcpradar plugin list                            # Yüklü topluluk eklentilerini listele
mcpradar plugin install <paket>                 # pip install + doğrula
mcpradar plugin uninstall <paket>               # pip uninstall
```

#### Plugin Sistemi Özellikleri

- **Scaffolder:** Cookiecutter benzeri şablon değişken değiştirme; `pyproject.toml`, `src/<isim>/__init__.py`, `src/<isim>/rule.py`, `tests/test_rule.py`, `README.md` otomatik oluşturma
- **Validator:** Entry point varlığı, Rule sınıf kalıtımı, rule_id formatı (X###), testlerin geçerliliği
- **Manager:** Plugin metaveri çıkarma (versiyon, yazar), `_discover_plugins()` entegrasyonu

#### Dosya Değişiklikleri

| Dosya | İşlem |
|---|---|
| `src/mcpradar/plugin/__init__.py` | **Yeni** paket |
| `src/mcpradar/plugin/manager.py` | **Yeni** (~200 satır) |
| `src/mcpradar/plugin/validator.py` | **Yeni** (~150 satır) |
| `src/mcpradar/plugin/scaffolder.py` | **Yeni** (~100 satır) |
| `src/mcpradar/cli.py` | `plugin_app` typer alt komutları |
| `src/mcpradar/scanner/rules.py` | `_discover_plugins()` metaveri geliştirmesi |
| `plugins/template/` | test/, README.md, CI şablonu ekleme |
| `tests/test_plugin_loading.py` | 20+ yeni test |
| `docs/writing-rules.md` | Tam eklenti geliştirme rehberi |

#### Tamamlanma Kriterleri

- [x] `mcpradar plugin init` tam çalışan eklenti paketi üretir
- [x] `mcpradar plugin validate` hataları yakalar: eksik entry_point, bozuk rule_id, Rule kalıtımı yok, import hatası
- [x] `mcpradar plugin list` tüm eklentileri versiyon/yazar bilgisiyle gösterir
- [x] 2 örnek topluluk eklentisi (`plugins/` altında)
- [x] Mevcut tüm plugin testleri değişmeden geçer

---

### 🔍 Sprint 3: "Fingerprint & Transport Security" — Sunucu Kimliği

**Hedef Sürüm:** v0.4.0 · **Süre:** 2 hafta · **OWASP:** MCP07, MCP09

#### Hedef

Shadow MCP sunucularını ve yetkisiz sunucu değişimlerini tespit etmek için parmak izi (fingerprint) sistemi. Transport katmanı güvenlik validasyonu.

#### Yeni Modül: `src/mcpradar/fingerprint/`

```python
@dataclass
class ServerFingerprint:
    server_id: str            # SHA256(endpoint + capabilities + tools_hash)
    endpoint: str
    transport: str
    server_version: str       # initialize() yanıtından
    protocol_version: str
    capabilities: dict
    tool_names_hash: str      # SHA256(sıralı tool isimleri)
    tool_count: int
    first_seen: str
    last_seen: str
    tls_info: TLSInfo | None

@dataclass
class TLSInfo:
    version: str              # "TLSv1.3"
    cert_issuer: str
    cert_expiry: str
    cert_valid: bool
    self_signed: bool
```

#### Yeni Kurallar

**R110 — Version Anomaly** (`Severity.HIGH`)
- Cross-scan: önceki fingerprint ile karşılaştırma
- Sürüm düşürme (rollback saldırısı) → CRITICAL
- Beklenmeyen major sürüm atlaması → HIGH
- İlk tarama (baseline yok) → MEDIUM

**R111 — Insecure Transport** (`Severity.HIGH`)
- Düz HTTP (TLS yok) → HIGH
- TLS < 1.2 → CRITICAL
- Sertifika süresi dolmuş → HIGH
- Self-signed sertifika → MEDIUM
- HSTS header eksik → MEDIUM

#### Yeni CLI Komutları

```bash
mcpradar fingerprint <hedef>                # Parmak izi oluştur
mcpradar fingerprint --compare <hedef>      # Baseline ile karşılaştır
```

#### Dosya Değişiklikleri

| Dosya | İşlem |
|---|---|
| `src/mcpradar/fingerprint/__init__.py` | **Yeni** |
| `src/mcpradar/fingerprint/fingerprinter.py` | **Yeni** (~250 satır) |
| `src/mcpradar/fingerprint/transport_check.py` | **Yeni** (~150 satır) |
| `src/mcpradar/scanner/rules.py` | R110, R111 sınıfları; `pre_scan_check()` hook'u |
| `src/mcpradar/scanner/engine.py` | Scanner'a TransportChecker entegrasyonu |
| `src/mcpradar/storage/store.py` | `fingerprints` tablosu; fingerprint CRUD |
| `src/mcpradar/cli.py` | `fingerprint` komutu |
| `tests/test_fingerprint.py` | **Yeni** 30+ test |
| `tests/test_transport_check.py` | **Yeni** 20+ test |

#### Tamamlanma Kriterleri

- [x] Parmak izi: endpoint hash, versiyon, capabilities, tools hash, TLS bilgisi
- [x] Karşılaştırma: tool listesi değişimi, versiyon sapması, endpoint değişimi, TLS downgrade
- [x] TransportChecker: TLS ≥ 1.2, sertifika geçerli, self-signed değil, HSTS mevcut
- [x] Parmak izleri SQLite'da saklanır
- [x] R110 diff pipeline ile entegre

---

### 🔗 Sprint 4: "Deep Cross-Server & Runtime Probing"

**Hedef Sürüm:** v0.5.0 · **Süre:** 2 hafta · **OWASP:** MCP02, MCP03, MCP10

#### Hedef

Cross-server analizi statik isim eşleştirmesinden çalışma zamanı saldırı yolu keşfine yükseltmek. Read-only tool'ların güvenli probing'i. C-kurallarını 5'ten 7'ye çıkarmak.

#### Yeni Modül: `src/mcpradar/probe/`

```python
class ReadOnlyProber:
    """Read-only olarak sınıflandırılan MCP tool'larını güvenli şekilde probe eder."""
    SAFE_TOOL_PATTERNS = [r"^(get|list|read|fetch|search|query|browse|show|describe)"]
    MAX_PROBE_COUNT = 20
    PROBE_TIMEOUT = 5.0  # saniye/tool

    async def probe_tool(self, session, tool) -> ProbeResult:
        """Minimal güvenli girdi ile tool'u çalıştırır, yanıtı analiz eder."""
```

**ProbeResult:** `tool_name`, `success`, `response_time_ms`, `response_preview`, `contains_urls`, `contains_scripts`, `contains_secrets` (R106 re-run), `contains_prompt_injection` (R102 re-run)

#### Yeni Cross-Server Kuralları

**C006 — Attack Path Chain** (MCP03/MCP10)
- (sunucu, tool) düğümlerinden oluşan yönlendirilmiş graf
- Kenarlar: tool A'nın output schema'sı ile tool B'nin input schema'sı tip bazlı eşleşme
- Tespit: "read sensitive" → "send external" (exfiltration zinciri), "receive input" → "execute command" (RCE zinciri), ≥3 uzunlukta zincirler

**C007 — Privilege Escalation via Cross-Server Chaining** (MCP02)
- Read-only tool çıktısının write/exec tool girdisine dönüşebildiği durumlar
- Yetkisiz yetki yükseltme yolları

#### Yeni CLI

```bash
mcpradar probe <hedef> --safe-only          # Sadece read-only tool'ları probe et
mcpradar analyze-context --deep              # Tam graf analizi
mcpradar analyze-context --graph -o risk.dot # GraphViz çıktısı
```

#### Dosya Değişiklikleri

| Dosya | İşlem |
|---|---|
| `src/mcpradar/probe/__init__.py` | **Yeni** |
| `src/mcpradar/probe/prober.py` | **Yeni** (~250 satır) |
| `src/mcpradar/probe/sandbox.py` | **Yeni** (~100 satır) |
| `src/mcpradar/analyzer/context.py` | C006, C007; graf oluşturucu; risk skorlayıcı |
| `src/mcpradar/analyzer/report.py` | `risk_score` alanı |
| `src/mcpradar/cli.py` | `probe` komutu; `--deep`, `--graph` flag'leri |
| `src/mcpradar/scanner/engine.py` | Prober entegrasyonu |
| `tests/test_probe.py` | **Yeni** 30+ test |
| `tests/test_context_analysis.py` | C006, C007 testleri |

#### Tamamlanma Kriterleri

- [ ] Prober read-only tool'ları güvenle tanımlar ve çalıştırır
- [ ] Timeout: yavaş/bozuk tool'larda asılı kalmaz
- [ ] ProbeResult R106 (secrets) ve R102 (prompt injection) re-run yapar
- [ ] C006 ≥2 uzunlukta saldırı zincirlerini tip-bazlı kenar benzerliğiyle tespit eder
- [ ] C007 sunucu sınırları arası yetki yükseltme zincirlerini tespit eder
- [ ] Risk skoru 0-100 her sunucu grubu için hesaplanır
- [ ] GraphViz DOT çıktısı
- [ ] Toplam 7 cross-server kuralı (C001–C007)

---

### 📊 Sprint 5: "Audit Trail & CVE Automation"

**Hedef Sürüm:** v0.6.0 · **Süre:** 2 hafta · **OWASP:** MCP08

#### Hedef

Tüm tarama aktiviteleri için yapılandırılmış denetim kaydı. NVD API'den otomatik CVE senkronizasyonu. Bulguları CVSS skorlu CVE'lere eşleme. Güvenlik istatistikleri ve trend analizi.

#### Yeni Modül: `src/mcpradar/audit/`

```python
@dataclass
class AuditEvent:
    event_id: str
    timestamp: str          # ISO 8601
    event_type: str         # scan_started, scan_completed, finding_created,
                            #   diff_detected, alert_sent, plugin_loaded, error
    severity: str           # info, warning, error
    target: str
    detail: dict

class AuditLogger:
    def log_scan_start(self, target, transport) -> str: ...
    def log_scan_complete(self, scan_id, findings_count) -> None: ...
    def log_diff(self, server, change_count, security_count) -> None: ...
    def query(self, since, event_type, target) -> list[AuditEvent]: ...
    def export_audit_log(self, path, format="json") -> None: ...

class StatsEngine:
    def server_stats(self, target) -> ServerStats: ...
    def global_stats(self) -> GlobalStats: ...
    def trend_analysis(self, target, days=30) -> TrendReport: ...

class NVDAPISyncer:
    """NVD API 2.0 üzerinden MCP-ilgili CVE'leri senkronize eder."""
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    def search_mcp_cves(self) -> list[CVEEntry]: ...
    def sync_all(self) -> int: ...
```

#### SQLite Şema Genişletme

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    event_id    TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info',
    target      TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type);
```

#### Yeni CLI

```bash
mcpradar audit                            # Son denetim olayları
mcpradar audit --target <url>             # Sunucuya göre filtrele
mcpradar audit --type diff_detected       # Olay tipine göre filtrele
mcpradar stats                            # Global güvenlik istatistikleri
mcpradar stats <hedef>                    # Sunucu bazlı istatistik + trend
mcpradar cve sync                         # Tam NVD senkronizasyonu
mcpradar cve match <scan_id>              # Bulguları CVE'lere eşle
mcpradar cve list                         # Önbellekteki CVE'leri listele
```

#### Dosya Değişiklikleri

| Dosya | İşlem |
|---|---|
| `src/mcpradar/audit/__init__.py` | **Yeni** |
| `src/mcpradar/audit/auditor.py` | **Yeni** (~200 satır) |
| `src/mcpradar/audit/stats.py` | **Yeni** (~200 satır) |
| `src/mcpradar/storage/store.py` | `audit_log` tablosu; audit CRUD |
| `src/mcpradar/cvefeed/syncer.py` | NVDAPISyncer; gelişmiş CVE eşleştirme |
| `src/mcpradar/cli.py` | `audit`, `stats`, `cve sync/match/list` komutları |
| `src/mcpradar/scanner/engine.py` | Scanner audit olayları yayar |
| `src/mcpradar/diff/differ.py` | Differ audit olayları yayar |
| `tests/test_audit.py` | **Yeni** 25+ test |
| `tests/test_stats.py` | **Yeni** 20+ test |
| `tests/test_cvefeed.py` | **Yeni** 20+ test (mock NVD API) |

#### Tamamlanma Kriterleri

- [ ] AuditLogger: scan_start, scan_complete, finding_created, diff_detected, alert_sent, error
- [ ] Audit sorgulama: zaman aralığı, olay tipi, hedef filtreleme
- [ ] StatsEngine: trend eğimi, en çok tetiklenen kurallar, severity dağılımı
- [ ] NVD API: gerçek CVE'leri CVSS skoruyla çeker (rate-limited, önbellekli)
- [ ] CVE eşleştirme: CWE mapping + anahtar kelime overlap skorlaması
- [ ] `mcpradar cve match <scan_id>` bulguları CVE referanslarıyla zenginleştirir

---

### 🏁 Sprint 6: "Validation, Performance & v1.0 Polish"

**Hedef Sürüm:** v0.7.0 → v1.0.0-rc1 · **Süre:** 2 hafta · **OWASP:** 10/10 tam kapsam

#### Hedef

10 sunuculuk gerçek dünya validasyon pipeline'ını tamamlamak. Performans optimizasyonu (paralel tarama). Dokümantasyonu tamamlamak. v1.0 sürüm adayı için hazırlık.

#### Validasyon Pipeline

```python
class ValidationRunner:
    async def run_all(self) -> ValidationReport:
        # 10 sunucuyu targets.yaml'dan tara
        # Tüm R ve C kurallarını çalıştır
        # Her bulgu için TP/FP/belirsiz sınıflandırması (auto-triage)
        # Kural bazlı precision/recall hesapla

    def generate_report(self) -> str:
        # Markdown rapor: sunucu bazlı bulgu tablosu,
        #   false positive analizi, kural etkinlik metrikleri
```

#### Performans Optimizasyonu

```python
class ParallelScanner:
    """Birden fazla sunucuyu eşzamanlı tarar."""
    async def scan_all(self, servers, max_concurrency=5) -> list[ScanReport]:
        # asyncio.gather + semaphore
```

```bash
mcpradar scan-all --parallel --max-concurrency 10
```

#### Benchmark

```python
# tests/test_benchmark.py
class TestBenchmarks:
    def test_rule_engine_latency(self, benchmark): ...     # ≤5ms/tool (100 tools)
    def test_sarif_generation_scale(self): ...             # ≤50ms (100 bulgu)
    def test_sqlite_insert_batch(self): ...                # ≤10ms (100 bulgu)
```

#### Dokümantasyon (8 yeni sayfa)

| Sayfa | İçerik |
|---|---|
| `docs/getting-started.md` | Kurulum, ilk tarama |
| `docs/cli-reference.md` | Tam CLI referansı (tüm komutlar, flag'ler) |
| `docs/plugin-authoring.md` | Eklenti geliştirme rehberi |
| `docs/api-reference.md` | Python API dokümantasyonu |
| `docs/fingerprinting.md` | Parmak izi rehberi |
| `docs/ci-integration.md` | CI/CD entegrasyon örnekleri (GitHub Actions, GitLab CI, CircleCI) |
| `docs/owasp-mapping.md` | OWASP MCP Top 10 kapsam matrisi |
| `docs/benchmarks.md` | Performans verileri |

#### v1.0 Öncesi Sertleştirme

- mypy strict: sıfır hata
- ruff: sıfır uyarı
- Test coverage ≥ %90
- Kendi bağımlılıklarının güvenlik denetimi
- SBOM oluşturma (cyclonedx veya spdx)
- `SECURITY.md` güncelleme

#### Dosya Değişiklikleri

| Dosya | İşlem |
|---|---|
| `validation/run_validation.py` | ValidationRunner tam uygulama |
| `src/mcpradar/scanner/engine.py` | ParallelScanner sınıfı |
| `src/mcpradar/cli.py` | `--parallel` flag'i |
| `tests/test_benchmark.py` | **Yeni** performans benchmark'ları |
| `docs/getting-started.md` | **Yeni** |
| `docs/cli-reference.md` | **Yeni** |
| `docs/plugin-authoring.md` | **Yeni** |
| `docs/api-reference.md` | **Yeni** |
| `docs/fingerprinting.md` | **Yeni** |
| `docs/ci-integration.md` | **Yeni** |
| `docs/owasp-mapping.md` | **Yeni** |
| `docs/benchmarks.md` | **Yeni** |
| `CHANGELOG.md` | v0.7.0 ve v1.0.0-rc1 girişleri |

#### Tamamlanma Kriterleri

- [ ] 10 sunucu validasyonu tamamlandı, sonuçlar yayınlandı
- [ ] False positive analizi: precision ≥ %85 (tüm kurallar)
- [ ] False negative analizi: recall ≥ %90 (malicious_server.py baseline)
- [ ] Paralel tarama: ≥ 5 sunucu/saniye
- [ ] Kural motoru: ≤ 5ms/tool (100 tools)
- [ ] SARIF üretimi: ≤ 50ms (100 bulgu)
- [ ] Dokümantasyon: 8 sayfa tamamlandı
- [ ] mypy + ruff + pytest: sıfır hata/uyarı
- [ ] SBOM oluşturuldu
- [ ] v1.0.0-rc1 PyPI'da yayınlandı

---

## Uzun Vadeli Hedefler (v1.1+)

### v1.1 — Runtime Behavioral Analysis
- WebSocket transport desteği (gelişmekte olan MCP transport'u)
- Tool call interception proxy modu (Pipelock benzeri, opsiyonel)
- Tool description'larında anomali tespiti için ML sınıflandırıcı
- LLM-as-a-judge entegrasyonu (yanıt kalitesi değerlendirme)

### v1.2 — Ecosystem Integration
- MCP sunucu kayıt defteri doğrulama servisi (otomatik leaderboard)
- Badge/shield sistemi: `![MCPRadar Score](https://img.shields.io/mcpradar/score/<sunucu>)`
- IDE eklentileri (VS Code, JetBrains) — `vscode-mcpradar/` zaten scaffold edildi
- Pre-commit hook: `- repo: https://github.com/yatuk/mcpradar`

### v1.3+ — Enterprise Features
- Multi-tenant veritabanı (namespace izolasyonlu paylaşımlı SQLite)
- Policy-as-code kuralları (YAML-tanımlı, Python gerektirmez — MCP Guardian benzeri ama açık kaynak)
- Web dashboard (FastAPI + htmx, self-hosted)
- OPA/Rego entegrasyonu (ileri politika değerlendirme)

---

## Kural ID Kayıt Defteri

### Tespit Kuralları (R-serisi)

| ID | İsim | Sprint | OWASP | Severity |
|---|---|---|---|---|
| R001 | Dangerous Tool Name | v0.1.0 | MCP03 | CRITICAL |
| R101 | Zero-Width Unicode Detection | v0.1.0 | MCP06 | HIGH/CRITICAL |
| R102 | Prompt Injection Detection | v0.1.0 | MCP06 | HIGH/CRITICAL |
| R103 | Encoded Blob Detection | v0.1.0 | MCP06 | MEDIUM/HIGH |
| R104 | Hidden Content Detection | v0.1.0 | MCP03/MCP06 | HIGH |
| R105 | Permission Scope Mismatch | v0.1.0 | MCP02 | LOW/MEDIUM |
| **R106** | **Secret/Token Exposure** | **Sprint 1** | **MCP01** | **CRITICAL** |
| **R107** | **Command Injection via Parameters** | **Sprint 1** | **MCP05** | **CRITICAL** |
| **R108** | **Supply Chain Risk Indicator** | **Sprint 1** | **MCP04** | **MEDIUM/HIGH** |
| **R109** | **Schema Poisoning Indicator** | **Sprint 1** | **MCP03** | **HIGH** |
| **R110** | **Version Anomaly** | **Sprint 3** | **MCP09** | **HIGH/CRITICAL** |
| **R111** | **Insecure Transport** | **Sprint 3** | **MCP07** | **HIGH/CRITICAL** |

### Cross-Server Kuralları (C-serisi)

| ID | İsim | Sprint | OWASP |
|---|---|---|---|
| C001 | Tool Name Collision | v0.1.0 | MCP10 |
| C002 | Tool Name Shadowing | v0.1.0 | MCP10 |
| C003 | Data Exfiltration Chain | v0.1.0 | MCP10 |
| C004 | Capability Overlap | v0.1.0 | MCP10 |
| C005 | Permission Gradient | v0.1.0 | MCP10 |
| **C006** | **Attack Path Chain** | **Sprint 4** | **MCP03/MCP10** |
| **C007** | **Privilege Escalation Chain** | **Sprint 4** | **MCP02** |

### Topluluk Kuralları (X-serisi, rezerve)

Topluluk eklentileri `X` + 3 haneli sayı formatını kullanır (X001–X999). Built-in kurallarla çakışmayı önler.

---

## Komut Matrisi (Tam CLI)

| Komut | Sürüm | Açıklama |
|---|---|---|
| `mcpradar scan <hedef> -t <transport>` | v0.1.0 | Tek MCP sunucusu tara |
| `mcpradar scan-all [--config] [--parallel]` | v0.1.0 | Tüm sunucuları tara |
| `mcpradar diff [sunucu] [-a] [-b] [--since]` | v0.1.0 | İki snapshot'u karşılaştır |
| `mcpradar watch <hedef> [-i] [--alert-cmd] [--alert-webhook]` | v0.1.0 | Periyodik tarama + alert |
| `mcpradar list [hedef] [-n]` | v0.1.0 | Snapshot geçmişi |
| `mcpradar show <scan_id>` | v0.1.0 | Tek snapshot detayı |
| `mcpradar export <scan_id> [-f] [-o]` | v0.1.0 | JSON/SARIF/CSV export |
| `mcpradar purge [--older-than] [--keep-last]` | v0.1.0 | Eski snapshot temizliği |
| `mcpradar init [-o]` | v0.1.0 | mcpradar.toml oluştur |
| `mcpradar registry-scan [-o]` | v0.1.0 | Leaderboard oluştur |
| `mcpradar rules list` | v0.1.0 | Kuralları listele |
| `mcpradar rules info <rule_id>` | v0.1.0 | Kural detayı |
| `mcpradar rules disable <rule_id>` | v0.1.0 | Kural devre dışı bırak |
| `mcpradar analyze-context [--config] [--deep] [--graph]` | v0.1.0 | Cross-server analiz |
| `mcpradar feed-update` | v0.1.0 | CVE feed güncelle |
| `mcpradar plugin init <isim> [-o]` | Sprint 2 | Yeni eklenti iskeleti |
| `mcpradar plugin validate <dizin>` | Sprint 2 | Eklenti doğrulama |
| `mcpradar plugin list` | Sprint 2 | Eklentileri listele |
| `mcpradar plugin install <paket>` | Sprint 2 | Eklenti yükle |
| `mcpradar plugin uninstall <paket>` | Sprint 2 | Eklenti kaldır |
| `mcpradar fingerprint <hedef> [--compare]` | Sprint 3 | Parmak izi |
| `mcpradar probe <hedef> [--safe-only \| --all]` | Sprint 4 | Runtime probing |
| `mcpradar audit [--target] [--type] [--since]` | Sprint 5 | Denetim kaydı |
| `mcpradar stats [hedef]` | Sprint 5 | Güvenlik istatistikleri |
| `mcpradar cve sync` | Sprint 5 | NVD senkronizasyonu |
| `mcpradar cve match <scan_id>` | Sprint 5 | CVE eşleştirme |
| `mcpradar cve list` | Sprint 5 | CVE listesi |

---

## Başarı Metrikleri

| Metrik | v0.1.0 (Mevcut) | v0.7.0 Hedef | v1.0 Hedef |
|---|---|---|---|
| OWASP MCP Top 10 kapsamı | 3/10 | 10/10 | 10/10 |
| Tespit kuralı sayısı | 6 | 11 | 11 |
| Cross-server kuralı sayısı | 5 | 7 | 7 |
| Transport protokolü | 3 | 3 | 4 (WebSocket) |
| Test coverage | ~%80 | ≥ %90 | ≥ %92 |
| Test kodu (satır) | ~2,150 | 4,000+ | 4,500+ |
| Tarama gecikmesi (tool başına) | ~10ms | ≤ 5ms | ≤ 3ms |
| Paralel tarama hızı | — | 5 sunucu/s | 10 sunucu/s |
| Topluluk eklentisi | 0 | 2 örnek | 5+ |
| Validasyon sunucusu | 0/10 | 10/10 | CI otomasyonu |
| NVD CVE veritabanı | 2 tohum | 50+ MCP-ilgili | 100+ otomatik |
| SARIF entegrasyonu | 6 kural | 11 kural + CVE | Code Scanning alert'leri |

---

## Risk Değerlendirmesi

| Risk | Etki | Olasılık | Azaltma |
|---|---|---|---|
| **MCP protokolünde breaking change** | Yüksek | Orta | MCP SDK sürümü sabitle; CI'da çoklu SDK testi; MCP spec reposunu izle |
| **Plugin API kararsızlığı** | Orta | Yüksek | Plugin API için SemVer; 2 minör sürüm deprecation warning |
| **False positive yorgunluğu** | Yüksek | Orta | Sprint 1+6 FP analizi; kural bazlı precision takibi; `--severity` filtreleme; kural disable UI |
| **NVD API rate limiting** | Düşük | Yüksek | TTL'li lokal önbellek; exponential backoff; tohum veri fallback |
| **Topluluk eklenti kalitesi** | Orta | Orta | Plugin validation CLI; test şablonu; eklenti inceleme checklist'i |
| **Kural büyümesiyle performans gerilemesi** | Orta | Düşük | Sprint 6 benchmark'ları; CI perf regresyon testi; kural seviyesinde profiling |
| **OWASP MCP Top 10 güncellemeleri** | Düşük | Düşük | Sprint 6 OWASP mapping dokümanı; aylık OWASP güncelleme takibi |
| **Rakip özellik paritesi baskısı** | Düşük | Düşük | Farklılaşmaya odaklan: deterministik + CI-dostu + MIT lisans + Python ekosistemi |

---

## Ek: Tespit Edilen MCP CV'leri ve MCPRadar Kapsamı (2025–2026)

OX Security araştırmacıları tarafından keşfedilen ve MCPRadar'ın hedeflediği kritik CVE'ler:

| CVE ID | Ürün | Açıklama | Durum | MCPRadar Kapsamı |
|---|---|---|---|---|
| CVE-2025-54136 | Cursor IDE | STDIO Komut Enjeksiyonu / RCE | ✅ Yamalandı | R107 (parametre enjeksiyonu) |
| CVE-2026-30623 | LiteLLM | Unauthenticated Command Injection | ✅ Yamalandı | R107 |
| CVE-2025-49596 | MCP Inspector | DNS Rebinding / RCE | ✅ Yamalandı | R111 (transport güvenliği) |
| CVE-2026-30615 | Windsurf | Yapılandırma Üzerinden RCE | ❌ Yamalanmadı | R107 + R108 |
| CVE-2026-30616 | Jaaz | STDIO Privilege Escalation | ❌ Yamalanmadı | R107 |
| CVE-2026-30617 | Langchain-Chatchat | STDIO RCE | ❌ Yamalanmadı | R107 |
| CVE-2026-30618 | Fay Framework | STDIO RCE | ❌ Yamalanmadı | R107 |
| CVE-2026-30624 | Agent Zero | STDIO RCE | ❌ Yamalanmadı | R107 |
| CVE-2026-30625 | Upsonic | Hardening Bypass | ⚠️ Uyarı eklendi | R107 + R108 |
| CVE-2026-33224 | Bisheng | STDIO RCE | ✅ Yamalandı | R107 |
| CVE-2026-40933 | Flowise | Auth RCE (CVSS 10) | ✅ Yamalandı | R107 |
| CVE-2026-30861 | WeKnora | Allowlist Bypass RCE | ❌ Yamalanmadı | R107 + R108 |
| CVE-2025-65720 | GPT Researcher | STDIO RCE | ❌ Yamalanmadı | R107 |
| CVE-2026-22252 | LibreChat | STDIO RCE | ✅ Yamalandı | R107 |

> **Not:** 17 atanmış CVE'nin sadece 6'sı yamalanmış durumda. MCPRadar'ın R107 (Command Injection via Parameters), R108 (Supply Chain Risk) ve R111 (Insecure Transport) kuralları bu CVE'lerin çoğuna karşı koruma sağlamayı hedefler.

---

## Referanslar

- [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/)
- [MCP Supply Chain Advisory — OX Security](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/)
- [Don't believe everything you read: MCP Behavior under Misleading Tool Descriptions — arXiv](https://arxiv.org/abs/2510.21236)
- [Breaking the Protocol: Security Analysis of MCP Spec — arXiv](https://arxiv.org/abs/2601.17549)
- [CVE-2025-54136: Cursor IDE RCE — SentinelOne](https://sentinelone.com)
- [MCP Scanner Comparison: Cisco vs Snyk vs Pipelock](https://dev.to/luckypipewrench/mcp-scanner-comparison-cisco-vs-snyk-vs-pipelock-32kd)
- [10 Tools for Securing MCP Servers — Nordic APIs](https://nordicapis.com/10-tools-for-securing-mcp-servers/)
- [ClawHub Security Signals — arXiv](https://arxiv.org/abs/2601.17549)
- [OpenClaw + NVIDIA Agent Skill Security](https://openclaw.ai)

---

<p align="center">
  <b>📋 Bu yol haritası canlı bir dokümandır.</b><br/>
  <sub>Sprint'ler tamamlandıkça güncellenecektir. Katkıda bulunmak için <a href="CONTRIBUTING.md">CONTRIBUTING.md</a>'ye bakın.</sub>
</p>
