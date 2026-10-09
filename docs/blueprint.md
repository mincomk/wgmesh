---
title: wgmesh Implementation Blueprint — Rust Workspace, Configuration, NixOS Modules
---

# wgmesh 구현 청사진

설계는 `wgmesh-coordinator-design` v3를 따른다. 이 문서는 그것을 **Rust 워크스페이스**로 옮기는 구체적 계획이다: crate 경계와 의존 규칙, 타입 시그니처, 파일 3분리(설정·상태·비밀), 설정 스키마와 기본값, AllowedIPs·라우팅 정책, CLI, NixOS 모듈, 테스트 전략, 마일스톤.

## 0. 이 문서에서 확정한 것

| 항목 | 결정 |
|---|---|
| 언어/에디션 | Rust 2024, 최소 1.85 |
| 바이너리 | `wgmesh`(에이전트), `wgmesh-relayd`(릴레이), `wgmeshd`(코디네이터) |
| 아키텍처 | clean architecture. 안쪽은 순수, 바깥은 어댑터. 의존은 항상 안쪽으로 |
| `unsafe` | 워크스페이스 전체 `forbid` — netlink도 순수 Rust 크레이트로 처리 |
| 설정/상태/비밀 | **파일 3개로 분리.** 설정은 사람이, 상태는 기계가, 비밀은 아무도 안 건드린다 |
| AllowedIPs | 기본은 피어별 /32. catch-all(0.0.0.0/0)은 **한 피어에게만** — `exit_peer` |
| 라우팅 테이블 | **설치할 대역을 명시적으로 고르고, 기본 경로는 절대 넣지 않는다.** `table = "off"`로 전면 위임 |
| 주석 | 전부 영문. **파일 레벨 주석(`//!`) 금지** — CI에서 grep으로 강제 |
| NixOS | 모듈 3개(agent/relay/coordinator) + `settings` freeform → TOML 1:1 |
| 검증 | 순수 도메인은 **실제로 컴파일·테스트 완료** — 24개 통과 (§15) |

**assumption.** "elegant"를 DI 크레이트(`elegant-departure` 류)가 아니라 *crate 설계의 성질*로 읽었다. 배선은 평범한 생성자 주입 + 단일 composition root다. DI 매크로를 쓰고 싶다면 §3.4의 `Container` 하나만 바꾸면 되도록 설계했다.

---

## 1. 워크스페이스 구조

```
wgmesh/
├── Cargo.toml                      workspace: members, lints, profile
├── xtask/                          의존 규칙·스타일 검사 (CI가 부르는 것)
├── crates/
│   ├── wgmesh-core/                순수 도메인. I/O 없음. 외부 의존 blake2 하나
│   ├── wgmesh-ports/               trait(port) 정의 + 오류 분류
│   ├── wgmesh-app/                 유스케이스. core + ports만 안다
│   ├── wgmesh-config/              설정 로드·기본값·검증
│   ├── wgmesh-state/               상태 저장소 (원자적 쓰기)
│   ├── wgmesh-secrets/             비밀 저장소 (키 파일, 0600)
│   ├── wgmesh-proto/               코디네이터 API의 와이어 타입 + 서명 정규화
│   ├── wgmesh-wireguard/           커널 WireGuard 어댑터 (netlink) + 라우트 어댑터
│   ├── wgmesh-client/              HTTPS 클라이언트 어댑터
│   ├── wgmesh-coordinator/         코디네이터 애플리케이션 + SQLite + HTTP + bin
│   ├── wgmesh-relay/               릴레이 포워딩 엔진 + UDP 드라이버 + bin
│   └── wgmesh-cli/                 `wgmesh` bin — composition root
└── nix/                            modules/, packages/, tests/
```

### 1.1 의존 규칙 (기계적으로 강제한다)

```
core ─► ports ─► app ─► { coordinator, relay, cli }
  ▲         ▲                ▲
  └─────────┴── adapters ────┘
     config, state, secrets, proto, wireguard, client
```

| crate | 의존해도 되는 내부 crate | 외부 crate |
|---|---|---|
| `wgmesh-core` | — | `blake2` |
| `wgmesh-ports` | core | `async-trait` |
| `wgmesh-app` | core, ports | `tracing` |
| `wgmesh-config` | core | `serde`, `toml`, `humantime-serde`, `thiserror` |
| `wgmesh-state` | core | `serde_json`, `tempfile`, `rustix` |
| `wgmesh-secrets` | core | `ed25519-dalek`, `x25519-dalek`, `rand_core`, `zeroize`, `base64ct` |
| `wgmesh-proto` | core | `serde`, `base64ct`, `hex` |
| `wgmesh-wireguard` | core, ports | `rtnetlink`, `nl-wireguard`, `tokio` |
| `wgmesh-client` | core, ports, proto | `reqwest`, `rustls`, `sha2`, `base64ct` |
| `wgmesh-coordinator` | core, app, proto, config, state, secrets | `axum`, `sqlx`, `tokio`, `tower-http` |
| `wgmesh-relay` | core, app, proto, config, state, secrets, client | `tokio`, `socket2`, `tracing` |
| `wgmesh-cli` | 전부 | `clap`, `tokio`, `tracing-subscriber` |

`xtask check-deps`가 위 표를 리터럴로 들고 `cargo metadata`와 대조한다. 규칙 위반은 빌드 실패다. 그리고 `wgmesh-core`의 의존성 트리에서 `tokio|reqwest|axum|sqlx|hyper|rustls|netlink|libc|nix` 중 하나라도 나오면 실패 — 이게 "순수 코어"를 구호가 아니라 사실로 만든다.

### 1.2 워크스페이스 린트

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "allow"

[workspace.lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
todo = "warn"
dbg_macro = "deny"
print_stdout = "warn"
```

`unsafe_code = "forbid"`가 성립하는 이유: WireGuard 제어는 generic netlink의 **순수 Rust 크레이트**로 처리한다(§11에서 확인한 `nl-wireguard` + `rtnetlink`). C 라이브러리 바인딩이 필요 없다.

---

## 2. 순수 코어 (`wgmesh-core`)

I/O도, async도, 시계도, OS도 없다. **시간은 인자로 들어오고, 결정은 값으로 나온다.** 그래서 커널·네트워크·타이머 없이 전부 단위 테스트할 수 있다.

핵심 타입:

```rust
pub struct PublicKey([u8; 32]);          pub struct DeviceId(pub u32);
pub struct Endpoint(SocketAddr);          pub struct RelayId(pub u16);
pub struct Millis(pub u64);               pub enum Path { Unknown, Relayed, Direct }
pub type Mac1Key = [u8; 32];              pub type Mac1 = Blake2sMac<U16>;
```

네 개의 순수 함수가 시스템 전체의 두뇌다.

```rust
pub fn mac1_key(responder: &PublicKey) -> Mac1Key;
pub fn classify(packet: &[u8]) -> Option<MessageKind>;
pub fn verify_mac1(packet: &[u8], key: &Mac1Key) -> bool;

pub fn rank(candidates: &[Candidate]) -> Vec<Candidate>;
pub fn step(state: &mut Traversal, event: Event, cfg: &TraversalConfig) -> Vec<Effect>;
pub fn diff(desired: &[PeerSpec], current: &BTreeMap<DeviceId, PeerSpec>) -> Vec<Change>;
impl RelayTable { pub fn route(&mut self, ingress_port: u16, src: Endpoint,
                              dst: DeviceId, packet: &[u8], at: Millis) -> Route; }
```

`step`이 홀펀칭 상태기계 그 자체다. 부수효과는 돌려주는 값(`Effect`)이고, 입력은 이벤트다.

```rust
pub enum Event {
    Assignment { relay: Endpoint, at: Millis },
    Observed   { endpoint: Endpoint, kind: CandidateKind, at: Millis },
    Handshake  { via: Endpoint, at: Millis },
    Degraded   { at: Millis },
    Tick       { at: Millis },
}

pub enum Effect { SetPeerEndpoint(Endpoint), SendHandshake, ReportObservation(Endpoint) }

pub enum Phase { Idle { next_attempt: Millis }, Probing { since: Millis } }
```

두 가지가 여기서 강제된다.

- **직접 경로가 살아 있으면 건드리지 않는다.** `path == Direct`인 동안 `Tick`은 아무 일도 하지 않는다. 경로가 죽었다는 판단은 에이전트(=커널에서 핸드셰이크 시각을 읽는 쪽)가 `Event::Degraded`로 알려준다. 설계 문서 §4.10의 "직접 시도 창을 짧게, 즉시 복귀"가 코드로 굳는 지점이다.
- **릴레이가 바뀌면 관찰값은 버린다.** 다른 릴레이에서 얻은 관찰은 대칭 NAT에서 무의미하므로 `Assignment`가 `Lan`/`Ipv6` 후보만 남기고 지운다.

`RelayTable::route`는 릴레이의 보안 규칙 전부다 — 입구 포트로 송신자를 식별하고, 출발지 주소를 TOFU로 고정하고, 배정된 쌍이 아니면 버리고, WireGuard 형태가 아니면 버린다.

```rust
pub enum DropReason { UnknownIngress, UnknownDestination, NotAssigned, SourceMoved, Malformed }
```

라우팅 정책도 같은 crate 안의 순수 함수다 (§6).

---

## 3. 포트와 유스케이스

### 3.1 `wgmesh-ports`

```rust
#[async_trait]
pub trait CoordinatorApi: Send + Sync {
    async fn enroll(&self, request: EnrollRequest) -> Result<Enrollment, ApiError>;
    async fn config(&self, etag: Option<&str>) -> Result<ConfigSnapshot, ApiError>;
    async fn report_observations(&self, observations: &[Observation]) -> Result<(), ApiError>;
    async fn report_punch(&self, report: PunchReport) -> Result<(), ApiError>;
    async fn rotate(&self, key: PublicKey) -> Result<(), ApiError>;
}

pub trait WireGuard: Send + Sync {
    fn ensure_interface(&self, spec: &InterfaceSpec) -> Result<(), WireGuardError>;
    fn apply(&self, changes: &[Change]) -> Result<(), WireGuardError>;
    fn status(&self, peers: &[DeviceId]) -> Result<Vec<PeerStatus>, WireGuardError>;
    fn listen_port(&self) -> Result<u16, WireGuardError>;
}

pub trait Routes: Send + Sync {
    fn ensure_address(&self, address: &Allowed) -> Result<(), RouteError>;
    fn installed(&self) -> Result<Vec<RouteSpec>, RouteError>;
    fn apply(&self, changes: &[RouteChange]) -> Result<(), RouteError>;
}

pub trait StateStore: Send + Sync {
    fn load(&self) -> Result<Option<PersistedState>, StateError>;
    fn save(&self, state: &PersistedState) -> Result<(), StateError>;
    fn clear(&self) -> Result<(), StateError>;
}

pub trait SecretStore: Send + Sync {
    fn wireguard_public_key(&self) -> Result<PublicKey, SecretError>;
    fn public_key(&self) -> Result<PublicKey, SecretError>;
    fn sign(&self, message: &[u8]) -> Result<Signature, SecretError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Millis;
}
```

세 가지 의도된 설계가 있다.

- **`SecretStore::sign`이지 `SecretStore::api_key`가 아니다.** 프라이빗 키는 저장소 밖으로 나오는 순간이 없고, 서명 요청만 나간다.
- **`WireGuard::apply`의 단위가 `Change`(core 타입)다.** 어댑터가 "무엇을 원하는지"를 판단하지 않는다. 판단은 `core::diff`가 전부 하고, 어댑터는 netlink 메시지로 번역만 한다.
- **`Routes`가 `WireGuard`와 분리돼 있다.** AllowedIPs(cryptokey routing)와 커널 라우팅 테이블은 다른 것이고, 서로 다른 이유로 바뀐다(§6). `WireGuard` 어댑터가 `ip route`를 몰라도 되는 게 이 분리의 값이다.

### 3.2 `wgmesh-app` — 에이전트 유스케이스

```rust
pub struct EnrollDevice<C: CoordinatorApi, S: SecretStore, T: StateStore> { .. }
pub struct ConvergeState<C, W: WireGuard, R: Routes, T: StateStore> { .. }
pub struct TraversePeers<W, C> { .. }
```

에이전트 시작 시퀀스가 곧 유스케이스 목록이다:

1. `Settings::load()` — 기본값 ← 파일 ← 환경 ← 플래그, 그리고 검증. `--check`면 여기서 정상 종료.
2. `secrets.wireguard_public_key()` — 없으면 생성(또는 프로비저닝 전용이면 에러).
3. `state.load()` — 없으면 `enroll()` → `state.save()`. 토큰 유무가 여기서 갈린다.
4. 상태의 SPKI와 설정의 SPKI 비교 — 다르면 **거부.** 핀 변경은 `trust --rotate`로만.
5. `config()` → `program_allowed_ips()` → `diff()` → `wireguard.apply()`, 그리고 `desired_routes()` → `routes.installed()` → `plan_routes()` → `routes.apply()`.
6. 루프: `Tick` → `Traversal::step` → `Effect` 적용, `wireguard.status()`가 `Handshake`/`Degraded` 이벤트를 만들고, 릴레이가 준 관찰이 `Observed`를 만든다.

`Effect` → 실제 행동의 사상은 `wgmesh-cli`의 한 함수다:

| `Effect` | 하는 일 |
|---|---|
| `SetPeerEndpoint(e)` | `wireguard.apply(&[Change::Update(..)])` — 라우트는 손대지 않는다 |
| `SendHandshake` | 피어 엔드포인트로 즉시 킥 (커널이 없으면 keepalive가 대신한다) |
| `ReportObservation(o)` | `coordinator.report_observations(&[o])` |

5번에서 **AllowedIPs와 라우트는 서로 다른 입력에서 나온다**는 게 §6의 요점이다. AllowedIPs는 정책(`peer`/`any`/`exit_peer`)이 정하고, 라우트는 `prefixes`가 정한다. 그래서 `AllowedIPs = 0.0.0.0/0`이어도 커널 라우팅 테이블에는 고른 대역만 들어간다.

### 3.3 `wgmesh-app` — 코디네이터 유스케이스

같은 crate, 다른 모듈: `app::coordinator::{ JoinDevice, ApproveDevice, AssignPair, RecordObservations, IngestHeartbeat, SelectRelay }`. 포트만 알므로 SQLite 없이 테스트된다.

`SelectRelay`는 순수 함수로 뽑는다:

```rust
pub fn select_relay(candidates: &[RelayCandidate], now: Millis) -> Option<RelayId>;
```

sticky 규칙(성공한 배정 유지), RTT 합 최소, 지역 다양성이 여기 들어간다.

### 3.4 Composition root

`wgmesh-cli/src/main.rs` 한 파일에서만 구체 타입이 만난다.

```rust
struct Container {
    settings: Settings,
    wireguard: NetlinkWireGuard,
    routes: NetlinkRoutes,
    state: FileStateStore,
    secrets: FileSecretStore,
    coordinator: HttpsCoordinator,
    clock: SystemClock,
}

impl Container {
    fn new(settings: Settings) -> Result<Self, StartupError> { .. }
    fn agent(&self) -> Agent<'_> { .. }
}
```

DI 크레이트를 쓰겠다면 이 `Container`를 매크로가 만든 그래프로 바꾸면 되고, 그 외 코드는 손대지 않는다.

---

## 4. 설정·상태·비밀 파일 (요구의 핵심)

### 4.1 세 파일의 역할

| | 설정 | 상태 | 비밀 |
|---|---|---|---|
| 경로 | `/etc/wgmesh/agent.toml` | `/var/lib/wgmesh/state.json` | `/var/lib/wgmesh/secrets/` |
| 소유 | `root:root` 0644 | `wgmesh:wgmesh` 0640 | `wgmesh:wgmesh` 0600 (디렉터리 0700) |
| 작성자 | 사람 또는 Nix | 데몬 | 데몬 또는 프로비저닝 도구 |
| git/Nix | **넣는다** (선언적) | 넣지 않는다 | 절대 넣지 않는다 |
| 잃어버리면 | 다시 쓴다 | 지우면 재동기화된다 | **재등록해야 한다** |
| 들어가는 것 | 원하는 상태 | 코디네이터가 알려준 사실 | 정체성 |

이 표가 곧 계약이다. 설정에는 비밀이 없고, 상태에는 비밀이 없고, **비밀은 비밀 디렉터리 밖으로 나오지 않는다.**

두 가지 성질을 실용적으로 쓴다.

- **상태는 일회용이다.** `rm /var/lib/wgmesh/state.json && systemctl restart wgmesh-agent` → 비밀은 그대로 두고 조인부터 다시 완주한다. 문제 생겼을 때의 첫 조치가 이것이다.
- **비밀은 일회용이 아니다.** `wg.key`를 잃으면 새 키로 다시 등록해야 하고, `api.key`를 잃으면 새 조인 토큰이 필요하다(기본값이 승인 대기이므로 관리자 손이 필요하다). 그래서 비밀만 따로 백업한다.

상태가 일회용인 것은 라우트에도 적용된다: 설치한 라우트 목록은 상태에 남기지만, 상태를 잃어도 **남의 라우트를 지우지 않는다** — 커널에서 우리 표식(`proto`)이 붙은 것만 다시 읽어 대조한다(§6.5).

### 4.2 디렉터리

```
/etc/wgmesh/
  agent.toml                 # 사람이 쓴다. 0644
/var/lib/wgmesh/
  state.json                 # 데몬이 쓴다. 0640
  state.json.tmp             # 원자적 교체용, 같은 디렉터리
  secrets/
    wg.key                   # X25519 개인키. 0600
    api.key                  # Ed25519 개인키. 0600
/run/wgmesh/
  agent.lock                 # 중복 기동 방지
/run/credentials/wgmesh-agent.service/
  enrollment-token           # systemd credential. 조인 때만 존재
```

### 4.3 원자적 쓰기와 권한

상태와 비밀은 **생성 시점에 모드를 지정**하고 같은 디렉터리에 임시 파일을 쓴 뒤 `rename`한다. 세계가 읽을 수 있는 순간이 존재하지 않게 하려면 이 순서여야 한다.

```rust
let tmp = dir.join(format!(".{name}.tmp"));
let mut file = OpenOptions::new()
    .create_new(true)
    .write(true)
    .mode(mode)               // 비밀은 0o600, 상태는 0o640
    .open(&tmp)?;
file.write_all(bytes)?;
file.sync_all()?;
fs::rename(&tmp, dir.join(name))?;
File::open(dir)?.sync_all()?;  // 디렉터리 엔트리까지 확정
```

### 4.4 비밀 파일 형식 — 로우 바이트와 base64 둘 다

```
wg.key    32바이트 로우  또는  base64 한 줄 (44자, 후행 개행 허용)
api.key   같은 규칙
```

`wg genkey > wg.key`(base64)와 sops-nix가 넣어주는 텍스트 비밀, 그리고 우리가 만든 로우 파일이 모두 같은 로더를 통과한다. 파서는 32바이트면 로우로, 아니면 base64로 해석하고 그 외는 거부한다. `wgmesh key show`가 `wg` 호환 base64와 공개키를 출력한다.

### 4.5 설정 우선순위

```
기본값  <  설정 파일  <  환경 변수  <  CLI 플래그
```

환경 변수는 `WGMESH__` 접두사 + `__`로 계층 구분: `WGMESH__TRAVERSAL__PUNCH_WINDOW_SECS=8`. NixOS 모듈이 비밀 경로를 TOML에 심지 않고 환경으로 주입할 수 있게 하는 통로다(§13.3).

---

## 5. 설정 스키마 (에이전트) — 전 필드 기본값 포함

`Settings`는 `#[serde(default)]` + `Default` 구현이라 **파일에 없는 필드는 전부 기본값**이다. 최소 설정 파일은 다섯 줄이면 끝난다.

```toml
[coordinator]
url = "https://wgmesh.example.com"
spki_sha256 = "9f2c…"

[enrollment]
token_file = "/run/credentials/wgmesh-agent.service/enrollment-token"
```

전체 스키마와 기본값:

```toml
[interface]
name             = "wg0"     # 인터페이스 이름
mtu              = 1420
listen_port      = 0         # 0 = 임의. 고정하면 방화벽을 열 수 있다
private_key_file = ""        # 비우면 <state.dir>/secrets/wg.key
api_key_file     = ""        # 비우면 <state.dir>/secrets/api.key

[coordinator]
url         = ""             # 필수. https만. userinfo 금지
spki_sha256 = ""             # 필수. 64 hex. 기본값 없음 — 보안상 타협 불가
network     = "default"

[enrollment]
token_file        = ""       # 이미 등록돼 있으면 불필요
wait_for_approval = true     # 승인 대기 상태로 남는다 (권장)

[peers]
allowed_ips = "peer"         # peer | any        (§6.2)
exit_peer   = ""             # 피어 이름. 그 피어만 0.0.0.0/0, ::/0을 갖는다

[route]
table    = "main"            # main | <u32> | off (§6.3). "auto"는 main과 같다
prefixes = "auto"            # auto | none | ["10.77.0.0/16", "192.168.5.0/24"]
metric   = 0                 # 0 = 미지정. 같은 대역이 여러 경로로 존재할 때만
address  = "auto"            # auto = 코디네이터가 준 터널 주소/프리픽스. "none"이면 주소도 안 준다

[forwarding]
enabled  = false             # ip_forward sysctl + 전달 (§6.6)
sysctl   = true              # 필요한 sysctl을 우리가 설정할지
firewall = "off"             # off | manage — manage면 전용 nftables 테이블만 만든다

[traversal]
punch_delay_secs  = 2        # 릴레이 경로가 선 뒤 관찰을 기다리는 시간
punch_window_secs = 5        # 직접 시도 창. 릴레이 매핑 수명보다 짧게
backoff_secs      = [30, 120, 600]
keepalive_secs    = 25
lan_candidates    = true
ipv6              = true
upnp              = false

[relay]
pool = "any"                 # any | operator-only | ["relay-1", "relay-3"]
pin  = ""                    # 지정하면 그 릴레이만 쓴다

[sync]
interval_secs = 30
sse           = true

[state]
dir = "/var/lib/wgmesh"

[log]
level  = "info"              # error|warn|info|debug|trace
format = "text"              # text|json
```

검증은 **전부 모아서** 보고한다. `wgmesh config check`가 모든 문제를 한 번에 출력한다: SPKI가 64 hex인지, `url`이 https이고 userinfo가 없는지, `punch_window_secs`가 `keepalive_secs`보다 짧은지, `backoff_secs`가 비어 있지 않고 증가하는지, `state.dir`이 절대 경로인지, `private_key_file`이 `state.dir` 밖이면 경고, 그리고 §6의 라우팅 불변식(기본 경로 금지, catch-all은 한 피어만, `exit_peer`가 실재하는 피어인지, `table = "off"`인데 `prefixes`가 명시 목록인지).

`wgmesh config show`는 **유효 설정 전체**를 기본값까지 채워 출력한다 — "무엇이 실제로 적용되는가"를 묻지 않게 만드는 게 목적이다.

릴레이와 코디네이터 설정도 같은 규칙(`Default` + 비밀은 경로로만):

```toml
# /etc/wgmesh/relay.toml
[relay]
listen           = "0.0.0.0"
port_range       = [51820, 51999]
keyset_ttl_secs  = 300        # 코디네이터 단절 후 신규 전달을 계속할 시간
[limits]
pps_per_slot     = 5000
mbit_per_slot    = 100
[coordinator]
url         = ""
spki_sha256 = ""
[enrollment]
token_file  = ""              # 승인 대기
[state]
dir         = "/var/lib/wgmesh"
```

```toml
# /etc/wgmesh/coordinator.toml
[api]
listen     = "127.0.0.1:8080" # TLS는 리버스 프록시가 담당
public_url = ""               # 예: https://wgmesh.example.com
[database]
url             = "sqlite:///var/lib/wgmesh/coordinator.db?mode=rwc"
max_connections = 4
[policy]
default_auto_approve       = false
max_devices_per_network    = 256
join_rate_limit_per_minute = 30
[relay]
heartbeat_timeout_secs = 15
reassign_after_misses  = 3
keyset_ttl_secs        = 300
[log]
level  = "info"
format = "json"
```

---

## 6. AllowedIPs와 라우팅 정책

요구를 그대로 옮기면 세 문장이다.

1. **포워딩 가능하게 AllowedIPs를 `0.0.0.0/0`으로 설정** — catch-all을 어느 피어에 줄 것인가.
2. **라우팅 테이블에는 선택한 대역의 아이피만** — 커널에 넣을 프리픽스를 고른다.
3. **라우팅 테이블 업데이트 끄기** — 아예 손대지 않는다.

**이 둘은 서로 다른 것이다.** AllowedIPs는 WireGuard의 **cryptokey routing** 테이블이고, 라우팅 테이블은 커널의 것이다. 1번을 켜도 2번은 바뀌지 않는다 — 그게 이 설계의 요점이다.

### 6.1 먼저 확인한 사실 두 가지

**(a) 커널은 AllowedIPs의 겹침을 거부하지 않는다.**

`drivers/net/wireguard/allowedips.c`의 `wg_allowedips_insert_v4` → `add`를 읽었다. 겹치는 프리픽스를 거부하는 코드가 없고, 반환하는 오류는 `-EINVAL`(`cidr > bits` 또는 피어 없음)과 `-ENOMEM`뿐이다. 조회는 트라이를 따라 내려가며 **longest-prefix-match**를 쓴다.

그래서 `exit_peer` 하나에 `0.0.0.0/0`을 주고 나머지 피어에 `/32`를 주면 **의도대로 동작한다**: 메시 트래픽은 각 피어의 `/32`로, 나머지 모든 목적지는 exit 피어로 간다. `wg(8)`도 이를 뒷받침한다:

> "AllowedIPs — a comma-separated list of IP (v4 or v6) addresses with CIDR masks from which incoming traffic for this peer is allowed and to which outgoing traffic for this peer is directed. The catch-all `0.0.0.0/0` may be specified for matching all IPv4 addresses, and `::/0` may be specified for matching all IPv6 addresses."

**단, 같은 프리픽스를 두 피어에 주면 조용히 마지막 것이 이긴다.** `add`는 정확히 일치하는 노드를 찾으면 그 노드의 peer 포인터를 갱신하기 때문이다. 그래서 여러 피어에 `0.0.0.0/0`을 주는 조합은 **검증에서 거부한다** — 침묵하는 footgun을 만들지 않는다.

**(b) `0.0.0.0/0`을 주는 순간 그 피어의 출발지 주소 인증은 꺼진다.****

AllowedIPs는 "이 피어가 어떤 출발지로 보낼 수 있는가"의 허용 목록이다. catch-all을 주면 그 피어는 **임의의 출발지**를 가진 패킷을 보낼 수 있다. 그게 라우터가 되기 위한 조건이지만(뒤에 있는 호스트들의 원래 출발지를 그대로 전달해야 하므로), 동시에 cryptokey routing의 anti-spoofing을 포기하는 것이다. 그래서 catch-all은 **정확히 하나의 신뢰하는 게이트웨이**에만 준다. 이건 제약이 아니라 설계 의도다.

**(c) `table`의 의미.** `wg-quick(8)`의 원문은 이렇게 정의한다:

> "Controls the routing table to which routes are added. There are two special values: `off' disables the creation of routes altogether, and `auto' (the default) adds routes to the default table and enables special handling of default routes."

우리는 `off`를 그대로 채택하고, **`auto`의 "special handling of default routes"(기본 경로를 `0.0.0.0/1`+`128.0.0.0/1`로 쪼개는 트릭)는 채택하지 않는다.** 기본 경로를 넣지 않는 것이 요구사항이므로 그 트릭이 필요 없고, `auto`는 `main`과 같은 뜻으로만 받는다.

### 6.2 AllowedIPs 정책 — `[peers]`

```rust
pub enum AllowedIpsPolicy { Peer, Any, ExitPeer(DeviceId) }

pub fn program_allowed_ips(
    policy: AllowedIpsPolicy,
    peers: &[PeerSpec],
) -> Result<Vec<(DeviceId, Vec<Allowed>)>, RoutingError>;
```

| 설정 | 동작 | 허용 조건 |
|---|---|---|
| `allowed_ips = "peer"` (기본) | 각 피어가 자기 터널 `/32`(또는 `/128`) + 그 피어가 광고한 대역 | 언제나 |
| `allowed_ips = "any"` | **모든** 피어가 `0.0.0.0/0, ::/0` | **피어가 정확히 하나일 때만** |
| `exit_peer = "<이름>"` | 그 피어만 `0.0.0.0/0, ::/0`, 나머지는 자기 `/32` | 이름이 실재하는 피어여야 함 |

`any`가 피어 하나를 요구하는 이유는 위 6.1(a)다 — 둘 이상에게 catch-all을 주면 어느 쪽이 이기는지가 삽입 순서에 달린다. `AnyPolicyNeedsOnePeer(n)`으로 거부한다.

`exit_peer`가 메시에서 "전부 터널로 보내되 메시는 직접"을 표현하는 정확한 수단이다.

### 6.3 라우팅 정책 — `[route]`

```rust
pub enum RouteTable { Unmanaged, Main, Number(u32) }
pub enum RoutePrefixes { Auto, None, Only(Vec<Allowed>) }

pub fn desired_routes(
    network: &[Allowed],
    advertised: &[Allowed],
    prefixes: &RoutePrefixes,
    table: RouteTable,
    metric: Option<u32>,
) -> Result<Vec<RouteSpec>, RoutingError>;

pub fn plan_routes(desired: &[RouteSpec], installed: &[RouteSpec]) -> Vec<RouteChange>;
```

| 설정 | 동작 |
|---|---|
| `table = "main"` | 기본 테이블에 우리 라우트를 넣는다 |
| `table = <u32>` | 그 번호의 테이블에 넣는다 (`ip rule`과 함께 정책 라우팅을 쓸 때) |
| `table = "off"` | **라우트를 전혀 만들지 않는다.** 주소와 인터페이스는 우리가 관리한다 (wg-quick `Table = off`와 같은 뜻) |
| `prefixes = "auto"` | 네트워크 CIDR + 각 피어가 광고한 대역 |
| `prefixes = ["10.77.0.0/16", "192.168.5.0/24"]` | **그 대역만.** 요구 2번이 이 옵션이다 |
| `prefixes = "none"` | 라우트 0개 (주소·인터페이스는 유지) |

### 6.4 불변식 — 기본 경로는 라우팅 테이블에 들어가지 않는다

```rust
pub fn validate_route_prefixes(prefixes: &[Allowed]) -> Result<(), RoutingError>;
pub fn is_catch_all(prefix: &Allowed) -> bool;
```

`prefixes`에 `0.0.0.0/0`이나 `::/0`이 들어오면 `CatchAllPrefix`로 **거부한다.** 기본 경로를 원하면 `exit_peer`로 표현하라 — 그건 AllowedIPs의 일이고 커널 라우팅 테이블의 일이 아니다. 이 한 줄이 요구 1과 2를 동시에 만족시키는 방법이다: **`AllowedIPs = 0.0.0.0/0`이어도 커널 라우팅 테이블에는 고른 대역만 들어간다.**

`table = "off"`와 `prefixes = [목록]`의 조합도 거부한다(`PrefixesWithUnmanagedTable`) — "라우트를 만들지 마라"와 "이 라우트를 만들어라"는 모순이고, 침묵하면 디버깅이 오래 걸린다. `table = "off"` + `prefixes = "auto"`는 정상 조합이다(off가 이긴다).

### 6.5 라우트 소유권

우리가 만든 라우트만 지운다. 두 겹으로 보장한다.

1. **표식**: 우리가 넣는 모든 라우트에 전용 `proto` 값을 붙인다. `iproute2`의 `rt_protos`에 이름(`wgmesh`)을 등록하고, 그 번호는 패키지가 문서화한다.
2. **상태 + 커널 대조**: 상태에 마지막으로 설치한 `RouteSpec` 목록을 남기되, 기동 시에는 **커널에서 표식이 붙은 라우트를 다시 읽어** 그 둘을 대조한다. 상태 파일이 사라져도 남의 라우트를 지우지 않는다. `wgmesh route reset`만이 표식 기준으로 전부 제거한다.

```rust
pub trait Routes: Send + Sync {
    fn installed(&self) -> Result<Vec<RouteSpec>, RouteError>;   // 표식 붙은 것만
    fn apply(&self, changes: &[RouteChange]) -> Result<(), RouteError>;
}
```

`RouteChange`는 `Add`/`Remove`뿐이고, 어느 라우트가 우리 것인지는 어댑터가 안다 — 판단(`plan_routes`)은 순수 함수에 남는다.

### 6.6 포워딩 — `[forwarding]`

```toml
[forwarding]
enabled  = false
sysctl   = true
firewall = "off"     # off | manage
```

`enabled = true`일 때:

- **sysctl**(`sysctl = true`이면): `net.ipv4.ip_forward = 1`, `net.ipv6.conf.all.forwarding = 1`. 변경 전 값을 상태에 기록하고 종료 시 되돌린다.
- **방화벽은 기본적으로 우리가 만지지 않는다.** 라우팅 데몬이 호스트 방화벽을 다시 쓰는 건 예측 불가능하고 선언적 관리와 충돌한다.
- `firewall = "manage"`를 고르면 **전용 nftables 테이블 `inet wgmesh`만** 만든다. 호스트 규칙과 섞이지 않으므로 `nft delete table inet wgmesh` 한 줄로 흔적 없이 사라진다. 그 안에 들어가는 것은 wg 인터페이스와 신뢰 인터페이스 사이의 forward 허용뿐이다.
- 무엇을 해야 하는지는 `wgmesh doctor`가 항상 출력한다. NixOS에서는 모듈이 대신 해준다(§13.4).

---

## 7. 상태 파일 스키마

```json
{
  "schema": 1,
  "device_id": "d_7Hq2Vx9",
  "network": "prod",
  "tunnel_ip": "10.77.0.7/16",
  "coordinator": {
    "spki_sha256": "9f2c…",
    "last_sync_unix": 1760000000,
    "etag": "cfg-42"
  },
  "relay": {
    "assigned": "relay-2",
    "slot_port": 51903,
    "slots": { "relay-1": 51901, "relay-2": 51903 }
  },
  "peers": [
    {
      "id": "d_K3n8",
      "name": "B",
      "wg_pubkey": "…",
      "tunnel_ip": "10.77.0.8/32",
      "endpoint": "203.0.113.9:41287",
      "path": "direct",
      "last_handshake_unix": 1760000042
    }
  ],
  "observations": {
    "relay-2": { "ip": "203.0.113.7", "port": 41287, "seen_unix": 1760000039 }
  },
  "routes": [
    { "prefix": "10.77.0.0/16", "table": "main", "metric": null }
  ],
  "sysctl": { "net.ipv4.ip_forward": "0" }
}
```

`schema`는 마이그레이션용이다. 읽을 때 모르는 스키마면 백업하고 새로 시작한다 — 상태는 일회용이므로 잃는 게 없다. `routes`와 `sysctl`은 **되돌리기 위한 기억**이지 진실의 원천이 아니다(§6.5).

상태에 **없는 것**: 개인키, 토큰, 평문 비밀. 있다면 버그다.

---

## 8. 비밀 파일 스키마

| 파일 | 내용 | 생성 | 프로비저닝(대안) |
|---|---|---|---|
| `secrets/wg.key` | X25519 개인키 32바이트 | 첫 기동 시 자동 | `private_key_file`로 sops-nix 파일 지정 |
| `secrets/api.key` | Ed25519 개인키 32바이트 | 첫 기동 시 자동 | `api_key_file`로 지정 |
| `secrets/relay.key` | Ed25519 개인키 (릴레이) | 첫 기동 시 자동 | 동일 |

`SecretStore` 어댑터가 두 모드를 표현한다.

```rust
pub enum SecretSource {
    LoadOrGenerate,   // 없으면 만든다 (파일 소유자가 우리일 때)
    RequireExisting,  // 없으면 실패 (외부 프로비저닝된 경로일 때)
}
```

`RequireExisting`은 NixOS에서 sops-nix/agenix가 키를 넣어주는 경우다. 어댑터는 파일을 **절대 다시 쓰지 않는다** — 읽기 전용 경로를 덮어쓰면 선언적 관리가 깨진다.

---

## 9. 코디네이터 (crate `wgmesh-coordinator`)

스키마는 설계 문서 §6 그대로, `sqlx` 마이그레이션으로 관리한다. 마이그레이션은 `migrations/0001_init.sql`부터 순번제.

HTTP 표면은 `axum` 라우터 + 인증 추출기 하나로 끝난다.

```rust
async fn require_device(
    State(services): State<Services>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError>;
```

추출기가 서명 헤더를 검증하고 `DeviceId`를 요청 확장에 넣는다. 핸들러는 서명을 모른다.

```rust
pub fn router(services: Services) -> Router {
    Router::new()
        .route("/v1/join", post(join))
        .route("/v1/relay/enroll", post(relay_enroll))
        .route("/v1/config", get(config).layer(device_auth()))
        .route("/v1/endpoint", post(report_endpoint).layer(device_auth()))
        .route("/v1/punch", post(report_punch).layer(device_auth()))
        .route("/v1/rotate", post(rotate).layer(device_auth()))
        .route("/v1/relay/assignment", get(relay_assignment).layer(relay_auth()))
        .route("/v1/relay/observations", post(relay_observations).layer(relay_auth()))
        .route("/v1/relay/heartbeat", post(relay_heartbeat).layer(relay_auth()))
}
```

`/v1/config`가 내려주는 스냅샷에 **피어별 광고 대역**이 들어간다 — `prefixes = "auto"`가 그걸 쓴다(§6.3). 서브넷 라우터를 붙이는 것이 곧 그 피어에 대역을 광고하는 일이다.

서명 검증의 정규 문자열은 `wgmesh-proto`에 있고 양쪽이 같은 함수를 쓴다:

```rust
pub fn canonical(method: &str, path: &str, body: &[u8], ts: i64, nonce: &[u8]) -> Vec<u8>;
```

TLS는 코디네이터가 하지 않는다. 리버스 프록시에 맡기고, 노드는 리프 인증서의 SPKI를 핀한다. ACME 갱신은 같은 키를 재사용하므로 핀이 유지된다. `wgmesh pin <url>`이 그 값을 출력한다.

---

## 10. 릴레이 (crate `wgmesh-relay`)

판단은 `core::RelayTable`(§2)이 전부 하고, crate에는 소켓 배관만 있다.

```rust
pub struct RelayEngine<S: SlotSockets> {
    table: RelayTable,
    sockets: S,
    keysets: KeysetCache,
    counters: TrafficCounters,
}

impl<S: SlotSockets> RelayEngine<S> {
    pub async fn run(&mut self, shutdown: Shutdown) -> Result<(), RelayError>;
    pub fn on_assignment(&mut self, assignment: Assignment);
    pub fn tick(&mut self, at: Millis) -> Vec<Report>;   // 관찰·트래픽·하트비트 보고
}
```

`SlotSockets` 포트가 있어서 테스트에서는 127.0.0.1 소켓을, 운영에서는 실제 바인딩을 쓴다. 슬롯마다 소켓 하나(`socket2`로 `SO_REUSEADDR` 없이 바인딩), 수신지 태그가 자기 키셋에 없으면 드롭, 출발지 TOFU 고정, 그리고 **받은 것과 같은 크기만 전송**하므로 증폭이 원리적으로 불가능하다.

배정이 바뀌면 슬롯 테이블만 갱신한다 — 재기동도, 연결 재수립도 필요 없다.

---

## 11. WireGuard 어댑터 — 검증한 크레이트와 ABI

Linux 커널 WireGuard는 **generic netlink 패밀리 `"wireguard"`** 다. 확인한 UAPI:

| | 값 |
|---|---|
| 패밀리 이름 | `WG_GENL_NAME = "wireguard"` |
| 명령 | `WG_CMD_GET_DEVICE`, `WG_CMD_SET_DEVICE` |
| 디바이스 속성 | `IFINDEX`, `IFNAME`, `PRIVATE_KEY`, `PUBLIC_KEY`, `FLAGS`, `LISTEN_PORT`, `FWMARK`, `PEERS` |
| 피어 속성 | `PUBLIC_KEY`, `PRESHARED_KEY`, `FLAGS`, `ENDPOINT`, `PERSISTENT_KEEPALIVE_INTERVAL`, `LAST_HANDSHAKE_TIME`, `RX_BYTES`, `TX_BYTES`, `ALLOWEDIPS`, `PROTOCOL_VERSION` |
| AllowedIP 속성 | `FAMILY`, `IPADDR`, `CIDR_MASK`, `FLAGS` |
| 엔드포인트 표현 | `struct sockaddr` |
| 마지막 핸드셰이크 | `struct __kernel_timespec` |

이걸 그대로 쓰는 크레이트 조합:

| 역할 | crate | 확인한 API |
|---|---|---|
| 인터페이스 생성·주소·MTU·라우트 | `rtnetlink` 0.23 | link add(kind `wireguard`), address add, route add/del |
| WG 속성 설정·조회 | `nl-wireguard` 0.3 | `new_connection()`, `handle.get_by_name(iface)`, `handle.set(config)`, `handle.remove_peer(iface, pubkey)`, 타입 `WireguardParsed` / `WireguardPeerParsed` / `WireguardIpAddress` / `WireguardParsedDeviceFlags::ReplacePeers` / `WireguardParsedPeerFlags::ReplaceAllowedIps` |
| 저수준이 필요할 때 | `netlink-packet-wireguard` 0.5 | `WireguardMessage`, `WireguardAttribute`, `WireguardCmd`, `WireguardPeer`, `WireguardPeerAttribute`, `WireguardAllowedIp`, `WireguardTimeSpec` |

`nl-wireguard` 문서가 명시한다: **인터페이스 생성은 `rtnetlink`가 먼저 해야 하고**, `nl-wireguard`는 설정만 한다. 그래서 어댑터가 정확히 두 크레이트로 나뉜다. 라우트도 `rtnetlink`의 같은 연결에서 처리하므로 `Routes` 구현이 별도 의존성을 갖지 않는다.

`AllowedIpsPolicy::ExitPeer`가 만들어내는 `0.0.0.0/0`은 `WireguardPeerParsed.allowed_ips`에 `WireguardIpAddress { ip_addr, prefix_length: 0 }`로 그대로 들어간다.

대안으로 `defguard_wireguard_rs` 0.12(`WGApi`, `WireguardInterfaceApi`, `InterfaceConfiguration`, `Kernel`/`Userspace`)가 있다. 크로스플랫폼이 필요해지면 그때 갈아탄다 — 포트 뒤에 있으므로 비용은 어댑터 하나다.

`WireGuard::status`가 `LAST_HANDSHAKE_TIME`, `ENDPOINT`, `RX/TX_BYTES`를 읽어 `PeerStatus`를 만들고, 그게 `Event::Handshake`/`Event::Degraded`를 만든다. 상태기계에 시간을 넣는 유일한 지점이다.

---

## 12. CLI

```
wgmesh  join --token <T> [--config PATH]     # 명시적 등록 (설정 파일 없이도 됨)
wgmesh  run  --config PATH                   # 데몬 (systemd가 부르는 것)
wgmesh  status [--json]                      # 피어별 경로·엔드포인트·핸드셰이크
wgmesh  peers [--json]                       # 피어별 AllowedIPs와 경로
wgmesh  routes [--json]                      # 우리가 설치한 라우트만 (표식 기준)
wgmesh  routes plan                          # 지금 적용될 Add/Remove를 실행 없이 출력
wgmesh  routes reset                         # 표식이 붙은 라우트 전부 제거
wgmesh  relays                              # 릴레이 풀, 내 슬롯, 헬스
wgmesh  config show|check|defaults            # 유효 설정 / 검증 / 기본값 전체
wgmesh  key show|rotate                       # 공개키 출력 / 터널 키 로테이션
wgmesh  state show|reset                      # 상태 확인 / 삭제 후 재동기화
wgmesh  trust show|rotate                     # 코디네이터 SPKI 핀
wgmesh  doctor                                # NAT 진단 + 라우팅/포워딩 점검
wgmesh  pin <url>                             # 코디네이터 SPKI 핀 계산
```

`wgmesh-relayd enroll|run|status|drain|keyset`, `wgmeshd run|bootstrap|network|token|device|relay`.

`routes plan`이 이 기능의 디버깅 도구다 — "무엇이 왜 들어가고 무엇이 안 들어가는지"를 실제로 적용하지 않고 보여준다. `doctor`는 NAT 진단에 더해 다음을 점검한다: `table = "off"`인데 라우트가 필요한 상태인지, `0.0.0.0/0`이 두 피어에 있는지, `ip_forward`가 꺼져 있는데 `forwarding.enabled`가 켜져 있는지, `prefixes`가 코디네이터가 준 대역 밖을 가리키는지.

`wgmesh peers`는 AllowedIPs를 `peer`/`any`/`exit:gw` 중 무엇으로 프로그래밍했는지 그대로 보여준다 — catch-all이 어디 붙었는지 눈으로 확인할 수 있어야 한다.

---

## 13. NixOS 모듈

### 13.1 flake 출력

```nix
{
  outputs = { self, nixpkgs, ... }: {
    overlays.default = final: prev: {
      wgmesh = final.callPackage ./nix/packages/wgmesh.nix { };
    };
    nixosModules = rec {
      agent       = ./nix/modules/agent.nix;
      relay       = ./nix/modules/relay.nix;
      coordinator = ./nix/modules/coordinator.nix;
      default     = { imports = [ agent relay coordinator ]; };
    };
    packages.${system} = { wgmesh = …; wgmesh-relayd = …; wgmeshd = …; default = …; };
    checks.${system} = {
      deps       = self.packages.${system}.xtask-deps;
      e2e        = pkgs.nixosTest ./nix/tests/e2e.nix;
      relay-unit = pkgs.nixosTest ./nix/tests/relay.nix;
      forwarding = pkgs.nixosTest ./nix/tests/forwarding.nix;
    };
  };
}
```

### 13.2 켜는 포맷 — 에이전트

```nix
{
  imports = [ wgmesh.nixosModules.default ];

  services.wgmesh.agent = {
    enable = true;

    # TOML과 1:1. 모듈은 이걸 파일로 렌더링만 한다 (스키마 중복 없음)
    settings = {
      coordinator = {
        url         = "https://wgmesh.example.com";
        spki_sha256 = "9f2c…";
        network     = "prod";
      };
      interface.listen_port = 51820;

      # 이 노드를 기본 게이트웨이로 쓰고, 커널에는 사내 대역만 넣는다
      peers.exit_peer = "gw";
      route = {
        table    = "main";
        prefixes = [ "10.77.0.0/16" "192.168.5.0/24" ];
      };
      forwarding.enabled = true;
    };

    # 비밀은 경로로만 받는다 (sops-nix / agenix / 아무 파일)
    enrollmentTokenFile = config.sops.secrets."wgmesh/token".path;
    apiKeyFile          = config.sops.secrets."wgmesh/api-key".path;   # 선택
    wireguardKeyFile    = null;                                        # 선택: 프로비저닝 모드

    openFirewall = true;    # interface.listen_port를 연다
  };
}
```

라우팅을 다른 데몬(BIRD 등)에 완전히 맡기는 노드는 이렇게만 하면 된다:

```nix
settings.route.table = "off";       # 라우트를 만들지 않는다
settings.route.address = "auto";    # 주소와 인터페이스는 wgmesh가 관리
```

### 13.3 모듈이 만드는 것

```nix
# nix/modules/agent.nix (요지)
{ config, lib, pkgs, ... }:
let
  cfg = config.services.wgmesh.agent;
  toml = pkgs.formats.toml { };
in {
  options.services.wgmesh.agent = {
    enable              = lib.mkEnableOption "wgmesh agent";
    package             = lib.mkOption { type = lib.types.package; default = pkgs.wgmesh; };
    user                = lib.mkOption { type = lib.types.str; default = "wgmesh"; };
    stateDir            = lib.mkOption { type = lib.types.path; default = "/var/lib/wgmesh"; };
    configFile          = lib.mkOption { type = lib.types.nullOr lib.types.path; default = null; };
    settings            = lib.mkOption { type = toml.type; default = { }; };
    enrollmentTokenFile = lib.mkOption { type = lib.types.nullOr lib.types.path; default = null; };
    apiKeyFile          = lib.mkOption { type = lib.types.nullOr lib.types.path; default = null; };
    wireguardKeyFile    = lib.mkOption { type = lib.types.nullOr lib.types.path; default = null; };
    openFirewall        = lib.mkOption { type = lib.types.bool; default = false; };
    forwarding = {
      enable   = lib.mkOption { type = lib.types.bool; default = cfg.settings.forwarding.enabled or false; };
      firewall = lib.mkOption { type = lib.types.enum [ "off" "manage" ]; default = "off"; };
      trustedInterfaces = lib.mkOption { type = lib.types.listOf lib.types.str; default = [ ]; };
    };
    logLevel            = lib.mkOption { type = lib.types.str; default = "info"; };
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = (cfg.configFile != null) || (cfg.settings.coordinator.spki_sha256 or "") != "";
      message   = "services.wgmesh.agent: coordinator.spki_sha256 is required (or supply configFile)";
    }];

    users.users.${cfg.user} = { isSystemUser = true; group = cfg.user; };
    users.groups.${cfg.user} = { };

    environment.etc."wgmesh/agent.toml".source =
      if cfg.configFile != null then cfg.configFile else toml.generate "agent.toml" cfg.settings;

    systemd.services.wgmesh-agent = {
      wantedBy = [ "multi-user.target" ];
      after    = [ "network-online.target" ];
      wants    = [ "network-online.target" ];
      environment.WGMESH__LOG__LEVEL = cfg.logLevel;
      serviceConfig = {
        ExecStart       = "${cfg.package}/bin/wgmesh run --config /etc/wgmesh/agent.toml";
        User            = cfg.user;
        Group           = cfg.user;
        StateDirectory  = "wgmesh";
        StateDirectoryMode = "0750";
        RuntimeDirectory = "wgmesh";
        Restart         = "always";
        RestartSec      = 5;

        # 비밀은 systemd credential로만 들어가고 설정 파일에 경로가 남는다
        LoadCredential = lib.optional (cfg.enrollmentTokenFile != null)
          "enrollment-token:${cfg.enrollmentTokenFile}"
          ++ lib.optional (cfg.apiKeyFile != null) "api-key:${cfg.apiKeyFile}"
          ++ lib.optional (cfg.wireguardKeyFile != null) "wg-key:${cfg.wireguardKeyFile}";
        Environment = lib.optional (cfg.enrollmentTokenFile != null)
          "WGMESH__ENROLLMENT__TOKEN_FILE=%d/enrollment-token"
          ++ lib.optional (cfg.apiKeyFile != null) "WGMESH__INTERFACE__API_KEY_FILE=%d/api-key"
          ++ lib.optional (cfg.wireguardKeyFile != null) "WGMESH__INTERFACE__PRIVATE_KEY_FILE=%d/wg-key";

        # 커널 인터페이스와 라우트를 만지려면 CAP_NET_ADMIN 하나면 충분하다
        AmbientCapabilities   = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_NETLINK" ];

        ProtectSystem = "strict";
        ProtectHome   = true;
        PrivateTmp    = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        MemoryDenyWriteExecute = true;
        SystemCallFilter = [ "@system-service" ];
        SystemCallArchitectures = [ "native" ];
      };
    };

    networking.firewall.allowedUDPPorts =
      lib.optional (cfg.openFirewall && (cfg.settings.interface.listen_port or 0) != 0)
        cfg.settings.interface.listen_port;
  };
}
```

세 가지 설계 결정을 짚어 둔다.

- **`settings`는 freeform TOML 미러다.** 옵션을 타입으로 다시 정의하지 않는다 — 스키마가 두 곳에 생기고 반드시 어긋나기 때문이다. 모듈이 실제로 값을 알아야 하는 곳만 `settings.x or 기본값`으로 읽는다(방화벽 포트, 포워딩 여부, 로그 레벨).
- **비밀은 `LoadCredential` + 환경 변수로 주입한다.** TOML에 비밀 경로를 심지 않으므로 설정 파일은 순수하게 선언적이고, 토큰은 `/run/credentials/...`에만 존재한다.
- **`configFile`을 주면 `settings`를 무시한다.** 손으로 쓴 TOML을 그대로 쓰고 싶은 사람의 탈출구다.

### 13.4 포워딩을 켤 때 모듈이 추가로 하는 일

```nix
# services.wgmesh.agent.forwarding.enable = true 일 때
boot.kernel.sysctl = {
  "net.ipv4.ip_forward"          = 1;
  "net.ipv6.conf.all.forwarding" = 1;
};

# nftables 백엔드에서 FORWARD 필터링을 끈다 (기본값이지만 명시한다)
networking.firewall.filterForward = false;

# 비대칭 라우팅(WG)에서 strict rp_filter는 패킷을 버린다
networking.firewall.checkReversePath = "loose";

networking.nftables.tables.wgmesh-forward = lib.mkIf (cfg.forwarding.firewall == "manage") {
  family = "inet";
  content = ''
    chain forward {
      type filter hook forward priority filter; policy accept;
      iifname { ${toString cfg.forwarding.trustedInterfaces} } oifname "wg0" accept
      iifname "wg0" oifname { ${toString cfg.forwarding.trustedInterfaces} } accept
    }
  '';
};
```

확인한 nixpkgs 사실: `networking.firewall.filterForward`는 존재하고 **기본 `false`**이며 설명이 "This option only works with the nftables based firewall"이다. `networking.firewall.checkReversePath`는 존재하고 **기본 `"loose"`**다. 그래서 이 둘은 이미 원하는 값이지만 **명시적으로 쓴다** — 기본값에 의존하면 백엔드가 iptables로 바뀌는 순간 조용히 달라진다.

`sysctl`은 모듈이 직접 설정한다(에이전트의 `forwarding.sysctl`은 NixOS에서 끈다). 선언적 관리가 우선이다.

### 13.5 릴레이 모듈

```nix
services.wgmesh.relay = {
  enable = true;
  settings = {
    coordinator.url         = "https://wgmesh.example.com";
    coordinator.spki_sha256 = "9f2c…";
    relay.listen            = "0.0.0.0";
    relay.port_range        = [ 51820 51999 ];
  };
  enrollmentTokenFile = config.sops.secrets."wgmesh/relay-token".path;
  openFirewall = true;                       # 포트 범위를 연다
};
```

유닛은 에이전트와 같은 골격에서 `CAP_NET_ADMIN`이 빠지고 `RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ]`만 남는다. 트래픽 상한은 `settings.limits`에서 읽어 그대로 넘긴다. `wgmesh-relayd drain`을 위한 `ExecReload`.

### 13.6 코디네이터 모듈

```nix
services.wgmesh.coordinator = {
  enable = true;
  settings.api.listen = "127.0.0.1:8080";
  openFirewall = false;                      # 공개는 리버스 프록시로만
};

services.caddy = {
  enable = true;
  virtualHosts."wgmesh.example.com".extraConfig = "reverse_proxy 127.0.0.1:8080";
};
```

DB는 `StateDirectory` 아래에 두고, 모듈이 `services.wgmesh.coordinator.backup`(선택)으로 `sqlite3 .backup`을 하루 한 번 돌리는 유닛을 만들 수 있게 한다. SQLite에는 공개키와 해시만 있으므로 백업 유출이 치명적이지 않다.

### 13.7 flake 안의 e2e 테스트

NixOS 테스트는 VM에서 root로 돌기 때문에 커널 WireGuard를 실제로 쓸 수 있다. 이게 이 프로젝트에서 가장 값싼 진짜 검증이다.

```nix
# nix/tests/e2e.nix (요지)
{
  name = "wgmesh-e2e";
  nodes.router = { ... };                    # 코디네이터 + 릴레이
  nodes.nodeA  = { services.wgmesh.agent = { enable = true; settings.coordinator.url = "https://router/"; ... }; };
  nodes.nodeB  = { ... };
  testScript = ''
    router.wait_for_unit("wgmeshd.service")
    router.wait_for_unit("wgmesh-relayd.service")
    nodeA.wait_for_unit("wgmesh-agent.service")
    nodeB.wait_for_unit("wgmesh-agent.service")
    nodeA.wait_until_succeeds("wgmesh status --json | jq -e '.peers[0].path == \"direct\"'")
    nodeA.succeed("ping -c1 10.77.0.8")
  '';
}
```

`nix/tests/forwarding.nix`는 이 문서의 §6을 검증한다 — exit 피어를 세운 3노드 구성에서:

- `wgmesh peers --json`의 exit 피어 AllowedIPs가 `0.0.0.0/0`이고 나머지는 `/32`
- `ip route show proto wgmesh`에 **`default`가 없고** 고른 대역만 있음
- `table = "off"` 노드에서는 `ip route show proto wgmesh`가 비어 있음
- 뒤에 숨은 호스트(`10.77.0.0/16` 밖, 예: `192.168.5.10`)로 ping이 통과

에이전트 둘을 서로 다른 NAT 뒤에 두려면 VM마다 별도 라우터를 만들면 되고, 그때 `punch` 경로까지 검증된다. 노드별로 `boot.kernelModules = [ "wireguard" ]`를 넣는다.

---

## 14. 테스트 전략

| 층 | 대상 | 도구 | 상태 |
|---|---|---|---|
| 순수 단위 | `core`: mac1, 정렬, 상태기계, diff, 릴레이 라우팅, **AllowedIPs 정책·라우트 계획** | `cargo test` | **완료 — 24개 통과** (§15) |
| 어댑터 단위 | 설정 파싱·기본값·검증, 상태 원자적 쓰기, 비밀 로더(로우/base64), 서명 정규화, 라우트 표식 | `cargo test` + `tempfile`, `insta` | 계획 |
| 유스케이스 | `app`: 조인→동기화→수렴→폴백, 라우트 수렴 | 인메모리 가짜 어댑터 (`FakeWireGuard`, `FakeRoutes`, `FakeCoordinator`, `RecordingState`) | 계획 |
| 엔진 | 릴레이 포워딩 + 슬롯 + TOFU + 레이트리밋 | 실제 127.0.0.1 UDP 소켓 (권한 불필요) | 계획 |
| 프로토콜 | 릴레이가 쌍을 잘못 보내지 않는지, mac1 목적지 식별 | 속성 기반 `proptest` | 계획 |
| e2e | 커널 WG + 3 노드 + 릴레이 + **포워딩/라우팅** | `nixosTest` | 계획 |

포트/어댑터 분리가 여기서 값을 낸다: 커널도 네트워크도 없이 "조인 → 관찰 → 펀치 → 폴백 → 릴레이 재배정 → 라우트 수렴"을 전부 단위 테스트로 돌릴 수 있다. 이전에 만든 파이썬 랩 두 개는 그대로 **참조 구현**으로 남겨 두고, 같은 시나리오를 Rust 테스트로 옮겨 두 곳이 어긋나면 알게 한다.

---

## 15. 검증 기록 — 순수 코어는 실제로 돈다

`crates/wgmesh-core`를 만들어 실제로 컴파일·테스트했다. `rustc 1.99.0`, 의존성은 `blake2 = "0.11"` 하나.

```
running 24 tests
test route::tests::any_policy_is_only_meaningful_for_a_single_peer ... ok
test route::tests::auto_prefixes_take_the_network_and_advertised_bands ... ok
test route::tests::a_numbered_table_is_carried_into_every_route ... ok
test route::tests::exit_peer_carries_the_catch_all_while_the_mesh_stays_specific ... ok
test route::tests::exit_peer_must_name_a_configured_peer ... ok
test route::tests::none_prefixes_and_an_unmanaged_table_install_nothing ... ok
test route::tests::only_prefixes_selects_the_band_and_drops_the_rest ... ok
test route::tests::peer_policy_keeps_each_peer_on_its_own_prefixes ... ok
test route::tests::plan_routes_adds_and_removes_against_what_is_installed ... ok
test route::tests::the_default_route_is_never_installed ... ok
test tests::assignment_arms_the_relay_path ... ok
test tests::candidate_ranking_prefers_lan_then_freshest ... ok
test tests::degraded_direct_path_reverts_to_the_relay_and_backs_off ... ok
test tests::diff_adds_updates_and_removes ... ok
test tests::failed_punch_falls_back_then_retries_with_backoff ... ok
test tests::mac1_pins_the_intended_recipient ... ok
test tests::mac1_rejects_wrong_shape ... ok
test tests::no_candidates_keeps_the_relay_path ... ok
test tests::punch_starts_after_the_delay_and_holds_direct ... ok
test tests::reassignment_drops_stale_observations_and_arms_the_new_relay ... ok
test tests::relay_forwards_only_assigned_pairs_from_known_slots ... ok
test tests::relay_pins_the_source_address_until_it_goes_stale ... ok
test tests::relay_rejects_packets_that_are_not_wireguard_shaped ... ok
test tests::unassigned_pair_is_dropped ... ok
test result: ok. 24 passed; 0 failed
```

컴파일과 사실 확인이 잡아낸 것들 (문서만 썼으면 그대로 나갔을 것):

| 잡은 것 | 내용 |
|---|---|
| `mac1`의 출력 길이 | BLAKE2s는 **출력 길이가 파라미터에 섞인다.** 32바이트 해시를 잘라 쓰면 틀린다. 프로토콜 원문이 `MAC(key, input) = Keyed-Blake2s(key, input, 16)`이므로 `Blake2sMac<U16>`이어야 한다. 그래서 `mac1_key`(HASH, 32바이트 출력)와 `Mac1`(16바이트 출력)이 **다른 타입**이다 |
| Idle → Probing 전이 누락 | 초기 설계에는 "언제 펀치를 시작하는가"가 없었다. `punch_delay`를 둔 `Phase::Idle { next_attempt }`가 필요했다 |
| 살아 있는 직접 경로를 다시 건드림 | 첫 구현은 주기적으로 재시도해서 **잘 돌아가는 경로를 스스로 끊었다.** `path == Direct`면 틱을 무시하고, 경로 사망은 `Event::Degraded`로만 들어오게 바꿨다 |
| 릴레이 재배정 시 옛 관찰값 | 다른 릴레이에서 얻은 후보는 대칭 NAT에서 무의미하다 → `Assignment`가 `Lan`/`Ipv6` 외 후보를 버린다 |
| **AllowedIPs 겹침은 거부되지 않는다** | 나는 커널이 겹치는 AllowedIPs를 거부한다고 잘못 기억하고 있었다. `allowedips.c`를 읽어보니 `wg_allowedips_insert_v4` → `add`는 겹침을 검사하지 않고 `-EINVAL`/`-ENOMEM`만 낸다. 조회는 LPM이다. **그래서 `exit_peer` 설계가 성립한다** — 이걸 확인하지 않았으면 "0.0.0.0/0은 피어 하나일 때만"이라는 잘못된 제약을 넣었을 것이다 |
| 같은 catch-all을 두 피어에 주면 조용히 진다 | `add`가 정확히 일치하는 노드를 찾으면 peer 포인터를 갱신하므로 나중 것이 이긴다 → `AnyPolicyNeedsOnePeer`로 거부 |
| `[0; 16]`은 패턴이 아니다 | `is_catch_all`을 배열 리터럴 패턴으로 쓰려다 컴파일 실패. mask==0 + 바이트 전부 0 비교로 바꿨다 |

**검증하지 않은 것:** netlink 어댑터(§11의 크레이트·ABI는 문서로 확인했으나 코드로는 미확인), 라우트 표식과 실제 `ip route` 동작, SQLite 스키마와 HTTP 표면, 실제 NAT 하드웨어, NixOS 모듈의 평가. 이들은 e2e 테스트와 NixOS VM 테스트가 붙을 때 확인된다.

---

## 16. 스타일 규칙과 CI

주석 규칙은 취향이 아니라 검사 대상이다.

```bash
# 파일 레벨 주석 금지
! grep -rn --include='*.rs' -e '^//!' crates/ xtask/

# 코드에 한글 금지 (주석 포함 — 주석은 영문)
! grep -rnP --include='*.rs' '[\x{AC00}-\x{D7A3}]' crates/ xtask/
```

CI 파이프라인:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo xtask check-deps          # §1.1 의존 규칙
cargo xtask check-style         # 위 두 grep
cargo deny check licenses bans
nix build .#checks.x86_64-linux.e2e
nix build .#checks.x86_64-linux.forwarding
```

`xtask`는 별도 크레이트로 두고 `cargo run -p xtask -- check-deps`로 부른다. 검사 규칙이 코드에 있으므로 리뷰어가 기억할 필요가 없다.

---

## 17. 구현 순서

| 단계 | 내용 | 검증 |
|---|---|---|
| M0 | `core`(완료, §15) + `ports` + `config` + `state` + `secrets` + `client` + `wireguard` + `app`(에이전트) + `cli` — **단일 노드가 릴레이를 통해 붙는다**, AllowedIPs는 `peer` 정책, 라우트는 네트워크 대역만 | 단위 + 2노드 VM |
| M1 | `route` 정책(§6) + exit 피어 + 포워딩, `coordinator`(조인·설정·릴레이 배정·관찰) + `relay` 바이너리 → **페일오버까지** | `forwarding` nixosTest |
| M2 | 서명 인증 전환, SPKI 핀, 승인 대기, 감사 로그, 레이트리밋, SSE, `doctor`, `routes plan` | e2e + 부하 |
| M3 | 릴레이당 노드 1포트 + mac1/`receiver_index` 라우팅, IPv6·LAN 후보, UPnP, 대칭 NAT 예측 | 랩 + 실측 |

M0의 순서가 중요하다: **릴레이를 처음부터 별도 바이너리로 만든다.** 나중에 떼어내는 비용이 훨씬 크다. 라우팅 정책(§6)은 M1에 넣는다 — M0에서는 `program_allowed_ips(Peer)`와 `desired_routes(Auto)`만 쓰면 되고, 어차피 그 두 경로가 순수 함수라 나머지는 옵션을 여는 일이다.

---

## 부록 A. 파일 트리 (M0 기준)

```
wgmesh/
├── Cargo.toml
├── rust-toolchain.toml
├── xtask/{Cargo.toml,src/main.rs,src/deps.rs,src/style.rs}
├── crates/
│   ├── wgmesh-core/     src/{lib.rs, packet.rs, traversal.rs, relay.rs, diff.rs, route.rs}
│   ├── wgmesh-ports/    src/{lib.rs, coordinator.rs, wireguard.rs, routes.rs, stores.rs}
│   ├── wgmesh-app/      src/{lib.rs, agent/, coordinator/}
│   ├── wgmesh-config/   src/{lib.rs, agent.rs, relay.rs, coordinator.rs, validate.rs, route.rs}
│   ├── wgmesh-state/    src/{lib.rs, file.rs, atomic.rs}
│   ├── wgmesh-secrets/  src/{lib.rs, file.rs, parse.rs, generate.rs}
│   ├── wgmesh-proto/    src/{lib.rs, api.rs, canonical.rs}
│   ├── wgmesh-wireguard/src/{lib.rs, netlink.rs, routes.rs, sysctl.rs}
│   ├── wgmesh-client/   src/{lib.rs, http.rs, pin.rs}
│   ├── wgmesh-coordinator/{src/{lib.rs, http/, store/, service/, bin/wgmeshd.rs}, migrations/}
│   ├── wgmesh-relay/    src/{lib.rs, engine.rs, sockets.rs, bin/wgmesh-relayd.rs}
│   └── wgmesh-cli/      src/{main.rs, container.rs, commands/}
└── nix/{modules/{agent,relay,coordinator}.nix, packages/, tests/{e2e,relay,forwarding}.nix}
```

## 부록 B. `wgmesh-core`를 그대로 돌려보기

`crates/wgmesh-core/Cargo.toml`은 두 줄짜리다:

```toml
[package]
name    = "wgmesh-core"
version = "0.1.0"
edition = "2024"

[dependencies]
blake2 = "0.11"
```

첨부한 `wgmesh-core-reference.rs`와 `wgmesh-core-route.rs`를 각각 `src/lib.rs`와 `src/route.rs`로 두고 `cargo test`를 돌리면 위 24개 테스트가 그대로 통과한다. 커널도 네트워크도 필요 없다.
