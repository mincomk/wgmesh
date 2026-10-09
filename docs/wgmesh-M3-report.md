# wgmesh M3 보고서 — 후보 다양화와 대칭 NAT 대응

> 단계 16 (`IPv6·LAN·UPnP 후보와 대칭 NAT 대응, M3 보고서`)의 산출물.
> 브랜치는 `m0/scaffold`(단계 1의 워크스페이스 골격) 위에 놓였다. 이 문서는 다음 국면(실기 검증)으로 넘기는 인계 문서다 — 무엇이 코드와 테스트로 증명됐고, 무엇이 여전히 가정인지 구분해서 적는다.

## 0. 요약

- 후보 등급과 우선순위 `Lan → Ipv6 → Observed → Mapping → Relay`(같은 등급은 최신 우선)가 `wgmesh-core`의 순수 함수로 들어갔고, 순수 테스트로 단정된다.
- `traversal.ipv6 = false`면 IPv6 후보가 만들어지지 않고, `traversal.lan_candidates = false`면 LAN 후보가 빠진다.
- `traversal.upnp`의 기본값은 `false`이고, 그때 NAT-PMP/UPnP 포트는 **호출 자체가 일어나지 않는다** — 호출 횟수를 세는 fake로 단정한다.
- 대칭 NAT는 **폴백 + 백오프**로 처리한다. 통합 테스트가 직접 시도 실패 → `punch_window` 뒤 릴레이 복귀 → 30초 → 2분 → 10분 백오프를 단정한다.
- 직접 경로가 나중에 죽으면 에이전트가 핸드셰이크 부재를 `Event::Degraded`로 바꿔 릴레이 슬롯으로 복귀하고, 슬롯 재관찰로 **한 왕복 안에** 자가치유된다.
- **대칭 NAT 포트 예측(birthday attack)은 이번 범위 밖이다** (§7).
- 이 Computer에서 돌아간 테스트: `cargo test --workspace` 50개 (core 31 · config 9 · app 단위 7 · 통합 3), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo xtask check-deps`, `cargo xtask check-style` 전부 통과.

## 1. 저장소에 더한 것

| crate | 추가 | 역할 |
|---|---|---|
| `wgmesh-core` | `candidates.rs` | 후보 등급·정렬·정책을 담은 순수 함수. I/O 없음 |
| `wgmesh-ports` | `discovery.rs`, `traversal.rs` | `InterfaceInventory`, `PortMapper`, `WireGuard`, `CoordinatorApi`, `Clock` trait |
| `wgmesh-app` | `agent/discovery.rs` | `CandidateDiscovery` — 주소 수집과 (켜졌을 때만) 포트 매핑 |
| `wgmesh-app` | `agent/traversal.rs` | `TraversalRunner`, `PeerTraversal`, `degraded()` |
| `wgmesh-config` | `TraversalSettings`, `Settings` | `[traversal]` 스키마·기본값·검증 |
| `wgmesh-testkit` | 새 crate | `VirtualClock`, `NatSim`, `FakeWireGuard`, `FakeCoordinator`, `RecordingPortMapper`, `block_on` |

`wgmesh-testkit`은 새 워크스페이스 멤버이므로 `xtask/src/deps.rs`의 의존 표에 한 줄을 추가했다(내부 `wgmesh-core`, `wgmesh-ports`; 외부 `async-trait`). 제품 crate가 아니라 테스트 지원 crate이며, 앱 crate에는 dev-dependency로만 들어간다.

### 1.1 후보 등급 — 설계 §3.2가 코드가 되는 자리

```rust
pub enum CandidateKind { Lan, Ipv6, Observed, Mapping, Relay }
```

`rank()`가 등급 순으로, 같은 등급 안에서는 `observed_at`이 **큰 것 먼저**로 정렬한다. 각 후보가 관측 시각을 들고 다니는 이유가 이것이다 — LAN 주소도, IPv6 주소도, 릴레이 관측값도 "언제 본 것인가"가 다르고, 같은 등급에서 오래된 값을 먼저 쓰면 이미 죽은 매핑으로 직접 시도를 걸게 된다.

`discover(&DiscoverySources, DiscoveryPolicy)`가 정책을 적용해 후보를 만들고, `best_candidate(...)`가 릴레이를 마지막 후보로 붙여 **전순서**를 만든다. 후보가 하나도 없으면 릴레이가 최선이라는 사실이 예외가 아니라 정렬의 결과로 나온다.

### 1.2 세 개의 스위치

| 설정 | 기본값 | 효과 |
|---|---|---|
| `traversal.lan_candidates` | `true` | `false`면 `Lan` 후보를 만들지 않는다 |
| `traversal.ipv6` | `true` | `false`면 `Ipv6` 후보를 만들지 않는다 |
| `traversal.upnp` | **`false`** | `false`면 `PortMapper` 포트를 **호출하지 않는다** |

앞의 둘은 후보 생성 단계의 필터이고, `upnp`는 그 앞단 — 라우터에게 말을 거는 행위 자체 — 를 막는다. 그래서 `upnp = false`의 단정은 "Mapping 후보가 없다"가 아니라 **"포트 매퍼 호출 횟수가 0이다"**로 쓴다(`wgmesh-app/src/agent/discovery.rs::upnp_off_never_touches_the_port_mapper`).

`Observed`와 `Relay`는 끌 수 없다. 릴레이가 관찰한 주소는 양쪽이 실제로 합의하는 유일한 값이고, 릴레이는 항상 남아야 하는 폴백이기 때문이다.

## 2. 대칭 NAT — 폴백 + 백오프 (설계 §3.4, §4.10)

### 2.1 WireGuard의 구조적 제약을 코드가 아니라 테스트에 남긴다

WireGuard 피어는 **엔드포인트가 하나뿐**이다. 직접 후보를 넣는 순간 릴레이 경로가 끊긴다. 그래서 "검증 후 전환"은 불가능하고, 창을 짧게 잡고 실패하면 즉시 되돌리는 수밖에 없다. 이 사실이 통합 테스트에 그대로 적혀 있다:

```rust
assert_eq!(harness.wireguard.current_endpoint(), Some(harness.peer_endpoint),
    "the peer endpoint is the direct candidate now, and the relay path is broken for as long \
     as it stays there — a WireGuard peer has exactly one endpoint");
```

기본값은 `punch_delay_secs = 2`, `punch_window_secs = 5`, `backoff_secs = [30, 120, 600]`이다. 창(5초)이 keepalive(25초)보다 짧아야 한다는 규칙은 `wgmesh-config`의 검증이 강제한다 — 창이 매핑 수명보다 길면 실패했을 때 돌아갈 릴레이 매핑 자체가 식어 있다.

### 2.2 참조 코어에서 고친 것 — 릴레이 핸드셰이크가 백오프를 지우고 있었다

**이 단계에서 참조 코어의 결함을 하나 찾아 고쳤다.** 원래 `Event::Handshake`는 `attempts = 0`을 무조건 실행했다. 순수 테스트는 핸드셰이크 이벤트를 넣지 않으므로 통과했지만, 실제 시스템에서는 `persistent-keepalive`가 릴레이 경로에서 계속 핸드셰이크를 만들고, 그것이 매번 후퇴 카운터를 0으로 되돌린다. 결과적으로 대칭 NAT에서 백오프는 30초에서 더 자라지 못하고, 2분·10분 단계는 영원히 도달하지 않는다 — §4.10이 요구하는 것과 정반대다.

고친 뒤의 규칙:

> **직접 엔드포인트로 들어온 핸드셰이크만** 직접 경로가 살아 있다는 증거다. 릴레이 핸드셰이크는 keepalive가 일한 결과일 뿐이므로 경로를 `Relayed`로 표시할 뿐, 후퇴 카운터와 대기 시각은 건드리지 않는다.

`wgmesh-core::tests::a_relay_handshake_does_not_clear_the_retreat_counter`가 이 규칙을 고정한다. 커널 WireGuard를 띄워 본 것이 아니라 상태기계와 모델의 모순을 찾아낸 것이므로, **실기에서 keepalive 주기(25초)와 재키 주기(약 2분)가 이 가정과 맞는지 확인해야 한다** (§6).

## 3. 직접 경로 생존 감지와 자가치유

커널은 인증된 패킷이 오면 엔드포인트를 알아서 갱신(roaming)한다. 그래서 직접 경로가 죽어도 **이벤트가 저절로 오지 않는다.** 핸드셰이크가 멈추는 것이 유일한 신호이고, 그것을 `Event::Degraded`로 바꾸는 것이 에이전트의 일이다:

```rust
pub fn degraded(path: Path, last_handshake: Option<Millis>, now: Millis, keepalive: Duration) -> bool
```

`path == Direct`이고 마지막 핸드셰이크가 **keepalive의 3배**보다 오래됐으면 죽은 것으로 본다. 살아 있는 경로는 건드리지 않는다 — 잘 돌아가는 직접 경로를 주기적으로 재시도해서 스스로 끊는 것이 참조 코어가 이미 겪은 실수였고, 그 규칙은 그대로 유지된다.

`Degraded`가 들어오면 상태기계는 후퇴 카운터를 올리고 엔드포인트를 릴레이 슬롯으로 되돌린 뒤 다음 시도를 30초 뒤로 미룬다. 그 뒤 릴레이 경로로 트래픽이 다시 흐르면 릴레이가 피어의 매핑을 **재관찰**하고, 에이전트는 다음 라운드에 그 값을 받아 후보를 갱신한다. 통합 테스트는 자가치유가 **한 왕복(30초) 안에** 일어나는지를 단정한다.

## 4. 무엇이 증명됐나 — 테스트 이름과 단정 내용

| 테스트 | 단정하는 것 |
|---|---|
| `wgmesh-core::tests::candidate_ranking_prefers_lan_then_freshest` | 등급 순서와 같은 등급 최신 우선 |
| `wgmesh-core::candidates::tests::candidates_are_ordered_lan_then_ipv6_then_observed_then_mapping_then_relay` | 5등급 전체 순서, 릴레이가 마지막 |
| `wgmesh-core::candidates::tests::within_one_class_the_newest_candidate_wins` | 같은 등급 안의 정렬 |
| `wgmesh-core::candidates::tests::ipv6_off_produces_no_ipv6_candidate` | `ipv6 = false` → `Ipv6` 후보 0개 |
| `wgmesh-core::candidates::tests::lan_off_drops_the_lan_candidate` | `lan_candidates = false` → `Lan` 후보 제거 |
| `wgmesh-core::candidates::tests::both_local_classes_off_leaves_the_relay_as_the_best_candidate` | 둘 다 끄면 릴레이가 최선 |
| `wgmesh-app::agent::discovery::tests::upnp_off_never_touches_the_port_mapper` | **포트 매퍼 호출 0회**, Mapping 후보 없음 |
| `wgmesh-app::agent::discovery::tests::upnp_on_asks_the_gateway_once_and_keeps_the_mapped_port` | 켜면 1회 호출, 매핑이 후보로 들어옴 |
| `wgmesh-app::agent::traversal::tests::a_direct_path_without_handshakes_for_three_keepalives_is_degraded` | 핸드셰이크 부재 → Degraded 판정 |
| `wgmesh-app::agent::traversal::tests::a_relayed_path_is_never_degraded` | 릴레이 경로는 Degraded로 보지 않음 |
| `wgmesh-app::agent::traversal::tests::a_direct_path_that_keeps_handshaking_is_healthy` | 살아 있는 경로는 건드리지 않음 |
| `wgmesh-app::tests::symmetric_nat::a_symmetric_nat_falls_back_to_the_relay_after_the_window_and_then_backs_off` | 직접 시도 실패 → 창 뒤 릴레이 복귀 → 백오프 30초·2분·10분 |
| `wgmesh-app::tests::symmetric_nat::a_cone_nat_promotes_the_direct_path_and_then_leaves_it_alone` | 성공한 직접 경로는 600초 동안 재시도 없음 |
| `wgmesh-app::tests::symmetric_nat::a_direct_path_that_goes_quiet_is_detected_and_heals_over_the_relay_within_one_round_trip` | 직접 경로 사망 감지 → 릴레이 복귀 → 1왕복 자가치유 |
| `wgmesh-core::tests::a_relay_handshake_does_not_clear_the_retreat_counter` | §2.2의 수정 규칙 |
| `wgmesh-config::tests::upnp_is_off_unless_it_is_asked_for` | `upnp` 기본값 `false` |
| `wgmesh-config::tests::the_defaults_are_the_documented_ones` | 기본값이 청사진 §5와 일치 |
| `wgmesh-config::tests::a_punch_window_that_outlives_the_keepalive_is_rejected` | 창 < keepalive 불변식 |

세 통합 테스트는 **가상 시계**로 돌아간다. 2초, 5초, 30초, 2분, 10분을 실제로 기다리지 않고 정확히 그 시각에 단정한다.

## 5. 미실측 — 실기에서 처음 만나게 될 것

이 목록은 "아직 안 했다"가 아니라 **"이 환경에서는 원리적으로 확인할 수 없었다"**는 뜻이다.

| 항목 | 상태 |
|---|---|
| **커널 WireGuard** | 이 Computer에는 `ip`도 `wg`도 없고, `sudo ip link add ... type wireguard`는 `RTNETLINK answers: Operation not permitted`다. `WireGuard` 포트의 실제(netlink) 구현은 이 단계에 없다. 통합 테스트의 "커널"은 `FakeWireGuard`다 |
| **실제 NAT 하드웨어** | `NatSim`은 RFC 4787의 분류를 두 상태(`Cone`/`Symmetric`)로 축약한 모델이다. 실제 NAT의 매핑 수명·필터 갱신 타이밍·포트 배정 편향은 재현하지 않는다 |
| **UPnP / NAT-PMP** | 포트(`PortMapper`)만 정의돼 있고 실제 어댑터는 없다. 게이트웨이와 한 번도 대화하지 않았다 |
| **IPv6 경로** | 후보 생성과 정책은 검증됐지만, 실제 IPv6 글로벌 주소를 수집하는 어댑터(`InterfaceInventory`)와 그 위의 직접 연결은 실측이 아니다 |
| **릴레이의 mac1/receiver_index 라우팅** | 단계 15의 범위다. 이 단계의 릴레이는 슬롯 포트로 송신자를 식별하는 모델을 쓴다 |
| **NixOS 모듈·flake** | `nix`도 `/dev/kvm`도 없어 평가되지 않는다 |
| **`persistent-keepalive` 실측** | §3의 "keepalive 3회 부재" 임계값은 모델 위에서 정한 값이다. 실제 재키 주기(약 2분)와의 관계는 실기에서 확인해야 한다 |

## 6. 실기 검증 계획 (다음 국면 인계)

### 6.1 준비

- 노드 3대 이상, 각각 **다른 NAT 뒤**에 둔다. 하나는 cone/restricted(가정용 공유기), 하나는 대칭(CGNAT·모바일 회선), 하나는 IPv6 글로벌 주소 보유. 실제 노드가 없으면 NixOS VM(`nix/tests/e2e.nix`)으로 대체한다.
- 릴레이 1대는 공인 IP에, 코디네이터 1대는 별도로.
- 관측 도구: `wg show <if> dump`(핸드셰이크·엔드포인트·송수신 바이트), `ip route show`, `tcpdump -ni any udp port <슬롯>`, 코디네이터의 관찰 테이블.

### 6.2 확인할 것 (순서대로)

1. **릴레이 경로가 먼저 선다.** 모든 노드가 릴레이 슬롯으로만 붙는 상태에서 핸드셰이크가 성립하는지.
2. **관찰값이 맞는가.** `wg show dump`의 엔드포인트와 코디네이터가 들고 있는 관찰 주소:포트가 같은지.
3. **cone/restricted에서 직접 승격.** `punch_delay` 뒤 직접 시도가 성공하고, 이후 릴레이 트래픽이 실제로 0에 가까워지는지.
4. **대칭 NAT에서 폴백.** 직접 시도 실패 후 **몇 초 안에** 릴레이 경로가 돌아오는지. 여기서 "5초 창 + 즉시 복귀"가 실제인지 확인한다.
5. **백오프가 자란다.** 대칭 NAT 노드에서 시도 간격이 30초 → 2분 → 10분으로 늘어나는지, 그리고 **keepalive가 후퇴 카운터를 지우지 않는지**(§2.2의 수정이 실제 커널 동작과 맞는지). 이 항목이 이번 단계에서 가장 위험이 큰 가정이다.
6. **직접 경로 사망 → 자가치유.** 직접 경로가 뚫린 노드에서 경로를 끊고(예: 중간 NAT 재시작·`iptables` drop), Degraded 감지까지 걸리는 시간과 복귀까지의 시간을 잰다.
7. **IPv6 노드.** 릴레이를 거치지 않고 붙는지, IPv4 후보와 경쟁할 때 IPv6가 선택되는지.
8. **UPnP를 켠 경우.** 게이트웨이가 응답하는 환경에서 매핑이 후보로 들어오고, 응답하지 않는 환경에서 **라운드가 실패하는지**(지금은 실패가 정상 동작으로 정의돼 있다 — §5 참고).

### 6.3 합격 기준

- cone/restricted 쌍: 릴레이 경유로 시작해 직접 경로로 승격, 직접 경로의 핸드셰이크가 keepalive 주기마다 갱신됨.
- 대칭 NAT 쌍: 릴레이 경로가 끊기지 않고 유지되며, 시도 간격이 30초/2분/10분으로 관측됨.
- 직접 경로 사망: 감지 후 한 왕복(≤ `sync_interval_secs`) 안에 릴레이로 복귀, 그 사이 데이터 경로가 완전히 끊기지 않음.
- 어느 경우에도 커널 라우팅 테이블에 `default` 라우트가 생기지 않음(M1의 불변식이 M3 변경으로 깨지지 않았는지 재확인).

## 7. 다음 단계

1. **대칭 NAT 포트 예측(birthday attack) — 이번 범위 밖.** 설계 §3.4대로 구현 비용 대비 이득이 작고 트래픽이 튄다. 필요한 선행 조건은 (a) 릴레이가 관찰한 포트의 배정 규칙을 측정하는 것, (b) 예측된 포트로의 시도가 실패했을 때 릴레이 매핑을 잃지 않는 창 관리다. 그 전까지는 폴백 + 백오프가 정답이다.
2. NAT-PMP / UPnP 어댑터 실제 구현 (포트는 이미 있다).
3. `InterfaceInventory`의 netlink 구현 — LAN 사설 주소와 IPv6 글로벌 주소 열거.
4. `NatSim`을 실제 NAT(또는 netns + nftables)로 교체한 실기 테스트.
5. 실기에서 §2.2의 keepalive/재키 가정 검증, 필요하면 Degraded 임계값을 설정값으로 승격.

## 8. 이 단계가 남긴 판단과 대가

- **`wgmesh-testkit` crate 추가.** 청사진의 crate 목록에 없던 crate다. 대안은 fake를 `wgmesh-app`의 공개 모듈로 두는 것이었지만, 그러면 테스트 전용 코드가 제품 crate에 실린다. 의존 표에 한 줄을 더하는 쪽이 더 싸다고 판단했다.
- **`Event::Handshake`의 의미 변경.** §2.2. 순수 코어의 동작을 바꾸는 변경이라 리뷰에서 반드시 봐야 한다. 근거는 "릴레이 핸드셰이크는 직접 경로의 증거가 아니다"이고, 그 근거가 틀렸다면 §6.2의 5번에서 드러난다.
- **`upnp = true`일 때 게이트웨이 실패는 라운드 실패다.** 지금은 조용히 넘어가지 않고 에러로 올린다. 실기에서 "UPnP가 없는 네트워크에서 켜 두면 어떻게 되어야 하는가"를 정해야 한다(현재 기본값이 `false`인 이유이기도 하다).
