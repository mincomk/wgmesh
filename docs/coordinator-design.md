---
title: wgmesh — NAT-traversing P2P WireGuard Coordinator Design
---

# wgmesh — NAT 홀펀칭 p2p WireGuard 설계

**v3 — 릴레이를 분리한 구조 + 릴레이의 송신자/목적지 식별 규칙 명시.**

대상: Linux 전용 노드. 코디네이터(제어 평면)는 VPS 1대에 셀프호스팅, 릴레이(데이터 평면)는 별도 프로세스·별도 호스트로 원하는 만큼.
요구: 설정파일 또는 `join` 명령 한 줄로 참가, 서버급으로 단순하면서 안정적인 인증.

---

## 0. 먼저 답부터

**"홀펀칭을 유저스페이스에서 직접 구현해야 하나요?" → 아니요.**

세 가지가 따로 있습니다.

| 계층 | 누가 하나 | 유저스페이스 필요? |
|---|---|---|
| 실제 구멍 뚫기 (NAT 매핑·필터 열기) | **커널 WireGuard 자신**. 자기 UDP 소켓으로 핸드셰이크를 쏘는 순간 NAT가 열린다 | 아니요. 구현 대상이 아니라 UDP의 성질 |
| 상대의 외부 주소:포트 알아내기 | **릴레이 서버**가 자기 슬롯에서 관찰해 코디네이터에 보고 | 아니요 — 릴레이가 대신 관찰해준다 |
| 양쪽에 동시에 "지금 쏴라" 지시 | 에이전트 (제어 평면) | 아니요 |

유저스페이스 `wireguard-go` + 커스텀 `conn.Bind`가 **필요해지는** 경우는 세 가지뿐입니다: (1) Linux가 아닌 OS 지원, (2) STUN/디스커버리 패킷을 WireGuard와 **완전히 같은 소켓**으로 보내야 할 때(Tailscale magicsock 방식), (3) 디스커버리 프로토콜을 같은 포트에 멀티플렉싱할 때. Linux 전용이라면 셋 다 해당 없음 — 커널 모듈을 그대로 쓰고, 제어 평면만 쓰면 됩니다.

근거는 `wg(8)` 원문입니다:

> "This endpoint will be updated automatically to the most recent source IP address and port of **correctly authenticated** packets from the peer."

**루밍(roaming)은 커널이 이미 합니다.** 양쪽이 상대의 외부 주소로 유효한 핸드셰이크를 한 번이라도 주고받으면 엔드포인트는 커널이 고정합니다. 우리가 만들 것은 그 "한 번"이 일어나게 만드는 장치뿐입니다.

**v2의 변화:** 코디네이터는 **UDP 소켓을 하나도 열지 않습니다.** 폴백 트래픽은 완전히 분리된 릴레이 서버가 나릅니다.

---

## 1. 용어와 전제

RFC 4787 기준 NAT 분류:

- **endpoint-independent mapping / filtering** (= cone NAT): 내부 (ip,port)마다 외부 포트를 하나만 쓰고, 나가는 상대와 무관하게 들어오는 패킷을 허용. **홀펀칭이 잘 됨.**
- **endpoint-independent mapping + address/port-dependent filtering** (= restricted cone): 외부 포트는 하나지만, 내가 먼저 보낸 적 있는 상대에게서만 들어옴. **양쪽이 동시에 쏘면 됨 (= 고전적 홀펀칭).**
- **endpoint-dependent mapping** (= symmetric NAT): **목적지마다 다른 외부 포트를 배정.** 관찰된 포트가 상대에게는 쓸모없음 → **직접 경로 실패, 릴레이 폴백 필수.** CGNAT·모바일 회선에서 흔함.

전제: 노드는 Linux + 커널 WireGuard. IPv4.

---

## 2. 아키텍처 — 3개 컴포넌트

```diagram
direction: right

admin: "관리자" {shape: person}

coord: "코디네이터 (제어 평면 전용)" {
  api: "HTTPS API + SQLite\nUDP 소켓 0개"
}

relays: "릴레이 패브릭 (데이터 평면, 별도 호스트)" {
  r1: "relay-1 — 무상태 UDP 포워더"
  r2: "relay-2 — 무상태 UDP 포워더"
}

nodeA: "노드 A" {
  agentA: "wgmesh-agent"
  wgA: "커널 WireGuard wg0"
  natA: "NAT"
  agentA -> wgA
  wgA -> natA
}

nodeB: "노드 B" {
  agentB: "wgmesh-agent"
  wgB: "커널 WireGuard wg0"
  natB: "NAT"
  agentB -> wgB
  wgB -> natB
}

admin -> coord.api: "네트워크 · 조인 토큰 · 릴레이 등록"
natA -> coord.api: "설정 동기화 (HTTPS)"
natB -> coord.api: "설정 동기화 (HTTPS)"
natA -> relays.r1: "슬롯 UDP — 여기서 매핑이 관찰됨"
natB -> relays.r1: "슬롯 UDP — 여기서 매핑이 관찰됨"
relays.r1 -> coord.api: "관찰 주소 · 하트비트 보고 (제어 경로)"
natA <-> natB: "홀펀칭 후 직접 경로 (커널끼리)"
```

| 컴포넌트 | 하는 일 | 상태 | 없으면 |
|---|---|---|---|
| **코디네이터** | 조인, 설정 배포, 후보 계산, 릴레이 배정, 감사 | SQLite 1개 | 신규 조인·변경 불가. **기존 직접 경로는 유지** |
| **릴레이** | 암호문 UDP 전달 + 출발지 관찰 + 하트비트 | 없음(설정 캐시만) | 그 릴레이에 붙은 쌍만 끊김 → 재배정 |
| **에이전트** | 키 생성, 커널 설정, 엔드포인트 상태기계 | 로컬 설정 | 그 노드만 |

**핵심 성질:** 직접 경로가 한 번 잡히면 엔드포인트는 커널에 들어가 있으므로 **코디네이터도 릴레이도 죽어도 연결이 유지**됩니다. 릴레이 분리의 가장 큰 이유입니다.

---

## 3. 홀펀칭 메커니즘

### 3.1 왜 릴레이가 먼저 필요한가 (이 설계의 트릭)

직접 뚫으려면 각 노드가 "내 WireGuard **소켓**의 외부 주소:포트"를 알아야 합니다. 그런데 커널 WireGuard는 자기 UDP 소켓을 커널이 소유하므로 사용자 공간에서 그 소켓으로 STUN 패킷을 보낼 수 없고, 별도 소켓으로 STUN을 하면 **다른 매핑**이 나옵니다(매핑은 소켓 단위).

해결: **릴레이가 진짜 WireGuard 패킷을 받아보고 그 출발지 주소를 읽습니다.**

```
phase 1  A, B 모두 peer endpoint = 자기 릴레이 슬롯  (릴레이 경로)
         → 실제 WG 핸드셰이크가 릴레이를 통과해 즉시 연결됨
         → 릴레이가 관찰한 주소를 코디네이터에 보고: A@(ipA,pA)  B@(ipB,pB)
            ← 이것이 WG 소켓의 진짜 매핑
phase 2  양쪽에 서로의 관찰 주소를 밀어넣고 "지금 동시에 쏴라" 지시
         → A→B, B→A 동시 발사 → 양쪽 NAT에 필터가 열림
         → 커널이 핸드셰이크 완료 → 이후 직접 경로
phase 3  N초 내 핸드셰이크 없으면 endpoint를 릴레이 슬롯으로 되돌림 (폴백)
```

릴레이가 **경로이자 관측 장치**입니다. 대칭 NAT여도 릴레이 경로만큼은 항상 동작합니다(관찰된 매핑으로 되돌아오는 패킷은 같은 목적지·같은 포트라서 필터를 통과).

### 3.2 후보 우선순위

| 순위 | 후보 | 비고 |
|---|---|---|
| 1 | 같은 LAN의 사설 주소 | NAT 헤어핀 우회 |
| 2 | IPv6 글로벌 주소 | NAT 없음 → 거의 항상 직접 성공 |
| 3 | 릴레이가 관찰한 외부 주소 | **주 경로** |
| 4 | NAT-PMP / UPnP로 받은 외부 포트 | 공유기가 협조적이면 정확한 포트 |
| 5 | 릴레이 (폴백) | 항상 동작 |

### 3.3 타이밍과 keepalive

- **persistent-keepalive = 25** 를 모든 피어에. `wg(8)`: "send an authenticated empty packet to a peer at a specified interval ... to keep a stateful firewall or NAT mapping valid persistently", 권장값 25초. 매핑을 살려두고, 동시 발사 타이밍도 자연히 맞추며, **직접 경로의 생존 감지기** 역할도 겸합니다.
- 실패한 직선 시도는 커널이 재시도합니다. `wireguard-go/device/constants.go` 기준: `RekeyTimeout = 5s` (+ 최대 334ms 지터), `RekeyAttemptTime = 90s`, `KeepaliveTimeout = 10s`, `RekeyAfterTime = 120s`, `RejectAfterTime = 180s`.
- 성공 판정은 `wg show <if> dump`의 마지막 핸드셰이크와 엔드포인트로. 필드 순서(man page 원문): `public-key, preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx, persistent-keepalive`.

### 3.4 대칭 NAT일 때

관찰된 포트 ≠ 상대에게 쓸 포트이므로 직접 경로는 실패합니다. 선택지: **폴백(권장)** — 릴레이 경로 유지, 추가 구현 없음. 포트 예측(birthday attack)은 구현 비용 대비 이득이 작고 트래픽이 튐 → 이후 단계.

---

## 4. 릴레이 패브릭 — 분리된 데이터 평면

### 4.1 왜 분리하는가

- **규모 특성이 다르다.** 코디네이터는 요청 수가 적고 상태가 중요합니다. 릴레이는 대역폭을 먹고 상태가 없습니다. 같이 두면 릴레이 트래픽 폭주가 조인 API를 죽입니다.
- **늘리고 버리기 쉽다.** 릴레이는 DB도 시크릿도 없으므로 지역·사업자별로 띄우고, 장애 시 버리고 다시 띄우면 됩니다.
- **장애 격리.** 릴레이 1대가 죽으면 그 릴레이에 배정된 쌍만 영향을 받고, 코디네이터가 다른 릴레이로 재배정합니다.
- **코디네이터 앞단에 CDN/WAF를 둘 수 있다.** 순수 HTTPS가 되기 때문입니다.
- **탈취 가치 하락.** 릴레이에는 프라이빗 키도, DB도, 네트워크 공개키 집합 말고는 아무것도 없습니다.

### 4.2 릴레이의 정체성과 등록

릴레이도 노드와 **같은 인증 스킴**을 씁니다 (§5).

```console
$ sudo wgmesh-relay enroll --coordinator https://coord.example.com \
      --token WGMESH-RELAY-4T7B-... --region ap-northeast-2 --provider vultr
  ✔ Ed25519 키 생성  /var/lib/wgmesh/relay.key 0600
  ✔ 코디네이터 SPKI 핀 기록
  ✔ 등록 완료 — 릴레이 id relay_9f2c, 서비스 네트워크: [prod]
```

- 릴레이 키쌍은 **Ed25519 (API 신원)** 하나. 트래픽용 키는 없습니다 — 릴레이는 복호화하지 않으므로 가질 필요가 없습니다.
- 부여받는 것: 서비스할 **네트워크 목록**과 그 네트워크의 **공개키 집합(keyset)**, 그리고 자기 **슬롯 배정표**.
- 줄 수 있는 것: 관찰 주소, 하트비트, 트래픽 카운터. **설정을 바꾸는 권한은 없습니다** (읽기 + 보고 전용).
- 릴레이는 코디네이터의 TLS를 **핀**합니다 (노드와 동일한 방어).

### 4.3 슬롯 배정 — 포트는 누가 정하는가

**코디네이터가 정합니다.** `(릴레이, 디바이스) → UDP 포트` 를 코디네이터가 배정해 노드 config에 넣고, 릴레이에는 배정표를 내려줍니다. 릴레이가 "제 포트는 51820입니다"라고 자기보고하는 구조는 포트 탈취와 충돌을 만듭니다.

```
릴레이 슬롯 예 (한 릴레이가 4개 디바이스를 서비스):
  A → 51901     B → 51902     C → 51903     D → 51904
```

- 노드는 **풀의 모든 릴레이에 자기 슬롯을 열어둡니다** (25초 keepalive). 그래야 어느 릴레이로 배정이 바뀌어도 즉시 동작합니다.
- 릴레이는 `GET /v1/relay/assignment` 로 슬롯 테이블을 받아 로컬에 구성합니다.
- 릴레이가 재시작해도 무상태 — assignment를 다시 받으면 복구됩니다.

### 4.4 릴레이는 무엇을 알아야 하나

정확히 세 가지뿐입니다.

1. **네트워크 공개키 집합(keyset)** — mac1 검증으로 목적지를 알아내기 위해 (§4.5). 공개키이므로 유출돼도 안전합니다.
2. **슬롯 포트 테이블** — 어느 포트가 어느 디바이스인지, 그리고 어느 디바이스가 어느 쌍의 상대인지.
3. 그 외 없음. **DB 없음. 판단 없음.**

### 4.5 목적지 식별 — mac1로 한 포트에 N개 쌍을 라우팅

WireGuard 프로토콜 원문:

```
msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
LABEL_MAC1 = "mac1----"
```

`mac1`의 MAC 키는 **받는 쪽의 공개키**로만 결정됩니다. 코디네이터가 모든 공개키를 알려주므로, 릴레이는 핸드셰이크 패킷 하나를 받으면 각 피어의 키로 mac1을 검증해 **"이 패킷은 누구에게 가는가"를 알아낼 수 있습니다**(타입 1은 responder, 타입 2는 initiator 기준). 전송 패킷(타입 4)은 `receiver_index` → 세션 → (송신자, 목적지) 쌍으로 라우팅합니다. 핸드셰이크에서 관찰해 테이블에 넣습니다.

결과: **노드당 UDP 소켓 1개로 N² 쌍을 모두 라우팅**할 수 있습니다.

> **주의:** `mac1`은 "보낸 사람이 그 목적지의 공개키를 아는 자"임을 증명할 뿐, 어느 멤버인지는 증명하지 않습니다. **송신자 신원은 다른 곳에서 옵니다 → §4.6.**
>
> **MVP 단순화:** 쌍마다 포트 2개(N²/2 포트)로 시작해도 됩니다. mac1 파싱이 전혀 필요 없고 ≤30 노드에서 무난합니다. 랩은 이 단순한 형태입니다.

### 4.6 송신자 식별 — 릴레이는 누가 보냈는지 어떻게 아는가

**패킷 내용으로는 알 수 없습니다.** WireGuard는 그걸 일부러 숨깁니다.

릴레이가 패킷에서 읽을 수 있는 것은 셋뿐입니다.

| 읽을 수 있는 것 | 위치 | 알려주는 것 |
|---|---|---|
| `message_type` | 첫 1바이트 | 1=핸드셰이크 개시, 2=응답, 3=쿠키 응답, 4=전송 |
| `mac1` | 핸드셰이크 패킷의 마지막 32바이트 중 앞 16 | **받는 쪽**의 공개키 (§4.5) |
| `receiver_index` | 응답(4B)·전송(4B) | **받는 쪽**이 고른 세션 인덱스 |

핸드셰이크 개시(v1, 148바이트)의 레이아웃:

```
type(1) | reserved(3) | sender_index(4) | unencrypted_ephemeral(32)
        | encrypted_static(48) | encrypted_timestamp(28) | mac1(16) | mac2(16)
```

여기서 `encrypted_static`이 **송신자의 정적 공개키**입니다. 그런데 프로토콜 원문은 이렇게 정의합니다:

```
msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
```

`key`는 개시자의 임시 키와 **응답자의 정적 공개키**로 유도됩니다(wireguard-go의 `ConsumeMessageInitiation`도 수신자의 정적 **개인**키로 복호화합니다). 즉 **응답자만 풀 수 있고, 릴레이는 못 풉니다** — Noise_IK의 identity hiding이 정확히 이 목적입니다. `sender_index`는 세션마다 무작위로 뽑히는 값이라 디바이스와 무관합니다.

전송 데이터(v1, 헤더 16바이트)는 더 노골적입니다:

```
type(1) | reserved_zero(3) | receiver_index(4) | counter(8) | encrypted_encapsulated_packet[]
```

프로토콜 원문 그대로 — **송신자 필드가 아예 없습니다.** WireGuard에서 "누가 보냈나"는 패킷이 아니라 **복호화 성공 여부**로 판정됩니다(수신자가 자기 키로 풀어 나온 정적 공개키가 그 피어). 그래서 중간 장비는 원리적으로 알 수 없습니다.

**그래서 릴레이는 패킷 밖의 정보를 씁니다: 어느 슬롯 포트로 들어왔는가.**

슬롯 포트는 코디네이터가 **그 디바이스 하나에게만** 발급한 핸들입니다. 노드는 자기 슬롯으로만 패킷을 보내므로, 릴레이에게는 "이 포트로 들어왔다 = 이 디바이스가 보냈다"가 성립합니다. **출발지 IP:포트가 아니라 입구 포트가 신원입니다.**

| 방식 | 송신자 식별 | 목적지 식별 | 패킷 파싱 |
|---|---|---|---|
| **MVP: 쌍마다 포트 2개** | 입구 포트 | 입구 포트 (= 그 쌍의 반대편) | **전혀 없음** |
| **확장: 노드당 포트 1개** | 입구 포트 | `mac1` / `receiver_index` | 핸드셰이크 헤더만 |

확장 방식에서 릴레이는 관찰한 핸드셰이크의 `sender_index`(그리고 응답의 `receiver_index`)를 그 디바이스에 귀속시켜 **세션 인덱스 → 디바이스** 표를 만듭니다(재키잉 주기 ≈2분마다 자연 갱신, `RejectAfterTime = 180s`). 이 표는 인덱스와 디바이스 id만 담고 **키나 평문은 담지 않습니다**. MVP 방식은 이 표조차 필요 없습니다 — 입구 포트가 목적지까지 알려주므로 릴레이는 패킷을 전혀 해석하지 않습니다.

**이 신원이 갖는 보안 성질 (정직하게):**

- 16비트 포트는 추측 가능합니다. 슬롯 번호를 아는 자는 그 슬롯으로 패킷을 넣을 수 있고, 릴레이는 그것을 그 디바이스가 보낸 것으로 취급합니다.
- 그러나 그 위조 패킷은 **WireGuard 암호를 통과하지 못합니다.** 공격자는 정적 키 없이 유효한 핸드셰이크를 만들 수 없으므로 피해자는 인증 실패한 패킷을 받고 버립니다. **읽기도, 유효한 스푸핑도 불가능합니다.**
- 잔여 위험은 **DoS와 대역폭 소모**뿐입니다 (1:1 전달이라 증폭은 없음).
- 완화책: (a) 슬롯 포트를 넓은 범위에서 무작위 배정하고 유휴 시 회수, (b) 첫 패킷을 본 출발지 주소를 **TOFU로 고정**하고 이후 변경 거부, (c) **코디네이터가 배정한 쌍에 대해서만 전달** — `(X,Y)` 배정이 이 릴레이에 없으면 드롭, (d) 슬롯당 PPS·바이트 레이트리밋, (e) 크기·타입 형태 검사(개시 148 / 응답 92 / 쿠키 64 / 전송 ≥32, 그 외 드롭).
- 감사 계층(선택): 핸드셰이크가 성립하면 **수신자는 송신자가 누구인지 알게 됩니다**(정적 공개키를 복호화하므로). 노드가 "X와 핸드셰이크했다"를 코디네이터에 보고하면 릴레이의 주장과 대조할 수 있습니다 — 사후 감사용이지 실시간 방어는 아닙니다.

**정리:** 릴레이는 **목적지는 패킷에서**(mac1 / receiver_index), **송신자는 입구 포트에서** 압니다. 두 축의 출처가 다르다는 것이 이 설계의 핵심입니다.

### 4.7 관찰 보고 — 데이터 경로 밖으로

릴레이는 자기 슬롯에서 본 출발지 주소를 **주기적으로(예: 2초 배치) 코디네이터에 HTTPS로 보고**합니다. 관찰값은 데이터 경로가 아니라 제어 경로로 흐릅니다. 코디네이터가 이 값으로 punch 후보를 만듭니다.

**규칙: 관찰한 릴레이 = 그 쌍이 실제로 쓸 릴레이여야 합니다.** 다른 릴레이에서 관찰한 값을 후보로 쓰면 대칭 NAT에서 어긋납니다. cone/restricted는 매핑이 endpoint-independent라 아무 릴레이에서 관찰해도 같은 포트가 나오지만, 규칙을 하나로 통일하는 편이 안전합니다. (랩에서 assert로 강제합니다.)

### 4.8 쌍 배정과 릴레이 선택

- **쌍마다 릴레이 하나**를 정해 **양쪽 config에 같은 릴레이**를 넣습니다. 한쪽만 바꾸면 동작하지 않습니다.
- 선택 기준: (a) 두 노드가 공통으로 도달 가능한 릴레이 중 양쪽 RTT 합 최소, (b) 지역·사업자 다양성, (c) **sticky** — 한 번 성공한 배정은 유지합니다. 재배정은 곧 끊김이므로 필요할 때만.
- 같은 지역에 여러 대가 있으면 플로우 해싱으로 부하 분산.

### 4.9 헬스와 페일오버

- 릴레이 → 코디네이터 하트비트 (예: 5초, 트래픽 카운터 포함).
- 3회 연속 누락 → unhealthy → 그 릴레이에 배정된 쌍을 다른 릴레이로 **재배정** → config 푸시(SSE) → 양쪽이 새 릴레이로 re-punch.
- **랩 실측: 재배정 → 세션 회복까지 0.3초.** (§11)

### 4.10 직접 시도의 비용 — 반드시 지켜야 할 규칙

WireGuard 피어는 **엔드포인트가 하나뿐**입니다. 직접 후보로 바꾸는 순간 릴레이 경로가 끊깁니다. 따라서:

> **직접 시도 창(window)은 릴레이 NAT 매핑 수명보다 짧아야 한다.**

NAT의 UDP 매핑 수명은 보통 수십 초 이상이므로, 5초 정도의 짧은 창이면 실패해도 릴레이 매핑이 살아 있어 즉시 복귀합니다. (RFC 4787 §4.3 "Mapping Refresh"가 매핑 유지 시간을 다룹니다.)

랩에서 이것을 그대로 봤습니다: 직접 시도 4초 → 실패 → 릴레이 복귀 **0.3초**. 시도 중에는 잠깐 끊깁니다. 대칭 NAT 노드에서는 이 짧은 끊김이 주기적으로 반복될 수 있으므로 **재시도 간격을 지수 백오프**로 늘리십시오(예: 30초 → 2분 → 10분).

피어를 둘로 잡아 같은 AllowedIPs를 공유할 수는 없으므로(중복 금지), "검증 후 전환"은 WireGuard 구조상 불가능합니다. 짧은 창 + 즉시 복귀가 정답입니다.

### 4.11 릴레이가 코디네이터와 단절되면

- 보유한 keyset을 **TTL(예: 5분)까지** 사용하고, 이후에는 **신규 전달을 중단**합니다.
- 이유: 오래된 keyset으로 폐기된 디바이스를 계속 서비스하지 않기 위해서입니다.
- 이미 성립한 세션은 정책 선택 — 서비스 지속이 운영상 낫습니다. 다만 TTL을 넘기면 새 전달은 거부합니다.

### 4.12 릴레이 보안과 남용 방지

- **암호문만 취급.** 트래픽 내용은 못 봅니다. 하지만 **메타데이터(누가 누구와, 얼마나)**는 봅니다 — 이것이 릴레이 신뢰 모델의 핵심입니다.
- **1:1 포워딩만.** 받은 것보다 큰 패킷을 만들지 않으므로 **증폭(reflection) 공격에 쓰일 수 없습니다.** 목적지도 등록된 슬롯으로만 한정됩니다.
- 슬롯당 PPS/바이트 레이트리밋, WireGuard 형태 검사(§4.6의 크기 표), 출발지 주소 TOFU, 배정된 쌍만 전달.
- keyset에 없는 목적지 태그는 드롭 (랩에서 `rejected` 카운터로 확인).
- **운영자 소유 릴레이 vs 제3자/자원봉사 릴레이:** 후자는 메타데이터를 남에게 넘기는 일이므로 **네트워크 단위 옵트인**이어야 하고, 사용자가 `relay_pool = ["my-relay-only"]`로 제한할 수 있어야 합니다. 이 경우 릴레이가 확인한 네트워크 keyset이 곧 격리 경계입니다.

### 4.13 릴레이가 필요 없는 경우

관찰할 곳이 하나도 없으면 punch할 수 없으므로 **최소 1대는 필요**합니다. 대안 관찰 수단으로 NAT-PMP/UPnP(공유기가 협조적일 때)나 `wgmesh doctor`로 직접 관찰을 대체할 수 있습니다. 두 노드가 IPv6로 만날 수 있으면 릴레이 없이도 됩니다.

---

## 5. 인증·신원 설계

### 5.1 위협 모델

| 위협 | 방어 |
|---|---|
| 인터넷의 임의 접속 | 조인 토큰 없이는 아무것도 못 함 |
| 조인 토큰 유출 | 1회용 + 만료 + 관리자 승인 대기 |
| 폐기된 멤버 | 다음 설정 동기화에서 피어 목록에서 제거 |
| 네트워크 MITM (코디네이터 위장) | TLS SPKI 핀 |
| 코디네이터 DB 유출 | 공개키·해시만 저장. 트래픽·프라이빗 키는 없음 |
| 악성/탈취된 릴레이 | 암호문은 못 읽음. 관찰값 위조는 DoS 수준. keyset으로 네트워크 격리 |
| 릴레이 슬롯 탈취 | mac1 검증 + 출발지 TOFU + 슬롯당 레이트리밋 (§4.6) |
| **방어하지 않음** | 이미 신뢰된 노드가 네트워크 내부에서 하는 짓 (피어별 AllowedIPs·방화벽으로 완화) |

### 5.2 신원 4단

```
관리자 ─(부트스트랩 토큰 → argon2id 비밀번호 → 선택적 OIDC)
   └── 네트워크(테넌트): WG 서브넷, MTU, DNS, 릴레이 풀, 등록 정책
          ├── 조인 토큰: 1회용, 만료, 승인 방식
          │      ├── 디바이스: X25519 터널 키 + Ed25519 API 키
          │      └── 릴레이:   Ed25519 API 키 하나 (터널 키 없음 — 복호화 안 하므로)
          └── (둘 다 같은 서명 스킴으로 API를 호출)
```

### 5.3 조인 토큰

- 160비트 랜덤 → Crockford Base32: `WGMESH-7K3M-9QXA-...`
- **서버에는 SHA-256 해시만 저장.** DB가 통째로 유출돼도 토큰을 복원할 수 없습니다.
- 필드: `network_id, kind(device|relay), created_by, expires_at, max_uses, uses, auto_approve, tags, revoked_at`
- 소비는 **단일 SQL 문**으로 원자적으로:
  ```sql
  UPDATE join_tokens SET uses = uses + 1
   WHERE token_hash = ?1 AND revoked_at IS NULL
     AND expires_at > ?2 AND uses < max_uses
   RETURNING network_id, kind, auto_approve;
  ```
  (SQLite 3.35+ `RETURNING`.) 경쟁 조건 없음.
- 실패 응답은 "없음"과 "만료됨"을 구분하지 않습니다.

### 5.4 디바이스 키가 두 개인 이유

| 키 | 알고리즘 | 용도 | 위치 |
|---|---|---|---|
| `wg.key` | X25519 | WireGuard 터널 | 노드 전용, 0600, **전송 안 함** |
| `dev.key` | Ed25519 | 코디네이터 API 인증 | 노드 전용, 0600 |

X25519 키로는 서명을 못 하므로 API 인증용 키를 따로 둡니다. 둘 다 노드에서 생성하고 **공개키만** 전송합니다. 릴레이는 API 키 하나면 충분합니다.

### 5.5 API 인증 — 베어러 토큰 대신 서명 (노드·릴레이 공통)

```
Authorization: WGMESH <id> <unix_ts> <nonce_b64> <sig_b64>

sig = Ed25519(priv,
        "WGMESHv1\n" + method + "\n" + path + "\n" +
        sha256_hex(body) + "\n" + ts + "\n" + nonce)
```

서버 검증: ① 신원 조회 → ② 상태가 `active` → ③ `|now - ts| ≤ 60s` → ④ 논스 미사용(120초 캐시) → ⑤ 서명 검증.

**서버에 저장되는 공유 비밀이 하나도 없습니다.** 디스크에 남는 비밀은 프라이빗 키 파일뿐이고, 그마저 TLS 위로 전송되지 않습니다.

> 최소 구현으로 가려면: 조인 시 256비트 토큰을 발급하고 해시만 저장하는 베어러 방식도 충분합니다. 다만 나중에 서명 방식으로 올릴 것을 전제로 `dev.key`를 처음부터 생성해 두십시오 — 마이그레이션이 훨씬 싸집니다.

### 5.6 코디네이터 신원 (반대 방향)

조인 시 CLI가 코디네이터의 **TLS SPKI SHA-256을 설정파일에 기록**하고, 이후 모든 요청에서 검증합니다. 이게 없으면 MITM이 피어 목록에 자기 공개키를 끼워 넣을 수 있습니다. 릴레이도 동일하게 핀합니다.

```toml
coordinator = "https://wgmesh.example.com"
coordinator_spki_sha256 = "9f2c...e1"   # enroll 시 자동 기록
```

인증서 갱신 시 핀도 갱신해야 합니다 → 장기 키를 쓰거나 `wgmesh trust --rotate` 절차를 두십시오.

**강화(선택):** 코디네이터가 설정 스냅샷을 Ed25519 네트워크 키로 서명하고 노드가 검증. TLS가 CDN/로드밸런서에서 종단될 때 필요합니다.

### 5.7 승인 · 폐기 · 로테이션

- 상태: `pending → active → revoked` (디바이스·릴레이 동일).
- `auto_approve=false`로 들어온 디바이스는 `pending`이고 **피어 목록에 들어가지 않습니다.** 토큰이 유출돼도 즉시 피해가 없습니다 — 서버용으로 가장 값싼 안전장치입니다.
- 폐기: 다음 동기화에서 모든 피어 목록·keyset에서 사라짐. 커널에서 피어 엔트리가 제거되는 순간 그 피어의 패킷은 전부 드롭됩니다(WireGuard 자체엔 세션 취소가 없으므로 **목록이 곧 ACL**). 폴링 30초면 최대 30초 지연, SSE 푸시면 수 초.
- 릴레이 폐기: `retired` → 노드 config에서 제거, keyset 갱신.
- 키 로테이션: 본인 서명으로 새 공개키 제출.

### 5.8 "단순하면서 안정적" — 지킬 것 5가지

1. **프라이빗 키는 자기 기계를 떠나지 않는다.** 코디네이터·릴레이는 공개키만 안다.
2. **조인 토큰은 1회용 + 해시 저장 + 승인 대기.**
3. **API는 자기 키로 서명한다** (서버에 저장되는 공유 비밀 0개).
4. **노드도 릴레이도 코디네이터 TLS를 핀한다.**
5. **릴레이는 트래픽을 복호화할 수 없다** — 키를 아예 갖지 않는다.

이 다섯만 지키면 나머지(스키마, 엔드포인트, 관리 UI)는 얼마든지 단순하게 가도 됩니다.

---

## 6. 데이터 모델

```sql
CREATE TABLE networks (
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
  cidr TEXT NOT NULL,              -- 예: 10.77.0.0/16
  mtu INTEGER NOT NULL DEFAULT 1420,
  relay_policy TEXT NOT NULL DEFAULT 'any',   -- any | operator-only
  created_at INTEGER NOT NULL);

CREATE TABLE join_tokens (
  id INTEGER PRIMARY KEY, network_id INTEGER NOT NULL REFERENCES networks(id),
  kind TEXT NOT NULL,                -- device | relay
  token_hash BLOB NOT NULL UNIQUE,
  max_uses INTEGER NOT NULL DEFAULT 1, uses INTEGER NOT NULL DEFAULT 0,
  auto_approve INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL, revoked_at INTEGER,
  created_by TEXT NOT NULL, created_at INTEGER NOT NULL);

CREATE TABLE devices (
  id INTEGER PRIMARY KEY, network_id INTEGER NOT NULL REFERENCES networks(id),
  name TEXT NOT NULL,
  wg_pubkey BLOB NOT NULL,          -- X25519, 32 bytes
  api_pubkey BLOB NOT NULL UNIQUE,  -- Ed25519, 32 bytes
  tunnel_ip TEXT NOT NULL,
  state TEXT NOT NULL,              -- pending | active | revoked
  last_seen_at INTEGER, created_at INTEGER NOT NULL,
  UNIQUE(network_id, tunnel_ip), UNIQUE(network_id, wg_pubkey));

-- 릴레이 패브릭
CREATE TABLE relays (
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
  api_pubkey BLOB NOT NULL UNIQUE,  -- 릴레이 자신의 Ed25519 신원
  state TEXT NOT NULL,              -- pending | active | retired
  endpoint_host TEXT NOT NULL,      -- 공인 IP/호스트 (노드가 여기로 UDP를 쏜다)
  port_range TEXT NOT NULL,         -- 배정 가능한 UDP 포트 범위
  region TEXT, provider TEXT, operator TEXT,
  last_heartbeat_at INTEGER, agent_version TEXT,
  created_at INTEGER NOT NULL);

CREATE TABLE relay_networks (       -- 이 릴레이가 서비스해도 되는 네트워크
  relay_id INTEGER NOT NULL REFERENCES relays(id),
  network_id INTEGER NOT NULL REFERENCES networks(id),
  PRIMARY KEY (relay_id, network_id));

CREATE TABLE relay_slots (          -- (릴레이, 디바이스)마다 UDP 포트 하나 = 송신자 신원
  relay_id INTEGER NOT NULL REFERENCES relays(id),
  device_id INTEGER NOT NULL REFERENCES devices(id),
  udp_port INTEGER NOT NULL,
  PRIMARY KEY (relay_id, device_id),
  UNIQUE (relay_id, udp_port));

CREATE TABLE pair_assignments (     -- 쌍마다 어느 릴레이를 쓸지 (sticky)
  device_a INTEGER NOT NULL REFERENCES devices(id),
  device_b INTEGER NOT NULL REFERENCES devices(id),
  relay_id INTEGER NOT NULL REFERENCES relays(id),
  assigned_at INTEGER NOT NULL,
  PRIMARY KEY (device_a, device_b));

CREATE TABLE relay_observations (   -- 릴레이가 보고한 출발지 주소
  relay_id INTEGER NOT NULL REFERENCES relays(id),
  device_id INTEGER NOT NULL REFERENCES devices(id),
  ip TEXT NOT NULL, port INTEGER NOT NULL, seen_at INTEGER NOT NULL,
  PRIMARY KEY (relay_id, device_id));

CREATE TABLE relay_traffic (        -- 복호화 없이 바이트만 (비용 계측)
  relay_id INTEGER NOT NULL, device_id INTEGER NOT NULL,
  rx_bytes INTEGER NOT NULL, tx_bytes INTEGER NOT NULL,
  period_start INTEGER NOT NULL,
  PRIMARY KEY (relay_id, device_id, period_start));

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL,
  network_id INTEGER, device_id INTEGER, relay_id INTEGER, detail TEXT);
```

---

## 7. API

**노드 (에이전트)**

| 메서드 | 경로 | 인증 | 설명 |
|---|---|---|---|
| POST | `/v1/join` | 조인 토큰 | `{token, wg_pubkey, api_pubkey, name, os, agent_version}` → `{device_id, network, peers[], relay_pool[]}` |
| GET | `/v1/config` | 디바이스 서명 | 피어 목록 + 배정된 릴레이 + 슬롯 (30초 폴링 또는 SSE) |
| POST | `/v1/endpoint` | 디바이스 서명 | 자기 관찰값/후보 보고 |
| POST | `/v1/punch` | 디바이스 서명 | 동시 발사 지시 수신·결과 보고 |
| POST | `/v1/rotate` | 디바이스 서명 | 새 `wg_pubkey` 제출 |

**릴레이**

| 메서드 | 경로 | 인증 | 설명 |
|---|---|---|---|
| POST | `/v1/relay/enroll` | 릴레이 조인 토큰 | 등록 → `{relay_id, endpoint_host, port_range}` |
| GET | `/v1/relay/assignment` | 릴레이 서명 | `{slots[], pairs[], networks[{id, peers[{device_id, wg_pubkey}]}]}` — 슬롯 + keyset + 배정된 쌍 |
| POST | `/v1/relay/observations` | 릴레이 서명 | `[{device_id, ip, port, seen_at}]` 배치 보고 |
| POST | `/v1/relay/heartbeat` | 릴레이 서명 | 헬스 + 트래픽 카운터 |
| GET | `/v1/relay/keyset` | 릴레이 서명 | 공개키 증분 갱신 (TTL 캐시 무효화용) |

**관리자**: 네트워크·토큰·승인·폐기·릴레이 등록/폐기·배정 조회. 세션 인증.

`/v1/join`과 `/v1/relay/enroll`만 인터넷에 노출되고 나머지는 서명 필수입니다. 둘 다 IP당 레이트리밋을 거십시오.

---

## 8. 설정과 명령

```toml
# /etc/wgmesh/agent.toml
network     = "prod"
interface   = "wg0"
state_dir   = "/var/lib/wgmesh"
listen_port = 51820        # 0 = 임의
mtu         = 1420
dns         = ["10.77.0.1"]

# enroll 시 자동 기록 — 손으로 쓰지 않는다
coordinator             = "https://wgmesh.example.com"
coordinator_spki_sha256 = "9f2c...e1"
device_id               = "d_7Hq2..."

[traversal]
keepalive_secs    = 25
punch_window_secs = 5       # 릴레이 매핑 수명보다 짧게 (§4.10)
punch_backoff     = [30, 120, 600]   # 대칭 NAT에서 반복 끊김을 줄인다
lan_candidates    = true
upnp              = false

[relay]
pool     = "any"          # any | operator-only | [ "relay-1", "relay-3" ]
per_pair = true           # peer별 릴레이 배정 존중
```

```toml
# /etc/wgmesh/relay.toml
coordinator             = "https://wgmesh.example.com"
coordinator_spki_sha256 = "9f2c...e1"
relay_id                = "relay_9f2c..."
listen                  = "0.0.0.0"
port_range              = [51820, 51999]
keyset_ttl_secs         = 300        # 코디네이터 단절 시 계속 서비스할 시간 (§4.11)
rate_limit_pps_per_slot  = 5000
rate_limit_mbit_per_slot = 100
```

```console
$ sudo wgmesh join https://wgmesh.example.com --token WGMESH-7K3M-9QXA-M2PE-8T4V
  ✔ 키 생성 (X25519 터널 / Ed25519 API)  /var/lib/wgmesh/{wg.key,dev.key} 0600
  ✔ 코디네이터 SPKI 핀 기록  9f2c...e1
  ✔ 조인 완료 — tunnel ip 10.77.0.7, network "prod", 상태 pending
  ✔ 승인 대기 중… (관리자 승인 후 자동 연결)

$ wgmesh status
  interface  wg0    10.77.0.7/16   up
  peer B  10.77.0.8   path=direct   endpoint=203.0.113.9:41287   handshake 4s ago
  peer C  10.77.0.9   path=relay    via=relay-2   endpoint=198.51.100.4:51903   handshake 12s ago
  relay-1  healthy   direct 4/4 pairs   relayed 12.4 MB/min
  relay-2  unhealthy (heartbeat missed x4) — 1 pair re-homed

$ wgmesh relays            # 릴레이 풀과 내 슬롯
$ wgmesh doctor            # NAT 유형 진단 + 매핑/필터 테스트
$ wgmesh trust --rotate    # 코디네이터 인증서 교체 시 핀 갱신
```

서브커맨드: 노드는 `join, leave, status, peers, relays, trust --rotate, reload, doctor`; 릴레이는 `wgmesh-relay enroll, status, drain, keyset`.

---

## 9. 운영

**코디네이터** — systemd 유닛 1개, `443/tcp`만 리스닝. SQLite + WAL, 시간당 스냅샷 백업(공개키만 있으므로 유출이 치명적이지 않음). 앞단에 CDN/WAF 선택 가능. 상시 부하는 요청 수가 적어 미미합니다.

**릴레이** — systemd 유닛 1개, UDP 포트 범위만 리스닝. 무상태이므로 오토스케일·재시작이 자유롭습니다. 대역폭이 곧 비용이므로 슬롯당 상한을 두고 트래픽을 계측하십시오.

- 배치: 2개 이상의 지역/사업자에 두면 한 곳의 장애나 회선 문제에 견딥니다. 노드가 직선 경로를 못 만들 때만 트래픽이 지나가므로 평상시 릴레이 부하는 작습니다.
- **대칭 NAT 노드가 몇 개 있으면 그 트래픽은 계속 릴레이를 탑니다.** 이건 정상이며 예산에 넣어야 합니다.
- `drain`: 유지보수 전 새 배정을 막고 기존 배정을 다른 릴레이로 옮깁니다.
- HA는 처음엔 불필요합니다. **코디네이터가 죽어도 이미 뚫린 직접 경로는 살아 있습니다.**

---

## 10. 실패 모드

| 상황 | 결과 | 대응 |
|---|---|---|
| 코디네이터 다운 | 조인·설정 변경 불가. 기존 직접 경로 유지. 릴레이는 keyset TTL까지 계속 서비스 | 정상 동작으로 간주 |
| 릴레이 1대 다운 | 그 릴레이에 배정된 쌍만 끊김 | 헬스 감지 → 다른 릴레이로 재배정 (실측 0.3초) |
| 릴레이 ↔ 코디네이터 단절 | 신규 전달 중단까지 TTL 유예 | `keyset_ttl_secs`, 이후 새 전달 거부 |
| 대칭 NAT (양쪽) | 직접 경로 실패 | 릴레이 폴백 (자동). 재시도 백오프 |
| CGNAT / 모바일 회선 | 대개 대칭 → 릴레이 | 릴레이 대역폭 예산 |
| NAT 매핑 만료 | 연결 끊김 | persistent-keepalive 25초. 릴레이 경로는 양쪽이 계속 쏘므로 자가치유 |
| 직접 경로가 나중에 깨짐 | 릴레이 경로도 식어 있음 | 에이전트가 핸드셰이크 부재를 감지 → 릴레이 슬롯으로 복귀 → 슬롯 재관찰로 1왕복에 자가치유 |
| 조인 토큰 유출 | 승인 대기면 피해 없음 | 토큰 폐기 |
| 코디네이터 DB 유출 | 공개키·해시만 노출 | 트래픽 안전 |
| 릴레이 탈취 | 암호문은 못 읽음. 메타데이터 노출. 관찰값 위조로 DoS | keyset 격리, `relay_policy = operator-only` |
| 슬롯 번호 추측/위조 주입 | 릴레이가 그 디바이스 명의로 전달하지만 **WG 인증 실패로 드롭** | 레이트리밋, TOFU, 배정된 쌍만 전달 (§4.6) |
| 릴레이가 리플렉터로 악용 | 1:1 포워딩이라 증폭 없음 | 슬롯당 레이트리밋 |
| 인증서 갱신 후 핀 불일치 | 노드/릴레이가 연결 거부 | `trust --rotate` |
| IPv6만 있는 네트워크 | IPv4 후보 무용 | IPv6 후보를 1순위로 |

---

## 11. 랩 검증

권한 없는 환경(`ip`·`wg`·netns 없음, uid 1000)에서 **실제 UDP 소켓으로** 제어 흐름과 상태기계를 검증한 시뮬레이터 두 개.

### 11.1 `wgmesh-nat-lab.py` — 홀펀칭 상태기계

NAT의 매핑·필터 정책과 매핑 만료를 명시적으로 시뮬레이션. 커널 WireGuard 대신 "인증된 패킷의 출발지로 엔드포인트를 갱신한다"는 `wg(8)`의 그 성질만 구현했습니다.

| NAT A | NAT B | 결과 (A→B / B→A) | NAT-A 매핑 수 |
|---|---|---|---|
| cone | cone | direct / direct (0.2초) | 1 |
| restricted | restricted | direct / direct (0.2초) | 1 |
| cone | restricted | direct / direct (0.2초) | 1 |
| restricted | cone | direct / direct (0.2초) | 1 |
| **symmetric** | **symmetric** | **relay / relay (폴백)** | **2** |

### 11.2 `wgmesh-relay-fleet-lab.py` — 릴레이 분리 + 페일오버

릴레이 2대, 코디네이터는 UDP 소켓 0개.

```
시나리오 1: cone + cone, 쌍은 relay-1에 배정
  coordinator UDP sockets: NONE (0)
  pair A<->B assigned to relay-1
  relayed: A path=relay  relay-1 forwarded=4
  observed via relay-1: A@:47626  B@:40709 -> simultaneous send
  direct path: True after 0.2s
  result A->B path=direct  B->A path=direct
  relay-1: forwarded=4  relay-2: forwarded=0     ← 직접 경로 후 릴레이는 놀고 있다

시나리오 2: symmetric + symmetric → 릴레이, punch 실패, 폴백, relay-1 사망
  relayed via relay-1: path=relay
  --- trying the direct punch (expected to fail) ---
  after 4s: path=down      ← 엔드포인트를 옮기면 릴레이 경로가 끊긴다 (§4.10)
  --- agent fallback: endpoint back to the assigned relay ---
  fallback to relay-1: True after 0.3s
  --- killing relay-1 ---
  connectivity now: down
  coordinator health check failed for relay-1 -> re-homing to relay-2
  re-homed to relay-2: recovered=True after 0.3s  path=relay
  relay-2 forwarded delta=2
  NAT mappings created: A=3 B=3
    (relay-1 + relay-2 + 직접 후보 = 3. 세 번째가 바로 대칭 NAT를 뚫을 수 없는 이유)
```

**검증한 것:** (1) 코디네이터가 UDP 소켓을 하나도 갖지 않음(구조적으로 확인), (2) 쌍 배정 → 릴레이 경로 → 배정된 릴레이에서 관찰 → 동시 발사 → 직접 승격, (3) 대칭 NAT에서 폴백, (4) 릴레이 사망 → 재배정 → 0.3초 회복, (5) 릴레이가 배정 밖 디바이스로는 전달하지 않음, (6) **입구 포트가 송신자 신원으로 동작함 — 랩의 릴레이는 자기 슬롯으로 들어온 포트만으로 송신자를 구분하고, 패킷 내용은 목적지 태그 외에 전혀 해석하지 않는다.**

**검증하지 않은 것:** 실제 WireGuard 암·복호화 경로, 커널 UDP 스택, 실제 NAT 하드웨어, IPv6, 그리고 **`mac1`/`receiver_index`로 릴레이가 목적지를 찾는 방식(§4.5)** — 프로토콜 원문의 공식에 근거한 설계이며 아직 실측하지 않았습니다. 랩에서는 그 자리에 2바이트 목적지 태그를 씁니다. 또한 실제 WireGuard는 전송 패킷에 송신자 필드가 없다는 사실(§4.6) 자체는 원문으로 확인했지만, 그것을 전제로 한 라우팅을 실측하지는 않았습니다.

**랩이 드러낸 설계 제약:** 직접 시도가 실패하면 그 사이 릴레이 경로가 끊깁니다(WireGuard 피어는 엔드포인트가 하나뿐). 그래서 §4.10의 "창을 짧게, 즉시 복귀" 규칙이 필요합니다. 이건 시뮬레이터의 인공물이 아니라 WireGuard 구조 자체의 성질입니다.

---

## 12. 구현 순서

| 단계 | 내용 | 예상 |
|---|---|---|
| **M0** | 코디네이터: 토큰·SQLite·`/join`·`/config`·릴레이 등록/배정 / **릴레이 바이너리(별도 프로세스)**: 슬롯, 전달, 관찰 보고 / 에이전트: 키 생성, netlink로 wg 설정, 릴레이 경로, 관찰 → 동시 발사 → 승격 → 폴백 | 며칠 |
| M1 | 승인 대기, 감사 로그, 레이트리밋, SSE 푸시, 헬스·재배정, `wgmesh doctor`, Prometheus 메트릭, `relay drain` | 1주 |
| M2 | 디바이스/릴레이 서명 인증으로 전환, SPKI 핀, IPv6·LAN 후보, UPnP 후보, 재시도 백오프, `trust --rotate` | 1주 |
| M3 | 릴레이당 노드 1포트 + **mac1/`receiver_index` 라우팅**(§4.5), 대칭 NAT 포트 예측, 서명된 스냅샷, 멀티 네트워크·ACL | 이후 |

M0만으로 "릴레이는 되고, 되는 곳은 직접 붙는다"가 성립합니다. M0부터 릴레이를 **별도 바이너리로** 시작하는 것이 중요합니다 — 나중에 떼어내는 것이 훨씬 비쌉니다.

---

## 13. 만들 것인가, 쓸 것인가

- **Tailscale**: 같은 문제를 완성도 높게 풀었고 DERP 릴레이가 이미 분리된 데이터 평면입니다. 통제 평면은 그들의 클라우드. 참고할 최고의 교본.
- **NetBird**: 셀프호스팅 가능한 코디네이터 + 유저스페이스 WireGuard + 릴레이. 요구에 가장 가깝습니다.
- **Nebula**: 자체 프로토콜(Noise) + lighthouse. WireGuard가 아님.
- **Innernet**: 셀프호스팅 WireGuard 관리 도구지만 노드마다 공인 엔드포인트가 필요 — 홀펀칭 없음.

**권장:** NetBird를 한 번 띄워 보십시오. 안 맞는 지점을 알면 최소 구현 범위가 훨씬 선명해집니다. 직접 가야 한다면 이 문서의 M0입니다.

---

## 부록 A. 참고 문헌

- WireGuard 프로토콜 (mac1 공식, 핸드셰이크·전송 메시지 레이아웃, `encrypted_static` 정의): https://www.wireguard.com/protocol/
- wireguard-go (메시지 크기 상수 148/92/64/32, `ConsumeMessageInitiation`의 복호화 경로): https://github.com/WireGuard/wireguard-go/blob/master/device/noise-protocol.go
- `wg(8)` man page (엔드포인트 루밍 문장, `wg show dump` 필드, persistent-keepalive): https://man7.org/linux/man-pages/man8/wg.8.html
- wireguard-go `conn` 패키지 (커스텀 `Bind` 확장점): https://pkg.go.dev/golang.zx2c4.com/wireguard/conn
- wireguard-go 상수 (RekeyTimeout 등): https://github.com/WireGuard/wireguard-go/blob/master/device/constants.go
- RFC 4787 (NAT behavioral requirements; §4.3 Mapping Refresh, §12 Requirements): https://www.rfc-editor.org/rfc/rfc4787
- Tailscale, "How NAT traversal works": https://tailscale.com/blog/how-nat-traversal-works

## 부록 B. 요약 카드

```
컴포넌트        : 코디네이터(제어, UDP 0개) · 릴레이(데이터, 무상태) · 에이전트
노드당 비밀      : wg.key(X25519), dev.key(Ed25519)  — 기계 밖으로 안 나감
릴레이가 가진 것 : Ed25519 신원 키 + 네트워크 공개키셋 + 슬롯표. DB·프라이빗 키 없음
API 인증         : Ed25519 서명 요청 (노드·릴레이 공통, 공유 비밀 0개)
코디네이터 인증  : TLS SPKI 핀 (노드·릴레이 모두)
참가             : 조인 토큰 1회용 → (기본) 관리자 승인
폐기 지연        : 폴링 30초 / SSE 수 초 / keyset TTL 5분
슬롯 배정        : 코디네이터가 정한다 (자기보고 아님)
송신자 식별      : 입구 슬롯 포트  ← 패킷에는 송신자 필드가 없다
목적지 식별      : mac1(핸드셰이크) / receiver_index(전송)  또는 MVP의 입구 포트
직접 경로        : 커널 WireGuard 루밍 + 양쪽 동시 발사
직접 시도 창     : 릴레이 매핑 수명보다 짧게 (≈5초) + 재시도 백오프
릴레이 폴백      : 암호문 1:1 전달. 복호화 불가, 증폭 불가
릴레이 장애      : 헬스 3회 누락 → 재배정 → 회복 실측 0.3초
```
