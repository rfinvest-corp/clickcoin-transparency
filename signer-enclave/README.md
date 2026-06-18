# signer enclave — 재현 빌드 & 검증

ClickCoin의 서명 enclave **소스 전체**와 **재현 빌드 키트**입니다. 누구나 이 소스를 빌드해
산출 PCR0가 공시값(`BUILD.lock`의 `expected_pcr0` / 상위 `../PCR0.txt`)과 **byte-match**하는지
직접 확인할 수 있습니다 — "운영 enclave = 공시된 코드"의 trustless 검증.

## 이 디렉토리가 곧 TCB

여기 있는 것(`enclave/` + 그것이 import하는 `signer/ envelope/ cms/ proto/ vtransport/`)이
**PCR0로 측정되는 전부**입니다. 부모 Signing Service·플랫폼·부하 테스터는 enclave 밖이라(측정 무관)
포함하지 않습니다.

## PCR0가 보장하는 것

- AWS KMS 키 정책이 **이 PCR0를 가진 enclave에만** 사용자 API Key 복호화를 허용합니다.
- 따라서 PCR0가 공시값과 같으면, 운영 중인 enclave가 바로 이 공개 소스임을 의미합니다.

## 검증 방법

**환경**: AWS Nitro Enclaves 지원 arm64 인스턴스(예: `c7g.large`) + Amazon Linux 2023.
(`nitro-cli build-enclave`는 enclave 실행이 아니라 빌드라 Nitro 활성 인스턴스가 아니어도 됩니다 —
nitro-cli 설치된 arm64 Linux면 충분합니다.)

```bash
# 1) 호스트 셋업 — BUILD.lock의 nitro_cli_pkg 버전으로 핀 설치
NITRO_VER=<BUILD.lock의 nitro_cli_pkg 버전> bash setup-host.sh
#    (재로그인으로 docker 그룹 반영 후 이 디렉토리로 복귀)

# 2) 재현 빌드 + 공시값 대조
make verify-pcr0
#    → "✅ MATCH — 재현 빌드 PCR0 == 공시값" 이면 검증 성공
```

`verify-pcr0`는 내부적으로 `reproduce.sh`(docker-container 드라이버 + 고정 `SOURCE_DATE_EPOCH` +
`rewrite-timestamp` → `nitro-cli build-enclave`)로 EIF를 만들고, 산출 PCR0를 `BUILD.lock`의
`expected_pcr0`와 비교합니다.

## 재현성 핀 (`BUILD.lock`)

빌드를 byte-단위로 고정하는 값들:
- `golang_base` — Go base 이미지 **digest**(arm64)
- `nitro_cli_pkg` / `kernel_blobs_sha256` — nitro-cli 버전 + 커널·init blobs 해시 (PCR0 최대 변수)
- `buildkit_image` — BuildKit 컨테이너 digest
- `source_date_epoch` — 고정 타임스탬프 (git/HEAD 무관 → 어디서 빌드해도 동일 PCR0)
- `go_build_flags` / `go_env` — 결정론 Go 빌드 플래그
- `expected_pcr0` — 위 핀으로 빌드 시 나와야 하는 PCR0

이 핀이 하나라도 다르면 PCR0가 달라집니다. 검증은 핀을 그대로 따랐을 때 공시 PCR0가 재현됨을 확인하는 것입니다.

## 라이선스 / 범위

이 저장소는 **투명성(검증) 목적**의 enclave 소스 공개입니다. 운영 인프라·시크릿·부모 서비스 코드는 포함하지 않습니다.
