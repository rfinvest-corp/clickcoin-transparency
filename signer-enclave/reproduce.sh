#!/usr/bin/env bash
# signer enclave 재현 빌드 (T4.8) — 같은 커밋 + 같은 핀(BUILD.lock) → 같은 PCR0.
#
# 실행 환경: AL2023 arm64(c7g) + BUILD.lock과 일치하는 nitro-cli/blobs + docker(buildx).
#   (nitro-cli build-enclave는 Nitro 인스턴스 불필요 — nitro-cli 설치된 arm64 Linux면 됨)
# 결정론 요소:
#   - enclave.Dockerfile: base digest 고정 + 결정론 Go 플래그 + GOARCH=arm64
#   - SOURCE_DATE_EPOCH = 현재 커밋 시각 → config created + 레이어 파일 mtime까지 고정
#   - docker-container 드라이버(최신 BuildKit) + rewrite-timestamp → 레이어 mtime을 SDE로 rewrite
#     (※ dockerd 내장 BuildKit 0.12는 type=docker에 rewrite-timestamp 미적용 — 그래서 컨테이너 드라이버)
#   - nitro-cli/커널 blobs = BUILD.lock 핀 (NITRO_VER)
set -euo pipefail
cd "$(dirname "$0")"

IMAGE_TAG="kcoin-signer-enclave:repro"
EIF_OUT="signer.eif"
DOCKER_TAR="image.docker.tar"
BUILDER="kcoin-repro"

# SDE = BUILD.lock 고정 상수. git 히스토리/HEAD/repo와 무관 → transparency repo 등 어디서 빌드해도
# 동일 PCR0 (ledger 커밋도, 다른 repo도 안 흔들림). 빌드 입력 변경 시에만 BUILD.lock에서 값 갱신.
SOURCE_DATE_EPOCH="$(grep -E '^source_date_epoch' BUILD.lock | grep -oE '[0-9]{6,}' | head -1)"
[ -n "$SOURCE_DATE_EPOCH" ] || { echo "✗ BUILD.lock에 source_date_epoch 없음"; exit 1; }
export SOURCE_DATE_EPOCH
echo "== 재현 빌드: HEAD $(git rev-parse --short HEAD 2>/dev/null || echo n/a), SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH (BUILD.lock 고정) =="

# 0) docker-container 빌더 (최신 BuildKit — type=docker rewrite-timestamp 지원)
#    TODO(BUILD.lock): moby/buildkit 이미지를 digest로 핀(--driver-opt image=moby/buildkit@sha256:…)해 장기 재현성 확보
docker buildx inspect "$BUILDER" >/dev/null 2>&1 || \
  docker buildx create --name "$BUILDER" --driver docker-container >/dev/null
echo "-- BuildKit 버전 --"
docker buildx inspect --bootstrap "$BUILDER" | grep -iE 'buildkit version|driver' || true

# 1) 결정론 이미지 → docker-format tar (rewrite-timestamp으로 레이어 mtime까지 SDE 고정)
rm -f "$DOCKER_TAR"
docker buildx build --builder "$BUILDER" \
  --platform linux/arm64 \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  --output "type=docker,name=${IMAGE_TAG},rewrite-timestamp=true,dest=${DOCKER_TAR}" \
  -f enclave.Dockerfile .

# 2) docker 데몬에 적재 (docker-format tar → docker load)
docker load -i "$DOCKER_TAR"

# 3) nitro-cli로 EIF 빌드 (핀고정 nitro-cli + 커널 blobs)
nitro-cli build-enclave --docker-uri "$IMAGE_TAG" --output-file "$EIF_OUT"

# 4) PCR0 출력
echo "== Measurements =="
nitro-cli describe-eif --eif-path "$EIF_OUT" | grep -iE 'PCR[0-9]'
echo "== 완료. 재현성 증명: 다른 호스트/CI에서 한 번 더 빌드해 PCR0 byte-match 확인(더블빌드) =="
