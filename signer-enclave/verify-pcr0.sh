#!/usr/bin/env bash
# 제3자 검증 (T4.8) — 현재 체크아웃(HEAD)을 재현 빌드해 산출 PCR0가 BUILD.lock의 expected_pcr0와
# byte-match하는지 확인한다. 누구나 이걸 돌려 "운영 enclave = 공시 코드"를 스스로 검증한다.
#
# SDE를 빌드 입력 경로로 묶었기에 ledger 커밋이 PCR0를 안 바꿈 → HEAD에서 바로 검증된다(checkout 불필요).
# 환경은 reproduce.sh와 동일(AL2023 arm64 + BUILD.lock 핀).
set -euo pipefail
cd "$(dirname "$0")"

echo "== 재현 빌드 실행 (HEAD $(git rev-parse --short HEAD)) =="
./reproduce.sh

BUILT="$(nitro-cli describe-eif --eif-path signer.eif | grep -ioE '[0-9a-f]{96}' | head -1)"
[ -n "$BUILT" ] || { echo "✗ 빌드 PCR0 파싱 실패"; exit 1; }

# 기대값 = BUILD.lock의 expected_pcr0 (안정적 — 커밋 위치 무관)
PUB="$(grep -E '^expected_pcr0' BUILD.lock 2>/dev/null | grep -ioE '[0-9a-f]{96}' | head -1 || true)"

echo ""
echo "  built PCR0    : $BUILT"
echo "  expected PCR0 : ${PUB:-<BUILD.lock expected_pcr0 미기입>}"
echo ""

[ -n "$PUB" ] || { echo "⚠ BUILD.lock에 expected_pcr0 없음 — 더블빌드 확정 후 기입 필요"; exit 2; }
if [ "$BUILT" = "$PUB" ]; then
  echo "✅ MATCH — 재현 빌드 PCR0 == 공시값. 운영 enclave가 공시 코드임을 검증."
else
  echo "❌ MISMATCH — 재현 빌드 결과가 공시값과 다름. 핀(BUILD.lock)·소스 확인 필요."
  exit 3
fi
