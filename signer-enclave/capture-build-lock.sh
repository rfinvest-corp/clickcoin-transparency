#!/usr/bin/env bash
# BUILD.lock 핀 값 캡처 (T4.8) — c7g arm64 / AL2023 호스트에서 실행.
# golang arm64 base digest, nitro-cli/패키지 버전, 커널 blob 해시를 모아 출력한다.
# signer.eif가 있으면 PCR0도 캡처. --write 주면 BUILD.lock·enclave.Dockerfile의 __FILL__을 치환.
#
# 사용:
#   bash capture-build-lock.sh           # 값만 출력(검토용 — 함께 확인 후 --write)
#   bash capture-build-lock.sh --write    # BUILD.lock + enclave.Dockerfile 자동 기입
# 의존: docker buildx, nitro-cli, rpm, python3 (AL2023 기본 충족)
set -euo pipefail
cd "$(dirname "$0")"

GOLANG_TAG="${GOLANG_TAG:-golang:1.25}"
WRITE=0; [ "${1:-}" = "--write" ] && WRITE=1

echo "== golang arm64 base digest ($GOLANG_TAG) =="
RAW="$(docker buildx imagetools inspect "$GOLANG_TAG" --raw)"
DIGEST="$(printf '%s' "$RAW" | python3 -c "import json,sys
d=json.load(sys.stdin); ms=d.get('manifests',[])
print(next(m['digest'] for m in ms if m.get('platform',{}).get('architecture')=='arm64' and m.get('platform',{}).get('os')=='linux'))")"
DIGEST_HEX="${DIGEST#sha256:}"
echo "  $DIGEST"

echo "== nitro-cli / 패키지 / 커널 blobs =="
NITRO_RAW="$(nitro-cli --version 2>/dev/null | head -1 || echo '?')"
PKG_V="$(rpm -q --qf '%{VERSION}' aws-nitro-enclaves-cli 2>/dev/null || echo '?')"
PKG_VR="$(rpm -q --qf '%{VERSION}-%{RELEASE}' aws-nitro-enclaves-cli 2>/dev/null || echo '?')"
DEV_VR="$(rpm -q --qf '%{VERSION}-%{RELEASE}' aws-nitro-enclaves-cli-devel 2>/dev/null || echo '?')"
BLOBS="$(sha256sum /usr/share/nitro_enclaves/blobs/* 2>/dev/null | sort || true)"
BLOBS_FP="$(printf '%s' "$BLOBS" | sha256sum | cut -d' ' -f1)"
echo "  nitro-cli : $NITRO_RAW"
echo "  pkg       : aws-nitro-enclaves-cli-$PKG_VR / -devel-$DEV_VR"
echo "  NITRO_VER : $PKG_VR   (setup-host.sh에 넘길 값)"
echo "  blobs fp  : $BLOBS_FP"
printf '%s\n' "$BLOBS" | sed 's/^/    /'

PCR0=""; COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
if [ -f signer.eif ]; then
  PCR0="$(nitro-cli describe-eif --eif-path signer.eif | grep -ioE '[0-9a-f]{96}' | head -1 || true)"
  echo "== signer.eif PCR0 (commit $COMMIT) =="
  echo "  $PCR0"
else
  echo "== signer.eif 없음 — PCR0는 'make build-eif-repro' 후 재실행 시 캡처 =="
fi

if [ "$WRITE" = 1 ]; then
  echo "== BUILD.lock / enclave.Dockerfile 기입 =="
  sed -i.bak \
    -e "s|__FILL_GOLANG_ARM64_DIGEST__|$DIGEST_HEX|g" \
    -e "s|^nitro_cli_version    = __FILL__|nitro_cli_version    = $PKG_V|" \
    -e "s|aws-nitro-enclaves-cli-__FILL__ , -devel-__FILL__|aws-nitro-enclaves-cli-$PKG_VR , -devel-$DEV_VR|" \
    -e "s|^kernel_blobs_sha256  = __FILL__|kernel_blobs_sha256  = $BLOBS_FP|" \
    BUILD.lock
  sed -i.bak "s|__FILL_GOLANG_ARM64_DIGEST__|$DIGEST_HEX|g" enclave.Dockerfile
  if [ -n "$PCR0" ]; then
    sed -i.bak \
      -e "s|expected_pcr0        = __FILL_AFTER_DOUBLE_BUILD__|expected_pcr0        = $PCR0|" \
      -e "s|^built_from_commit    = __FILL__|built_from_commit    = $COMMIT|" \
      BUILD.lock
  fi
  rm -f BUILD.lock.bak enclave.Dockerfile.bak
  echo "  ✅ 기입 완료."
  echo "     남은 항목: expected_pcr0(더블빌드 일치 확인 후)·verified_double_build=yes 는 수동 확정."
fi
