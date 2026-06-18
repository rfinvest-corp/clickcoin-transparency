#!/usr/bin/env bash
# 부모 EC2(c7g.large Graviton, Amazon Linux 2023 arm64)에 Nitro Enclaves 실행 환경을 구성한다.
# enclave 지원 인스턴스 + IAM role(KMS/SSM) 필요. doc 04 환경 표 참조.
set -euo pipefail

echo "== nitro-cli + docker + 빌드도구(make/git) 설치 =="
# 재현 빌드(T4.8)는 nitro-cli 버전 고정 필수 — 커널·init blobs가 PCR0를 좌우한다. BUILD.lock과 일치시킬 것.
# NITRO_VER 미지정 시 latest 설치(= 비재현, PoC용). 재현 빌드용이면 반드시 지정.
NITRO_VER="${NITRO_VER:-}"
if [ -n "$NITRO_VER" ]; then
  sudo dnf install -y \
    "aws-nitro-enclaves-cli-${NITRO_VER}" "aws-nitro-enclaves-cli-devel-${NITRO_VER}" \
    docker make git
else
  echo "⚠ NITRO_VER 미지정 — latest 설치(비재현). 재현 빌드는 NITRO_VER 지정 필요(예: NITRO_VER=1.3.4-0.amzn2023)." >&2
  sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker make git
fi
# 재현 빌드는 docker-container 드라이버(최신 BuildKit)를 쓴다 — dockerd 내장 BuildKit(0.12)은
# type=docker에 rewrite-timestamp 미적용. skopeo/podman 불필요(AL2023 기본 repo에 없음).

echo "== nitro-cli / 커널 blobs 핀 기록 (BUILD.lock 채우기용) =="
nitro-cli --version || true
rpm -q aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel || true
sha256sum /usr/share/nitro_enclaves/blobs/* 2>/dev/null | sort || true

echo "== 그룹 추가(ne, docker) =="
sudo usermod -aG ne "$USER"
sudo usermod -aG docker "$USER"

echo "== allocator: enclave에 1 vCPU / 2048 MiB 할당 (c7g.large 2vCPU/4GB → parent에 1 vCPU 잔여) =="
sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null <<'YAML'
---
memory_mib: 2048
cpu_count: 1
YAML

echo "== 서비스 기동 =="
sudo systemctl enable --now docker
sudo systemctl enable --now nitro-enclaves-allocator.service

cat <<'NOTE'

[다음 단계]
  1) 로그아웃 후 재로그인(ne/docker 그룹 반영)
  2) nitro-cli --version 으로 확인
  3) scripts/create-kms-poc.sh 로 CMK 생성
  4) make build-eif && make pcr0
NOTE
