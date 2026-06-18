# syntax=docker/dockerfile:1.7
# signer enclave 재현 빌드 이미지. nitro-cli build-enclave가 이 이미지를 EIF로 감싼다. (T4.8)
#
# 재현성 원칙: 측정되는 것은 최종 scratch 이미지(=/signer 바이트 + CA 번들 + 이미지 구조)뿐.
#   - base를 digest로 핀고정 → /signer 빌드 toolchain·CA 번들 바이트가 고정
#   - 결정론 Go 플래그(-trimpath/-buildvcs=false/-buildid=) → 같은 소스 = 같은 바이너리
#   - GOARCH 고정(arm64, prod c7g Graviton)
#   - 이미지 레이어 타임스탬프는 reproduce.sh의 BuildKit SOURCE_DATE_EPOCH로 고정
# 빌드는 반드시 reproduce.sh로 실행한다(`docker build` 직접 호출 금지 — 타임스탬프 비고정).

# base는 floating tag 금지, 반드시 digest 핀고정. 값/해석은 BUILD.lock 참조.
FROM --platform=linux/arm64 golang:1.25@sha256:188c07d275836f297fe211d98ecd2d7f252501000c5b3d0e601d6392748c593b AS build
ENV CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# 결정론: -trimpath(경로 제거) -buildvcs=false(VCS 스탬프 제거) -buildid=(빌드ID 고정) -s -w(디버그 제거)
RUN go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o /signer ./enclave

FROM scratch
# scratch엔 CA 루트가 없어 KMS TLS 검증 실패(x509: unknown authority).
# digest 고정된 build 이미지에서 복사 → 번들 바이트가 결정론적.
# (Amazon Trust 루트만으로 최소화하는 TCB 하드닝은 별도 후속 — 그때 ca-certificates.crt를 vendor)
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /signer /signer
ENTRYPOINT ["/signer", "--listen", "vsock", "--port", "5005", "--kms-proxy-port", "8000", "--region", "ap-northeast-2"]
