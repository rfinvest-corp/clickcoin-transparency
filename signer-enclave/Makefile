# signer enclave 재현 빌드/검증 (ClickCoin transparency).
# 빌드/검증 호스트: AL2023 arm64(c7g) + nitro-cli + docker. 핀은 BUILD.lock 참조.
GO ?= go
.PHONY: test build-eif-repro verify-pcr0 capture-build-lock pcr0

## 공개 패키지 단위 테스트
test:
	$(GO) test ./signer/... ./envelope/... ./cms/... ./proto/... ./vtransport/...

## 재현 빌드(결정론적) → signer.eif + PCR0
build-eif-repro:
	./reproduce.sh

## 검증 — 재현 빌드 PCR0 == BUILD.lock expected_pcr0 (HEAD에서 바로)
verify-pcr0:
	./verify-pcr0.sh

## BUILD.lock 핀 값 캡처(호스트). 자동 기입: make capture-build-lock WRITE=--write
capture-build-lock:
	./capture-build-lock.sh $(WRITE)

## EIF measurements 출력
pcr0:
	@nitro-cli describe-eif --eif-path signer.eif | grep -iE 'PCR[0-9]'
