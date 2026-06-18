# ClickCoin Transparency

ClickCoin(클릭코인)은 사용자의 거래소 API Key를 **평문으로 보관하거나 열람하지 않습니다.**
주문 서명은 AWS Nitro Enclave 내부에서만 이뤄지고, AWS KMS 키 정책이 **특정 PCR0 측정값을 가진
enclave에만** 복호화를 허용하도록 못박혀 있습니다. 이 저장소는 그 PCR0를 공개해 제3자가 무결성을
검증할 수 있게 합니다.

## PCR0

PCR0 = Nitro Enclave 이미지(EIF)의 SHA-384 측정값. 운영 중인 서명 enclave의 코드를 고정합니다.
현재 공시 값은 [`PCR0.txt`](./PCR0.txt)(release당 1행, append-only) 참조.

## 무엇을 보장하나

- 운영 enclave의 PCR0가 공시 값과 같다 → 코드가 바뀌지 않았음.
- KMS는 PCR0 일치 enclave에만 복호화를 허용 → 다른 코드는 사용자 키를 복호화할 수 없음.
- 각 기록은 AWS S3 Object Lock(Compliance, 10년)으로도 불변 보관됩니다.

## 검증

지금 공개되는 것은 **PCR0 값(정본)** 입니다. 이 값은 AWS KMS 정책 조건과 대조해 확인할 수 있습니다.

enclave가 사용자 키를 빼돌리지 않는다는 점은 **독립 외부 감사인의 검증**으로 보증합니다 — 감사인이
NDA 하에 signer enclave 소스를 동일 toolchain으로 재현 빌드해 산출 PCR0가 위 공시 값과 byte-match하는지
확인하고, 그 **검증 보고서를 공개**합니다.

> 소스를 전면 공개하지 않고도, 신뢰 가능한 제3자가 "공시된 PCR0 = 키 비유출 코드"임을 검증·보증하는 모델입니다.

## 릴리스

각 PCR0 공시는 GitHub release로도 태깅됩니다. [Releases](../../releases) 참조.
