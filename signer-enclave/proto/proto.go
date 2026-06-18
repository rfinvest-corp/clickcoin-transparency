// Package proto는 부모(호스트)와 enclave가 vsock 위에서 주고받는 메시지와
// 프레이밍을 정의한다. stdlib만 의존하므로 모든 플랫폼에서 컴파일/테스트된다.
package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
)

const (
	// DefaultEnclavePort: enclave가 vsock에서 listen하는 포트.
	DefaultEnclavePort uint32 = 5005
	// ParentCID: VMADDR_CID_PARENT. enclave에서 부모 인스턴스를 가리키는 고정 CID.
	ParentCID uint32 = 3
	// DefaultKMSProxyPort: 부모의 vsock-proxy가 KMS 엔드포인트로 포워딩하는 포트
	// (scripts/run-vsock-proxy.sh와 일치시킬 것).
	DefaultKMSProxyPort uint32 = 8000
	// DefaultCredsPort: 부모가 enclave에 IMDS 자격증명을 내려주는 vsock 포트.
	// enclave엔 IMDS가 없어 부모가 중계한다(자격증명 전달).
	DefaultCredsPort uint32 = 5006
)

// SignRequest: 부모 → enclave.
// enclave는 거래소 의미를 전혀 모르고, payload 바이트열만 HMAC 서명한다.
// 따라서 거래소가 늘어도 enclave는 변경 불필요(Upbit JWT는 payload 구성만 다름).
type SignRequest struct {
	// Phase 1 security.py가 DB에 저장하는 envelope 토큰 그대로:
	// "v2:b64(wrapped):b64(nonce):b64(ct)". enclave는 wrapped 데이터키를
	// KMS.Decrypt(attestation)로 풀고 AES-256-GCM으로 api_secret을 복원한다.
	// CMK는 enclave 정책/환경으로 고정 — 호출자가 키를 고르지 못하게 요청에 KeyID를 두지 않는다.
	Envelope string `json:"envelope"`
	// Payload: HMAC 서명 입력. Binance=urlencode된 query string,
	// Upbit=JWT 서명입력(b64url(header).b64url(payload)). 거래소별 조립은 호출자 담당(doc 09).
	Payload string `json:"payload"`
	// Encoding: enclave가 HMAC 출력을 인코딩하는 방식. "hex"(Binance) | "base64url"(Upbit). 빈 값=hex.
	Encoding string `json:"encoding,omitempty"`
	// Exchange: 부모의 JWT claim 검증용("binance"|"upbit"). enclave는 사용하지 않는다.
	Exchange string `json:"exchange,omitempty"`
}

// SignResponse: enclave → 부모.
type SignResponse struct {
	// Signature: 인코딩된 서명(hex 또는 base64url — 요청 Encoding에 따름).
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
	// KMSCacheHit: 이 요청이 in-enclave 데이터키 캐시를 맞췄는지(S4 측정용).
	KMSCacheHit bool `json:"kms_cache_hit"`
	// EnclaveMicros: enclave 내부 처리 시간(µs). vsock 왕복은 제외 — 부모에서 별도 측정.
	EnclaveMicros int64 `json:"enclave_micros"`
}

// Credentials: 부모 → enclave. 부모가 자신의 IMDS 자격증명(단기 STS)을 내려준다.
// enclave의 AWS SDK가 이걸로 KMS를 호출하고, Expiration 전에 다시 요청하면 fresh를 받는다.
type Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	Expiration      string `json:"expiration,omitempty"` // RFC3339, 없으면 빈 값
	Error           string `json:"error,omitempty"`
}

// EnvHash는 JWT env_hash 클레임 값을 계산한다 — base64url(SHA256(envelope)).
// Leader(발급)와 Signing Service(검증)가 반드시 동일하게 계산해야 JWT가 특정 envelope에
// 바인딩된다. 양쪽이 이 한 함수를 공유해 계산이 어긋날 수 없게 한다(stdlib만 사용).
func EnvHash(envelope string) string {
	h := sha256.Sum256([]byte(envelope))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// Stream: 하나의 연결에서 요청/응답을 newline-delimited JSON으로 주고받는다.
// json.Decoder는 스트림에서 연속된 JSON 값을 읽으므로 연결당 다중 요청에 안전하다.
type Stream struct {
	dec *json.Decoder
	enc *json.Encoder
}

func NewStream(rw io.ReadWriter) *Stream {
	return &Stream{dec: json.NewDecoder(rw), enc: json.NewEncoder(rw)}
}

func (s *Stream) ReadRequest() (*SignRequest, error) {
	var req SignRequest
	if err := s.dec.Decode(&req); err != nil {
		return nil, err
	}
	return &req, nil
}

func (s *Stream) WriteResponse(resp *SignResponse) error { return s.enc.Encode(resp) }

func (s *Stream) WriteRequest(req *SignRequest) error { return s.enc.Encode(req) }

func (s *Stream) ReadResponse() (*SignResponse, error) {
	var resp SignResponse
	if err := s.dec.Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
