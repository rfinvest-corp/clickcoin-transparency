// Package envelope는 Phase 1 ccapp/security.py의 `v2:` envelope 포맷을 Go에서 동일하게
// 읽고 쓴다. enclave는 이 포맷을 그대로 복호화하므로, DB에 이미 저장된 사용자 키
// 암호문을 코드 변경 없이 enclave가 처리할 수 있다(Phase 1 ↔ Phase 2 연속성).
//
// 포맷: "v2:" + b64(wrapped_data_key) + ":" + b64(nonce) + ":" + b64(ciphertext)
// 암호화: AES-256-GCM, nonce 12B, AAD="kcoin-apikey-v2" (security.py와 동일).
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

const Prefix = "v2:"

// AAD는 security.py._AAD와 반드시 동일해야 한다(불일치 시 복호화 실패).
var AAD = []byte("kcoin-apikey-v2")

var b64 = base64.StdEncoding

// Parse는 envelope 토큰을 (wrapped, nonce, ct)로 분해한다. "v2:" 접두는 있으면 제거.
func Parse(token string) (wrapped, nonce, ct []byte, err error) {
	parts := strings.Split(strings.TrimPrefix(token, Prefix), ":")
	if len(parts) != 3 {
		return nil, nil, nil, errors.New("잘못된 envelope 형식(세그먼트 3개 아님)")
	}
	if wrapped, err = b64.DecodeString(parts[0]); err != nil {
		return nil, nil, nil, err
	}
	if nonce, err = b64.DecodeString(parts[1]); err != nil {
		return nil, nil, nil, err
	}
	if ct, err = b64.DecodeString(parts[2]); err != nil {
		return nil, nil, nil, err
	}
	return wrapped, nonce, ct, nil
}

// OpenWith는 KMS로 복원한 평문 데이터키로 ciphertext를 AES-256-GCM 복호화한다.
// 반환된 평문(api_secret)은 호출자가 사용 직후 zeroing할 책임이 있다.
func OpenWith(dataKey, nonce, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, AAD)
}

// Seal은 명시 nonce로 envelope 토큰을 만든다(테스트 결정성용). security.py._envelope_encrypt와 동일 산출.
func Seal(dataKey, wrapped, plaintext, nonce []byte) (string, error) {
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plaintext, AAD)
	return Prefix + b64.EncodeToString(wrapped) + ":" + b64.EncodeToString(nonce) + ":" + b64.EncodeToString(ct), nil
}

// SealRandom은 loadgen 키풀 생성용 — crypto/rand로 12B nonce를 뽑아 Seal한다.
func SealRandom(dataKey, wrapped, plaintext []byte) (string, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return Seal(dataKey, wrapped, plaintext, nonce)
}
