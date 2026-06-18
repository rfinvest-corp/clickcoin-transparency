package envelope

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// Python security.py(AESGCM, AAD="kcoin-apikey-v2")가 만든 토큰을 Go가 그대로 복호화하는지.
// 통과 = enclave가 DB에 저장된 Phase 1 envelope을 코드 변경 없이 처리할 수 있음을 증명.
// (KMS unwrap 단계는 여기서 알려진 데이터키로 대체 — AES-GCM 호환성만 검증)
const pyToken = "v2:V1JBUFBFRF9QTEFDRUhPTERFUg==:AAECAwQFBgcICQoL:CnuUcquErHjoAOfi4owbH+aizFGJJA8TeziTtDvb8V5XOuGHi+mmyMMQJj8="

func TestOpenDecryptsPythonEnvelope(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	_, nonce, ct, err := Parse(pyToken)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pt, err := OpenWith(key, nonce, ct)
	if err != nil {
		t.Fatalf("Python envelope 복호화 실패: %v", err)
	}
	if string(pt) != "MyBinanceApiSecretKey_PoC_v1" {
		t.Fatalf("평문 불일치: %q", pt)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	wrapped := []byte("wrapped-data-key-bytes")
	pt := []byte("api-secret-xyz")

	tok, err := SealRandom(key, wrapped, pt)
	if err != nil {
		t.Fatal(err)
	}
	w, nonce, ct, err := Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w, wrapped) {
		t.Fatal("wrapped 라운드트립 실패")
	}
	got, err := OpenWith(key, nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("평문 라운드트립 실패: %q", got)
	}
}

func TestTamperFails(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	tok, _ := SealRandom(key, []byte("w"), []byte("secret"))
	_, nonce, ct, _ := Parse(tok)
	ct[0] ^= 0xff // GCM 태그 검증 실패 유도
	if _, err := OpenWith(key, nonce, ct); err == nil {
		t.Fatal("변조된 ciphertext가 복호화되면 안 된다")
	}
}
