package signer

import "testing"

// 현행 prod 코드(ccapp/exchange/binance_futures.py)와 동일 입력에 대해
// Python이 만든 golden 서명과 정확히 일치해야 한다. 불일치 = 주문 서명 거부.
func TestSignMatchesBinancePython(t *testing.T) {
	secret := []byte("MyBinanceApiSecretKey_PoC_v1")
	payload := []byte("symbol=BTCUSDT&side=BUY&type=LIMIT&timeInForce=GTC&quantity=1&price=20000&recvWindow=5000&timestamp=1700000000000")
	const want = "a2f063a0260b845423a10d9e82df36d3ff0f4b8abec48572a56dfca0cca63cb9"

	if got := Sign(secret, payload); got != want {
		t.Fatalf("서명 불일치\n got=%s\nwant=%s", got, want)
	}
}

func TestSignEmptyAndUnicodePayload(t *testing.T) {
	// payload는 enclave 입장에서 불투명한 바이트열 — 빈 값/유니코드도 안정적으로 처리.
	secret := []byte("k")
	if Sign(secret, []byte("")) == "" {
		t.Fatal("빈 payload도 유효한 HMAC을 내야 한다")
	}
	if Sign(secret, []byte("심볼=비트코인")) == Sign(secret, []byte("symbol=btc")) {
		t.Fatal("서로 다른 payload가 같은 서명을 내면 안 된다")
	}
}

func TestSignEncoded(t *testing.T) {
	secret := []byte("MyBinanceApiSecretKey_PoC_v1")

	// hex(Binance) == Sign
	in := []byte("symbol=BTCUSDT&side=BUY&type=LIMIT&timeInForce=GTC&quantity=1&price=20000&recvWindow=5000&timestamp=1700000000000")
	got, err := SignEncoded(secret, in, "hex")
	if err != nil || got != Sign(secret, in) {
		t.Fatalf("hex 불일치: err=%v got=%s", err, got)
	}

	// base64url(Upbit JWT HS256 서명) — Python golden과 일치
	signingInput := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3Nfa2V5IjoiQUtFWSIsIm5vbmNlIjoibi0xIn0")
	const wantB64 = "6q9aJpSsCrWCQA1_iidqcWy25juKFYJfqtjcSqdqFGg"
	gotB64, err := SignEncoded(secret, signingInput, "base64url")
	if err != nil {
		t.Fatal(err)
	}
	if gotB64 != wantB64 {
		t.Fatalf("base64url 불일치\n got=%s\nwant=%s", gotB64, wantB64)
	}

	if _, err := SignEncoded(secret, in, "weird"); err == nil {
		t.Fatal("알 수 없는 encoding은 에러여야 한다")
	}
}

func TestZero(t *testing.T) {
	b := []byte("supersecret")
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d 미소거: %d", i, v)
		}
	}
}
