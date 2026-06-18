// Package signer는 HMAC-SHA256 서명을 수행한다(Binance=hex, Upbit JWT=base64url 출력).
// 이 패키지는 stdlib만 쓰며, enclave 안에서 평문 키를 다루는 유일한 핫패스다.
package signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// mac은 raw HMAC-SHA256(secret, input).
func mac(secret, input []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(input)
	return m.Sum(nil)
}

// Sign은 Binance HMAC: hex(HMAC-SHA256(secret, input)).
// (ccapp/exchange/binance_futures.py:80-84 _sign_params와 동일)
func Sign(secret, input []byte) string {
	return hex.EncodeToString(mac(secret, input))
}

// SignEncoded는 raw HMAC을 encoding으로 인코딩한다:
//
//	"hex" | ""  → Binance 서명
//	"base64url" → Upbit JWT 서명(HS256 — base64url, no padding)
//
// enclave는 거래소를 모르고 인코딩만 분기한다(거래소별 구조 조립은 호출자 담당, doc 09).
// secret은 호출 직후 Zero()로 소거한다.
func SignEncoded(secret, input []byte, encoding string) (string, error) {
	m := mac(secret, input)
	switch encoding {
	case "", "hex":
		return hex.EncodeToString(m), nil
	case "base64url":
		return base64.RawURLEncoding.EncodeToString(m), nil
	default:
		return "", fmt.Errorf("알 수 없는 encoding: %q", encoding)
	}
}

// Zero는 평문 키 바이트 슬라이스를 0으로 덮는다.
// Go는 GC가 평문 복사본을 힙에 남길 수 있어 완전한 zeroing을 보장하지 못한다(Q-2.C 리스크).
// 최소한 원본 슬라이스는 서명 직후 즉시 소거한다.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
