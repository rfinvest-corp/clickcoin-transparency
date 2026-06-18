// Command enclave는 vsock(또는 tcp) 서버로 동작하며, "envelope + payload"를 받아
// KMS로 데이터키를 복원하고 api_secret을 풀어 Binance HMAC 서명만 돌려준다.
// 평문 키는 enclave 메모리에만 존재하고 서명 직후 zeroing된다.
package main

import (
	"flag"
	"log"
	"net"
	"time"

	"kcoin/poc-enclave-signing/envelope"
	"kcoin/poc-enclave-signing/proto"
	"kcoin/poc-enclave-signing/signer"
)

func main() {
	transport := flag.String("listen", "vsock", "리슨 transport: vsock|tcp")
	port := flag.Uint("port", uint(proto.DefaultEnclavePort), "리슨 포트")
	mock := flag.Bool("mock", false, "attestation 생략 + 평문 KMS.Decrypt (비-enclave 브링업)")
	region := flag.String("region", "ap-northeast-2", "AWS region")
	kmsProxyPort := flag.Uint("kms-proxy-port", uint(proto.DefaultKMSProxyPort), "부모 vsock-proxy 포트")
	credsPort := flag.Uint("creds-port", uint(proto.DefaultCredsPort), "부모 자격증명 vsock 포트")
	flag.Parse()

	unw, err := buildUnwrapper(*mock, *region, uint32(*kmsProxyPort), uint32(*credsPort))
	if err != nil {
		log.Fatalf("unwrapper 초기화 실패: %v", err)
	}

	ln, err := listen(*transport, uint32(*port))
	if err != nil {
		log.Fatalf("listen 실패: %v", err)
	}
	log.Printf("signer enclave 시작: transport=%s port=%d mock=%v region=%s", *transport, *port, *mock, *region)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept 오류: %v", err)
			continue
		}
		go serve(conn, unw)
	}
}

func buildUnwrapper(mock bool, region string, kmsProxyPort, credsPort uint32) (Unwrapper, error) {
	if mock {
		return NewMockUnwrapper(region)
	}
	return NewAttestationUnwrapper(region, kmsProxyPort, credsPort)
}

func serve(conn net.Conn, unw Unwrapper) {
	defer conn.Close()
	st := proto.NewStream(conn)
	for {
		req, err := st.ReadRequest()
		if err != nil {
			return // 연결 종료 또는 디코드 오류 → 연결 닫기
		}
		if err := st.WriteResponse(handle(req, unw)); err != nil {
			return
		}
	}
}

// handle은 단일 책임: envelope → 데이터키(KMS) → api_secret → HMAC → 평문 zeroing.
func handle(req *proto.SignRequest, unw Unwrapper) *proto.SignResponse {
	start := time.Now()

	wrapped, nonce, ct, err := envelope.Parse(req.Envelope)
	if err != nil {
		return &proto.SignResponse{Error: "envelope 파싱: " + err.Error()}
	}
	dataKey, hit, err := unw.Unwrap(wrapped)
	if err != nil {
		return &proto.SignResponse{Error: "KMS unwrap: " + err.Error()}
	}
	secret, err := envelope.OpenWith(dataKey, nonce, ct)
	if err != nil {
		return &proto.SignResponse{Error: "secret 복호화: " + err.Error()}
	}

	sig, sErr := signer.SignEncoded(secret, []byte(req.Payload), req.Encoding)
	signer.Zero(secret) // 평문 api_secret 즉시 소거 (데이터키는 캐시에 유지)
	if sErr != nil {
		return &proto.SignResponse{Error: "서명: " + sErr.Error()}
	}

	return &proto.SignResponse{
		Signature:     sig,
		KMSCacheHit:   hit,
		EnclaveMicros: time.Since(start).Microseconds(),
	}
}
