package main

import (
	"context"
	"net"

	"kcoin/poc-enclave-signing/proto"
	"kcoin/poc-enclave-signing/vtransport"
)

// vsockKMSDialContext는 enclave에서 부모의 vsock-proxy를 통해 KMS로 나가는 다이얼러다.
// TLS는 상위 http.Transport가 KMS 호스트명(SNI)으로 수행하고 vsock-proxy는 TCP 패스스루이므로,
// enclave ↔ KMS가 end-to-end로 암호화된다(부모는 평문을 못 봄).
func vsockKMSDialContext(proxyPort uint32) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, _, _ string) (net.Conn, error) {
		return vtransport.Dial(proto.ParentCID, proxyPort)
	}
}
