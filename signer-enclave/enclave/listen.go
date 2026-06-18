package main

import (
	"fmt"
	"net"

	"kcoin/poc-enclave-signing/vtransport"
)

// listen은 transport에 맞는 listener를 만든다. "vsock"은 플랫폼별 구현(linux)으로 위임한다.
func listen(transport string, port uint32) (net.Listener, error) {
	switch transport {
	case "tcp":
		return net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	case "vsock":
		return vtransport.Listen(port)
	default:
		return nil, fmt.Errorf("알 수 없는 transport: %q (vsock|tcp)", transport)
	}
}
