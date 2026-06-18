//go:build !linux

package vtransport

import (
	"errors"
	"net"
)

// 비-Linux(개발 머신)에는 vsock이 없다. tcp 모드(--listen tcp / --enclave-transport tcp)로 브링업한다.
var errUnsupported = errors.New("vsock는 linux/enclave에서만 지원 (개발 머신은 tcp 모드 사용)")

func Listen(uint32) (net.Listener, error) { return nil, errUnsupported }

func Dial(uint32, uint32) (net.Conn, error) { return nil, errUnsupported }
