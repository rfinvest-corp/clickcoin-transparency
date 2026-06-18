//go:build linux

// Package vtransport는 vsock dial/listen을 한 곳에 모은다.
// enclave/parent 두 바이너리가 공유해, 플랫폼 build-tag 분기를 바이너리마다 복제하지 않는다.
package vtransport

import (
	"net"

	"github.com/mdlayher/vsock"
)

func Listen(port uint32) (net.Listener, error) { return vsock.Listen(port, nil) }

func Dial(cid, port uint32) (net.Conn, error) { return vsock.Dial(cid, port, nil) }
