//go:build !linux

package main

import "errors"

// 비-Linux에서는 attestation 경로를 쓸 수 없다. 브링업은 --mock 사용.
func NewAttestationUnwrapper(string, uint32, uint32) (Unwrapper, error) {
	return nil, errors.New("attestation은 linux/enclave에서만 지원 (브링업은 --mock 사용)")
}
