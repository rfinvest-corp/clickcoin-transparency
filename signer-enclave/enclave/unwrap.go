package main

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Unwrapper는 wrapped 데이터키(KMS CiphertextBlob)를 평문 데이터키로 복원한다.
type Unwrapper interface {
	Unwrap(wrapped []byte) (dataKey []byte, cacheHit bool, err error)
}

// cachingUnwrapper는 wrapped별로 평문 데이터키를 캐시한다
// (ccapp/security.py _unwrap_data_key LRU와 동일 취지). 평문 api_secret이 아니라
// "데이터키"만 캐시한다 — 평문 키는 매 요청 재유도 후 즉시 zeroing된다(S4 측정 대상).
type cachingUnwrapper struct {
	inner func(wrapped []byte) ([]byte, error)
	mu    sync.RWMutex
	cache map[string][]byte
	order []string
	max   int
}

func newCachingUnwrapper(inner func([]byte) ([]byte, error), max int) *cachingUnwrapper {
	return &cachingUnwrapper{inner: inner, cache: make(map[string][]byte), max: max}
}

func (c *cachingUnwrapper) Unwrap(wrapped []byte) ([]byte, bool, error) {
	// hit 경로: RLock + 인라인 string(wrapped) 맵 조회 → 키 문자열 할당 없음(컴파일러 최적화).
	c.mu.RLock()
	if dk, ok := c.cache[string(wrapped)]; ok {
		c.mu.RUnlock()
		return dk, true, nil
	}
	c.mu.RUnlock()

	// 캐시 미스는 KMS 호출. 동일 키 동시 미스 시 thundering herd 가능(PoC 허용; 운영은 singleflight 권장).
	dk, err := c.inner(wrapped)
	if err != nil {
		return nil, false, err
	}

	k := string(wrapped) // 키 문자열은 miss 경로에서만 생성
	c.mu.Lock()
	c.put(k, dk)
	c.mu.Unlock()
	return dk, false, nil
}

func (c *cachingUnwrapper) put(k string, dk []byte) {
	if _, ok := c.cache[k]; ok {
		return
	}
	if len(c.order) >= c.max { // 가장 오래된 키 evict (단순 FIFO — PoC엔 충분)
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.cache, oldest)
	}
	c.cache[k] = dk
	c.order = append(c.order, k)
}

// NewMockUnwrapper는 attestation 없이 평문 KMS.Decrypt를 호출한다(비-enclave 브링업/CI용).
// 일반 EC2/IAM 환경에서 전체 파이프라인(proto·envelope·HMAC·metrics)을 Nitro 없이 검증할 수 있다.
// 단, attestation 오버헤드(NSM doc + 큰 KMS 페이로드 + CMS)는 측정에 빠지므로 GO 판정은 실경로로.
func NewMockUnwrapper(region string) (Unwrapper, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	client := kms.NewFromConfig(cfg)
	inner := func(wrapped []byte) ([]byte, error) {
		out, err := client.Decrypt(context.Background(), &kms.DecryptInput{CiphertextBlob: wrapped})
		if err != nil {
			return nil, err
		}
		return out.Plaintext, nil
	}
	return newCachingUnwrapper(inner, 4096), nil
}
