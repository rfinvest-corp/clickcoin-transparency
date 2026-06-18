//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"

	"kcoin/poc-enclave-signing/cms"
)

// NewAttestationUnwrapper는 진짜 enclave 경로다:
//
//	NSM attestation doc(공개키 포함) → KMS.Decrypt(Recipient=RSAES_OAEP_SHA_256)
//	→ CiphertextForRecipient(CMS) → enclave 개인키로 복호화 → 평문 데이터키
//
// ⚠️ 하드웨어 검증 필요. enclave엔 IMDS가 없어 자격증명은 부모가 vsock으로 중계한다
// (vsockCredsProvider → parent serveCredentials). CMS 호환성 문제 시 README의 kmstool_enclave_cli 폴백.
func NewAttestationUnwrapper(region string, kmsProxyPort, credsPort uint32) (Unwrapper, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("NSM 세션 열기 실패(enclave 밖에서 실행?): %w", err)
	}

	httpClient := &http.Client{Transport: &http.Transport{DialContext: vsockKMSDialContext(kmsProxyPort)}}
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
		config.WithHTTPClient(httpClient),
		// enclave엔 IMDS가 없으므로 부모가 vsock으로 중계한 자격증명을 사용(SDK가 캐시·갱신).
		config.WithCredentialsProvider(vsockCredsProvider{credsPort: credsPort}),
	)
	if err != nil {
		return nil, err
	}
	client := kms.NewFromConfig(cfg)

	inner := func(wrapped []byte) ([]byte, error) {
		// 요청마다 fresh attestation doc — KMS가 PCR0 조건을 매번 검증한다.
		res, err := sess.Send(&request.Attestation{PublicKey: pubDER})
		if err != nil {
			return nil, fmt.Errorf("attestation 요청: %w", err)
		}
		if res.Attestation == nil || len(res.Attestation.Document) == 0 {
			return nil, fmt.Errorf("attestation document 비어 있음")
		}
		out, err := client.Decrypt(context.Background(), &kms.DecryptInput{
			CiphertextBlob: wrapped,
			Recipient: &kmstypes.RecipientInfo{
				AttestationDocument:    res.Attestation.Document,
				KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
			},
		})
		if err != nil {
			return nil, err
		}
		// Recipient 사용 시 out.Plaintext는 비고, out.CiphertextForRecipient(CMS)만 채워진다.
		return cms.Decrypt(out.CiphertextForRecipient, priv)
	}
	return newCachingUnwrapper(inner, 4096), nil
}
