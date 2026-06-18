// Package cms는 KMS가 attestation Decrypt에서 돌려주는 CiphertextForRecipient를 복호화한다.
//
// KMS는 Recipient(attestation document, RSAES_OAEP_SHA_256)로 호출하면 평문을 직접 주지 않고,
// enclave 공개키로 암호화한 CMS(PKCS#7) EnvelopedData를 CiphertextForRecipient로 돌려준다.
// 구조(RFC 5652): RSAES-OAEP-SHA256으로 content-encryption key(CEK)를 감싸고,
// AES-256-CBC로 본문(평문 데이터키)을 암호화한다.
//
// ⚠️ 하드웨어 검증 필요: 아래 파서는 자체 인코더와의 라운드트립으로만 단위 검증됐다.
// AWS의 실제 바이트 레이아웃(RID 형태, OAEP 파라미터 명시 여부 등)과의 최종 일치는
// 실제 enclave에서 확인해야 한다. 불일치 시 README의 kmstool_enclave_cli 폴백 사용.
package cms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type keyTransRecipientInfo struct {
	Version                int
	RID                    asn1.RawValue // issuerAndSerialNumber 또는 [0] subjectKeyIdentifier
	KeyEncryptionAlgorithm algorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"` // [0] IMPLICIT OCTET STRING (primitive 또는 구성)
}

// contentBytes는 [0] encryptedContent(RawValue)에서 ciphertext를 꺼낸다.
// primitive면 그대로, 구성(BER 청크)이면 내부 OCTET STRING들을 병합한다.
func contentBytes(rv asn1.RawValue) ([]byte, error) {
	if !rv.IsCompound {
		return rv.Bytes, nil
	}
	var out []byte
	rest := rv.Bytes
	for len(rest) > 0 {
		var chunk []byte
		r, err := asn1.Unmarshal(rest, &chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		rest = r
	}
	return out, nil
}

type envelopedData struct {
	Version          int
	OriginatorInfo   asn1.RawValue           `asn1:"optional,tag:0"`
	RecipientInfos   []keyTransRecipientInfo `asn1:"set"`
	EncryptedContent encryptedContentInfo
	UnprotectedAttrs asn1.RawValue `asn1:"optional,tag:1"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// Decrypt는 CiphertextForRecipient → 평문(여기선 평문 데이터키)을 돌려준다.
// 입력은 BER일 수 있어(AWS KMS는 indefinite-length 사용) DER로 정규화 후 파싱한다.
func Decrypt(raw []byte, priv *rsa.PrivateKey) ([]byte, error) {
	der, err := ber2der(raw)
	if err != nil {
		return nil, fmt.Errorf("BER→DER: %w", err)
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("ContentInfo 파싱: %w", err)
	}
	if !ci.ContentType.Equal(oidEnvelopedData) {
		return nil, fmt.Errorf("EnvelopedData 아님: %v", ci.ContentType)
	}

	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		return nil, fmt.Errorf("EnvelopedData 파싱: %w", err)
	}
	if len(ed.RecipientInfos) == 0 {
		return nil, errors.New("recipientInfos 비어 있음")
	}

	ktri := ed.RecipientInfos[0]
	if !ktri.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAESOAEP) {
		return nil, fmt.Errorf("키 암호화가 RSAES-OAEP 아님: %v", ktri.KeyEncryptionAlgorithm.Algorithm)
	}
	// RSAES-OAEP-SHA256: label/MGF1 모두 SHA-256 (Go DecryptOAEP는 hash를 양쪽에 사용).
	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ktri.EncryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("CEK OAEP 복호화: %w", err)
	}

	eci := ed.EncryptedContent
	if !eci.ContentEncryptionAlgorithm.Algorithm.Equal(oidAES256CBC) {
		return nil, fmt.Errorf("본문 암호화가 AES-256-CBC 아님: %v", eci.ContentEncryptionAlgorithm.Algorithm)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(eci.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("CBC IV 파싱: %w", err)
	}
	ct, err := contentBytes(eci.EncryptedContent)
	if err != nil {
		return nil, fmt.Errorf("encryptedContent 추출: %w", err)
	}
	return aesCBCDecrypt(cek, iv, ct)
}

func aesCBCDecrypt(key, iv, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(ct) == 0 || len(ct)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("CBC 입력 길이 비정상 (iv=%d ct=%d key=%d block=%d)", len(iv), len(ct), len(key), block.BlockSize())
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	return pkcs7Unpad(out, block.BlockSize())
}

func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	n := len(b)
	if n == 0 {
		return nil, errors.New("빈 평문")
	}
	pad := int(b[n-1])
	if pad == 0 || pad > blockSize || pad > n {
		return nil, errors.New("잘못된 PKCS#7 패딩")
	}
	for _, c := range b[n-pad:] {
		if int(c) != pad {
			return nil, errors.New("PKCS#7 패딩 바이트 불일치")
		}
	}
	return b[:n-pad], nil
}
