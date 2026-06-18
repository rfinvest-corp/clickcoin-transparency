package cms

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"testing"
)

// 디코더 검증용 최소 인코더(optional 필드 제외). RFC 5652 EnvelopedData 구조를 동일 OID로 구성.
type edOut struct {
	Version          int
	RecipientInfos   []keyTransRecipientInfo `asn1:"set"`
	EncryptedContent eciOut
}

// eciOut: 인코딩용 — primitive [0] OCTET STRING을 내보낸다(디코더는 RawValue로 받음).
type eciOut struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func pkcs7Pad(b []byte, k int) []byte {
	pad := k - len(b)%k
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func buildCMS(t *testing.T, plaintext []byte, pub *rsa.PublicKey) []byte {
	t.Helper()
	cek := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(cek)
	rand.Read(iv)

	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
	if err != nil {
		t.Fatal(err)
	}
	ivParam, err := asn1.Marshal(iv) // OCTET STRING
	if err != nil {
		t.Fatal(err)
	}
	ridDER, _ := asn1.Marshal(1) // 더미 RID — 파서는 내용을 무시

	ed := edOut{
		Version: 0,
		RecipientInfos: []keyTransRecipientInfo{{
			Version:                0,
			RID:                    asn1.RawValue{FullBytes: ridDER},
			KeyEncryptionAlgorithm: algorithmIdentifier{Algorithm: oidRSAESOAEP},
			EncryptedKey:           encKey,
		}},
		EncryptedContent: eciOut{
			ContentType:                asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}, // id-data
			ContentEncryptionAlgorithm: algorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivParam}},
			EncryptedContent:           ct,
		},
	}
	edDER, err := asn1.Marshal(ed)
	if err != nil {
		t.Fatal(err)
	}
	oidDER, err := asn1.Marshal(oidEnvelopedData)
	if err != nil {
		t.Fatal(err)
	}
	// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT EnvelopedData }.
	// asn1.Marshal은 RawValue에 explicit 래퍼를 안 씌우므로 외부 TLV를 수동 구성한다.
	inner := append(oidDER, tlv(0xA0, edDER)...) // [0] EXPLICIT (context|constructed|0)
	return tlv(0x30, inner)                      // SEQUENCE
}

// tlv는 DER TLV를 만든다(태그 1바이트 + 길이 + 내용).
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

func TestDecryptRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("0123456789abcdef0123456789abcdef") // 32B 평문 데이터키 흉내
	der := buildCMS(t, want, &priv.PublicKey)

	got, err := Decrypt(der, priv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("불일치: got=%q want=%q", got, want)
	}
}

func TestBer2DerIndefinite(t *testing.T) {
	// indefinite-length SEQUENCE { INTEGER 1 } → definite-length DER
	ber := []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}
	want := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	got, err := ber2der(ber)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got=%x want=%x", got, want)
	}
}

func TestBer2DerIdempotentOnDER(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := buildCMS(t, []byte("0123456789abcdef0123456789abcdef"), &priv.PublicKey)
	got, err := ber2der(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, der) {
		t.Fatalf("DER이 ber2der로 변형됨\n got=%x\nwant=%x", got, der)
	}
}

// AWS처럼 바깥 구조를 indefinite-length BER로 감싸도 복호화되는지(ber2der 경로 검증).
func TestDecryptHandlesIndefiniteBER(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("0123456789abcdef0123456789abcdef")
	der := buildCMS(t, want, &priv.PublicKey)

	// 최상위 SEQUENCE의 length를 indefinite(0x80 ... 00 00)로 교체.
	i := 1
	if der[i] > 0x80 {
		i += 1 + int(der[i]&0x7f)
	} else {
		i++
	}
	ber := append([]byte{der[0], 0x80}, der[i:]...)
	ber = append(ber, 0x00, 0x00)

	got, err := Decrypt(ber, priv)
	if err != nil {
		t.Fatalf("Decrypt(BER): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("불일치: %q", got)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := buildCMS(t, []byte("secret-data-key-1234567890123456"), &priv.PublicKey)
	if _, err := Decrypt(der, other); err == nil {
		t.Fatal("다른 키로 복호화가 성공하면 안 된다")
	}
}
