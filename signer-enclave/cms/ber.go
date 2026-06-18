package cms

import (
	"bytes"
	"errors"
)

// ber2der는 BER 인코딩을 DER로 정규화한다. AWS KMS의 CiphertextForRecipient(CMS)는
// indefinite-length(BER)를 쓰는데 Go의 encoding/asn1은 DER만 읽으므로, 파싱 전에 변환한다.
// (구성 OCTET STRING 병합 포함. 잘 알려진 변환 — go.mozilla.org/pkcs7의 ber2der와 동일 취지)
func ber2der(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, errors.New("ber2der: 입력이 비어 있음")
	}
	obj, _, err := readObject(ber, 0)
	if err != nil {
		return nil, err
	}
	out := new(bytes.Buffer)
	if err := obj.encodeTo(out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type asn1Object interface {
	encodeTo(out *bytes.Buffer) error
}

type asn1Primitive struct {
	tagBytes []byte
	content  []byte
}

func (p asn1Primitive) encodeTo(out *bytes.Buffer) error {
	out.Write(p.tagBytes)
	encodeLength(out, len(p.content))
	out.Write(p.content)
	return nil
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
}

func (s asn1Structured) encodeTo(out *bytes.Buffer) error {
	inner := new(bytes.Buffer)
	for _, c := range s.content {
		if err := c.encodeTo(inner); err != nil {
			return err
		}
	}
	out.Write(s.tagBytes)
	encodeLength(out, inner.Len())
	out.Write(inner.Bytes())
	return nil
}

// encodeLength는 DER 최소 길이 인코딩을 쓴다.
func encodeLength(out *bytes.Buffer, n int) {
	if n < 0x80 {
		out.WriteByte(byte(n))
		return
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	out.WriteByte(0x80 | byte(len(b)))
	out.Write(b)
}

// readObject는 offset에서 ASN.1 객체 1개를 읽어 (객체, 다음 offset)을 돌려준다.
func readObject(ber []byte, offset int) (asn1Object, int, error) {
	if offset >= len(ber) {
		return nil, 0, errors.New("ber2der: 태그 위치가 끝을 넘음")
	}
	tagStart := offset
	b := ber[offset]
	offset++
	if b&0x1f == 0x1f { // high-tag-number form (CMS엔 없지만 방어적으로)
		for offset < len(ber) && ber[offset]&0x80 == 0x80 {
			offset++
		}
		offset++
	}
	if offset >= len(ber) {
		return nil, 0, errors.New("ber2der: 길이 위치가 끝을 넘음")
	}
	tagBytes := ber[tagStart:offset]
	constructed := b&0x20 == 0x20

	l := ber[offset]
	offset++
	var length int
	indefinite := false
	switch {
	case l == 0x80:
		indefinite = true
	case l > 0x80:
		nb := int(l & 0x7f)
		if nb > 4 || offset+nb > len(ber) {
			return nil, 0, errors.New("ber2der: 길이 옥텟 비정상")
		}
		for i := 0; i < nb; i++ {
			length = length<<8 | int(ber[offset])
			offset++
		}
	default:
		length = int(l)
	}

	if !constructed {
		if indefinite {
			return nil, 0, errors.New("ber2der: primitive에 indefinite length")
		}
		if offset+length > len(ber) {
			return nil, 0, errors.New("ber2der: content가 끝을 넘음")
		}
		return asn1Primitive{tagBytes: tagBytes, content: ber[offset : offset+length]}, offset + length, nil
	}

	var children []asn1Object
	if indefinite {
		for {
			if offset+2 > len(ber) {
				return nil, 0, errors.New("ber2der: end-of-contents 못 찾음")
			}
			if ber[offset] == 0x00 && ber[offset+1] == 0x00 {
				offset += 2
				break
			}
			child, next, err := readObject(ber, offset)
			if err != nil {
				return nil, 0, err
			}
			children = append(children, child)
			offset = next
		}
	} else {
		end := offset + length
		if end > len(ber) {
			return nil, 0, errors.New("ber2der: 구성 content가 끝을 넘음")
		}
		for offset < end {
			child, next, err := readObject(ber, offset)
			if err != nil {
				return nil, 0, err
			}
			children = append(children, child)
			offset = next
		}
	}

	// 구성 OCTET STRING(BER 청크) → DER primitive OCTET STRING으로 병합.
	if b == 0x24 {
		merged := new(bytes.Buffer)
		for _, c := range children {
			p, ok := c.(asn1Primitive)
			if !ok {
				return nil, 0, errors.New("ber2der: 구성 OCTET STRING 자식이 primitive 아님")
			}
			merged.Write(p.content)
		}
		return asn1Primitive{tagBytes: []byte{0x04}, content: merged.Bytes()}, offset, nil
	}
	return asn1Structured{tagBytes: tagBytes, content: children}, offset, nil
}
