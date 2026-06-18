package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"kcoin/poc-enclave-signing/proto"
	"kcoin/poc-enclave-signing/vtransport"
)

// vsockCredsProvider는 enclave 안의 AWS SDK가 쓸 자격증명을 부모로부터 vsock으로 가져온다.
// enclave엔 IMDS가 없으므로 부모(호스트 IMDS 보유)가 중계한다. SDK가 CredentialsCache로 감싸
// 만료 전까지 캐시하고, 만료 임박 시에만 Retrieve를 다시 호출하므로 매 요청 비용은 없다.
type vsockCredsProvider struct {
	credsPort uint32
}

func (p vsockCredsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	conn, err := vtransport.Dial(proto.ParentCID, p.credsPort)
	if err != nil {
		return aws.Credentials{}, err
	}
	defer conn.Close()

	var c proto.Credentials
	if err := json.NewDecoder(conn).Decode(&c); err != nil {
		return aws.Credentials{}, err
	}
	if c.Error != "" {
		return aws.Credentials{}, errors.New("부모 자격증명 조회 실패: " + c.Error)
	}

	creds := aws.Credentials{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Source:          "vsock-parent-imds",
	}
	if c.Expiration != "" {
		if t, err := time.Parse(time.RFC3339, c.Expiration); err == nil {
			creds.CanExpire = true
			creds.Expires = t
		}
	}
	return creds, nil
}
