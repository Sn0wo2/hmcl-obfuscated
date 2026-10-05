package hmcl

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"

	"golang.org/x/crypto/chacha20poly1305"
)

type Account struct {
	AccountID   string         `json:"accountID"`
	PrivateData PrivateData    `json:"privateData"`
	Extra       jsontext.Value `json:",embed"`
}

type PrivateData struct {
	ProfileName  *string        `json:"profileName,omitzero"`
	TokenType    *string        `json:"tokenType,omitzero"`
	AccessToken  *string        `json:"accessToken,omitzero"`
	RefreshToken *string        `json:"refreshToken,omitzero"`
	NotAfter     *int64         `json:"notAfter,omitzero"`
	UserID       *string        `json:"userid,omitzero"`
	Extra        jsontext.Value `json:",embed"`
}

func Encrypt(accounts []Account, marshal func(any) ([]byte, error)) (*EnvelopeV1, error) {
	plain, err := marshal(accounts)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, nil))

	laneLen := len(encoded) / 4
	payload := make([]*string, 256)

	for i := range 4 {
		start := i * laneLen
		lane := encoded[start : start+laneLen]

		payload[(i+1)*64-1] = &lane
	}
	data, err := marshal(payload)
	if err != nil {
		return nil, err
	}
	encodedNonce := base64.StdEncoding.EncodeToString(nonce)

	return &EnvelopeV1{
		Schema:     "https://schemas.glavo.site/hmcl/account-private-data/1.0.0",
		Protection: "hmcl-obfuscated-v1",
		Payload:    data,
		Nonce:      &encodedNonce,
	}, nil
}
