package hmcl

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/chacha20poly1305"
)

type Account struct {
	AccountID   string      `json:"accountID"`
	PrivateData PrivateData `json:"privateData"`
}

type PrivateData struct {
	ProfileName  string `json:"profileName"`
	TokenType    string `json:"tokenType"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	NotAfter     int64  `json:"notAfter"`
	UserID       string `json:"userid"`
}

func (a Account) Encrypt(marshaler func(any) ([]byte, error)) (*EnvelopeV1, error) {
	plain, err := marshaler([]Account{a})
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

	return &EnvelopeV1{
		Schema:     "https://schemas.glavo.site/hmcl/account-private-data/1.0.0",
		Protection: "hmcl-obfuscated-v1",
		Payload:    payload,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}, nil
}