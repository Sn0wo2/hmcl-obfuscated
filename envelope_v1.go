package hmcl

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"math/bits"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

type EnvelopeV1 struct {
	Schema     string         `json:"$schema"`
	Protection string         `json:"protection"`
	Payload    jsontext.Value `json:"payload"`
	Nonce      *string        `json:"nonce,omitzero"`
	Extra      jsontext.Value `json:",embed"`
}

var aead, aeadErr = chacha20poly1305.New([]byte{
	0x3c, 0xd8, 0xa2, 0x22, 0x11, 0xd2, 0x8d, 0x89,
	0xb4, 0xf7, 0xd9, 0xb0, 0x65, 0xbc, 0x14, 0x8a,
	0x6e, 0xb0, 0xa9, 0x4d, 0xeb, 0x93, 0x99, 0x6f,
	0x84, 0x07, 0x5a, 0x9e, 0xbd, 0xc8, 0xd1, 0xeb,
})

func Encrypt(accounts []Account, marshal func(any) ([]byte, error)) (*EnvelopeV1, error) {
	plain, err := marshal(accounts)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	if aeadErr != nil {
		return nil, aeadErr
	}

	encoded := base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, nil))

	payload := make([]*string, 256)
	for i := range 4 {
		payload[(i+1)*64-1] = new(encoded[i*len(encoded)/4 : (i+1)*len(encoded)/4])
	}

	data, err := marshal(payload)
	if err != nil {
		return nil, err
	}

	return &EnvelopeV1{
		Schema:     "https://schemas.glavo.site/hmcl/account-private-data/1.0.0",
		Protection: "hmcl-obfuscated-v1",
		Payload:    data,
		Nonce:      new(base64.StdEncoding.EncodeToString(nonce)),
	}, nil
}

func (e *EnvelopeV1) Decrypt(unmarshal func([]byte, any) error) ([]Account, error) {
	if e.Protection == "plain" {
		var accounts []Account

		err := unmarshal(e.Payload, &accounts)

		return accounts, err
	}

	if e.Protection != "hmcl-obfuscated-v1" {
		return nil, fmt.Errorf("unsupported account protection: %q", e.Protection)
	}

	if e.Nonce == nil {
		return nil, errors.New("invalid nonce")
	}

	nonce, err := base64.StdEncoding.DecodeString(*e.Nonce)
	if err != nil {
		return nil, err
	}

	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, errors.New("invalid nonce")
	}

	var payload []*string
	if err := unmarshal(e.Payload, &payload); err != nil {
		return nil, err
	}

	if len(payload) < 4 {
		return nil, errors.New("payload too small")
	}

	var encoded strings.Builder

	for i := range 4 {
		lane := payload[(i+1)*(1<<(bits.Len(uint(len(payload)))-3))-1]
		if lane == nil {
			return nil, fmt.Errorf("invalid lane %d", i)
		}

		encoded.WriteString(*lane)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return nil, err
	}

	if aeadErr != nil {
		return nil, aeadErr
	}

	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var accounts []Account
	if err := unmarshal(plain, &accounts); err != nil {
		return nil, err
	}

	return accounts, nil
}
