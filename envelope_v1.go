package hmcl

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"math/bits"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

type EnvelopeV1 struct {
	Schema     string         `json:"$schema"`
	Protection string         `json:"protection"`
	Payload    []*string      `json:"payload"`
	Nonce      string         `json:"nonce"`
	Extra      jsontext.Value `json:",embed"`
}

func (e *EnvelopeV1) Decrypt() ([]Account, error) {
	if e.Protection != "hmcl-obfuscated-v1" {
		return nil, fmt.Errorf("payload is not encrypted")
	}

	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("invalid nonce")
	}

	if len(e.Payload) < 4 {
		return nil, fmt.Errorf("payload too small")
	}

	size := 1 << (bits.Len(uint(len(e.Payload))) - 1)
	segment := size / 4

	var encoded strings.Builder

	for i := range 4 {
		index := (i+1)*segment - 1
		if index >= len(e.Payload) || e.Payload[index] == nil {
			return nil, fmt.Errorf("invalid lane %d", i)
		}

		encoded.WriteString(*e.Payload[index])
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var accounts []Account
	if err := json.Unmarshal(plain, &accounts); err != nil {
		return nil, err
	}

	return accounts, nil
}
