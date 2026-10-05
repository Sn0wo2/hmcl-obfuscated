package hmcl

import (
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

	segment := (1 << (bits.Len(uint(len(payload))) - 1)) / 4

	var encoded strings.Builder

	for i := range 4 {
		index := (i+1)*segment - 1
		if payload[index] == nil {
			return nil, fmt.Errorf("invalid lane %d", i)
		}

		encoded.WriteString(*payload[index])
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
	if err := unmarshal(plain, &accounts); err != nil {
		return nil, err
	}

	return accounts, nil
}
