package hmcl

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/bits"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

var key = []byte{
	0x3c, 0xd8, 0xa2, 0x22, 0x11, 0xd2, 0x8d, 0x89,
	0xb4, 0xf7, 0xd9, 0xb0, 0x65, 0xbc, 0x14, 0x8a,
	0x6e, 0xb0, 0xa9, 0x4d, 0xeb, 0x93, 0x99, 0x6f,
	0x84, 0x07, 0x5a, 0x9e, 0xbd, 0xc8, 0xd1, 0xeb,
}

type EnvelopeV1 struct {
	Schema     string          `json:"$schema,omitempty"`
	Protection string          `json:"protection"`
	Payload    json.RawMessage `json:"payload"`
	Nonce      string          `json:"nonce,omitempty"`
}

// Decrypt 会将解密后的内容填充到 e.Payload 中, 同时 e.Protection 为"plain"
func (e *EnvelopeV1) Decrypt() error {
	if e.Protection != "hmcl-obfuscated-v1" {
		return fmt.Errorf("payload must be decrypted")
	}

	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSize {
		return fmt.Errorf("invalid nonce")
	}

	var lanes []json.RawMessage
	if err := json.Unmarshal(e.Payload, &lanes); err != nil || len(lanes) < 4 {
		return fmt.Errorf("invalid payload")
	}

	size := 1 << (bits.Len(uint(len(lanes))) - 1)
	segment := size / 4

	var encoded strings.Builder
	for i := range 4 {
		index := (i+1)*segment - 1

		var lane string
		if index >= len(lanes) || json.Unmarshal(lanes[index], &lane) != nil {
			return fmt.Errorf("invalid lane %d", i)
		}
		encoded.WriteString(lane)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}

	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	if !json.Valid(plain) {
		return fmt.Errorf("decrypted payload is not JSON")
	}

	e.Protection = "plain"
	e.Nonce = ""
	e.Payload = plain
	return nil
}

// Encrypt 会将 e.Payload 中的内容加密到 e.Payload 中, 同时 e.Protection 为"hmcl-obfuscated-v1"
func (e *EnvelopeV1) Encrypt() error {
	if e.Protection != "plain" {
		return fmt.Errorf("payload must be encrypted")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, e.Payload); err != nil {
		return err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}

	ciphertext := aead.Seal(nil, nonce, compact.Bytes(), nil)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	if len(encoded)%4 != 0 {
		return fmt.Errorf("unexpected base64 length")
	}

	laneLen := len(encoded) / 4
	lanes := make([]any, 0, 256)

	for i := range 4 {
		for range 63 {
			lanes = append(lanes, nil)
		}

		start := i * laneLen
		lanes = append(lanes, encoded[start:start+laneLen])
	}

	payload, err := json.Marshal(lanes)
	if err != nil {
		return err
	}

	e.Protection = "hmcl-obfuscated-v1"
	e.Nonce = base64.StdEncoding.EncodeToString(nonce)
	e.Payload = payload
	return nil
}
