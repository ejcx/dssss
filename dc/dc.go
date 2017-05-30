package dc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	MasterKeyByteLength = 32
)

type Key struct {
	Bytes [32]byte
}

func (k *Key) String() string {
	return hex.EncodeToString(k.Bytes[:])
}
func NewKey() (*Key, error) {
	buf := new([MasterKeyByteLength]byte)
	_, err := rand.Read(buf[:])
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Could not generate master key: %s", err))
	}
	return &Key{Bytes: *buf}, nil

}

// Seal wraps that AEAD interface secretbox Seal and safely
// generates a random nonce for developers. This change to
// seal eliminates the risk of programmers reusing nonces.
func Seal(key *[32]byte, message []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return secretbox.Seal(nonce[:], message, &nonce, key), nil
}

// Open wraps the AEAD interface secretbox.Open
func Open(key *[32]byte, ciphertext []byte) (message []byte, err error) {
	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])
	message, ok := secretbox.Open(message[:0], ciphertext[24:], &nonce, key)
	if !ok {
		err = errors.New("Unable to decrypt message")
	}
	return
}

// Scrypt is a wrapper around scrypt.Key that performs the Scrypt
// algorithm on the input with opinionated defaults.
func Scrypt(pass, salt []byte) (key [32]byte, err error) {
	keyBytes, err := scrypt.Key(pass, salt, 262144, 8, 1, 32)
	copy(key[:], keyBytes)
	return
}
