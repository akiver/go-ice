package ice

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {
	key := NewIceKey(1)
	key.Set([]byte{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89})
	toEncrypt := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	encrypted := make([]byte, 8)
	key.Encrypt(toEncrypt, encrypted)

	expected := []byte{88, 76, 140, 254, 103, 42, 211, 107}
	assert.Equal(t, expected, encrypted)
}

func TestDecrypt(t *testing.T) {
	key := NewIceKey(1)
	key.Set([]byte{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89})
	toDecrypt := []byte{88, 76, 140, 254, 103, 42, 211, 107}

	decrypted := make([]byte, 8)
	key.Decrypt(toDecrypt, decrypted)

	expected := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	assert.Equal(t, expected, decrypted)
}

func TestDecryptFull(t *testing.T) {
	key := NewIceKey(1)
	key.Set([]byte{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89})
	toDecrypt := []byte{88, 76, 140, 254, 103, 42, 211, 107, 220, 104, 67, 20, 201, 178, 90, 174}

	decrypted := make([]byte, 16)
	key.DecryptFullArray(toDecrypt, decrypted)
	expected := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x85, 0x68, 0x88, 0xe8, 0x75, 0x70, 0x12, 0xaf}
	assert.Equal(t, expected, decrypted)
}
