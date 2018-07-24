package xxtea

import (
	"testing"
)

func TestEncrypt(t *testing.T) {
	data := []uint32{1, 2, 3, 4}
	key := [4]uint32{5, 6, 7, 8}
	Encrypt(data[:1], &key)
	t.Logf("%08x", data)
	Decrypt(data[:1], &key)
	t.Logf("%08x", data)
	Encrypt(data, &key)
	t.Logf("%08x", data)
	Decrypt(data, &key)
	t.Logf("%08x", data)
}

func TestEncryptBytes(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	key := [4]uint32{5, 6, 7, 8}
	EncryptBytes(data, &key)
	t.Logf("%02x", data)
	DecryptBytes(data, &key)
	t.Logf("%02x", data)
}

var (
	bkey  = [4]uint32{1, 2, 3, 4}
	bdata = make([]uint32, 256)
)

func BenchmarkEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Encrypt(bdata, &bkey)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Decrypt(bdata, &bkey)
	}
}
