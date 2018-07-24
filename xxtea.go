package xxtea

import "unsafe"

const _DELTA = 0x9e3779b9

func Encrypt(v []uint32, k *[4]uint32) {
	if len(v) <= 1 {
		return
	}
	n := len(v)
	rounds := 6 + 52/n
	last := n - 1
	sum := uint32(0)
	for {
		sum += _DELTA
		e := (sum >> 2) & 3
		z := v[last]
		for p := 0; p < last; p++ {
			vp := (*[2]uint32)(unsafe.Pointer(&v[p]))
			y := vp[1]
			vp[0] += ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(uint32(p)^e)&3] ^ z))
			z = vp[0]
		}
		y := v[0]
		v[last] += ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(uint32(last)^e)&3] ^ z))
		rounds--
		if rounds == 0 {
			break
		}
	}
}

func Decrypt(v []uint32, k *[4]uint32) {
	if len(v) <= 1 {
		return
	}
	sum := uint32((6 + 52/len(v)) * _DELTA)
	tail := &v[len(v)-1]
	for {
		y := v[0]
		e := (sum >> 2) & 3
		p := len(v) - 2
		for ; p >= 0; p-- {
			vp := (*[2]uint32)(unsafe.Pointer(&v[p]))
			z := vp[0]
			vp[1] -= ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(uint32(p+1)^e)&3] ^ z))
			y = vp[1]
		}
		z := *tail
		v[0] -= ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(0^e)&3] ^ z))
		sum -= _DELTA
		if sum == 0 {
			break
		}
	}
}

func EncryptBytes(data []byte, k *[4]uint32) {
	v := *(*[]uint32)(unsafe.Pointer(&data))
	Encrypt(v[:len(data)/4], k)
}

func DecryptBytes(data []byte, k *[4]uint32) {
	v := *(*[]uint32)(unsafe.Pointer(&data))
	Decrypt(v[:len(data)/4], k)
}
