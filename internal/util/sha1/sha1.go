package sha1

import (
	"encoding/binary"
	"math/bits"
)

const (
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)

type Hash struct {
	h0 uint32
	h1 uint32
	h2 uint32
	h3 uint32
	h4 uint32
}

func New() Hash {
	return Hash{
		h0: init0,
		h1: init1,
		h2: init2,
		h3: init3,
		h4: init4,
	}
}

// Helper for MAC attacks
func (h *Hash) LoadState(in [20]byte) {
	h.h0 = binary.BigEndian.Uint32(in[0:4])
	h.h1 = binary.BigEndian.Uint32(in[4:8])
	h.h2 = binary.BigEndian.Uint32(in[8:12])
	h.h3 = binary.BigEndian.Uint32(in[12:16])
	h.h4 = binary.BigEndian.Uint32(in[16:20])
}

func (h *Hash) Sum(in []byte) [20]byte {
	{
		// this part is adapted from
		// https://cs.opensource.google/go/go/+/master:src/crypto/sha1/sha1block.go
		originalLength := len(in)

		var tmp [64]byte

		// append 10000000, not 00000001
		// append 0x80, not 0x01
		tmp[0] = 0x80

		if originalLength%64 < 56 {
			in = append(in, tmp[0:56-originalLength%64]...)
		} else {
			in = append(in, tmp[0:64+56-originalLength%64]...)
		}

		// x << 3 == x * 8
		lengthInBits := originalLength << 3

		// uint64 data requires 8 bytes
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(lengthInBits))

		in = append(in, b...)
	}

	{
		for i := 0; i < len(in); i += 64 {
			chunk := in[i : i+64]
			var words [80]uint32
			for i := 0; i < 16; i++ {
				words[i] = binary.BigEndian.Uint32(chunk[i*4 : (i+1)*4])
			}
			for i := 16; i < 80; i++ {
				temp := (words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16])
				words[i] = bits.RotateLeft32(temp, 1)
			}

			a, b, c, d, e := h.h0, h.h1, h.h2, h.h3, h.h4
			var f, k uint32

			for i := 0; i < 80; i++ {
				if i <= 19 {
					f = (b & c) | ((^b) & d)
					k = 0x5A827999
				} else if i <= 39 {
					f = b ^ c ^ d
					k = 0x6ED9EBA1
				} else if i <= 59 {
					f = (b & c) | (b & d) | (c & d)
					k = 0x8F1BBCDC
				} else {
					f = b ^ c ^ d
					k = 0xCA62C1D6
				}

				temp := bits.RotateLeft32(a, 5) + f + e + k + words[i]
				e = d
				d = c
				c = bits.RotateLeft32(b, 30)
				b = a
				a = temp
			}

			h.h0 += a
			h.h1 += b
			h.h2 += c
			h.h3 += d
			h.h4 += e

			// fmt.Println(a, b, c, d, e)
		}
	}

	{
		var digest [20]byte
		binary.BigEndian.PutUint32(digest[0:], h.h0)
		binary.BigEndian.PutUint32(digest[4:], h.h1)
		binary.BigEndian.PutUint32(digest[8:], h.h2)
		binary.BigEndian.PutUint32(digest[12:], h.h3)
		binary.BigEndian.PutUint32(digest[16:], h.h4)

		return digest
	}
}

func (h *Hash) SumSingleBlockWithoutPadding(chunk []byte) [20]byte {
	{
		var words [80]uint32
		for i := 0; i < 16; i++ {
			words[i] = binary.BigEndian.Uint32(chunk[i*4 : (i+1)*4])
		}
		for i := 16; i < 80; i++ {
			temp := (words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16])
			words[i] = bits.RotateLeft32(temp, 1)
		}

		a, b, c, d, e := h.h0, h.h1, h.h2, h.h3, h.h4
		var f, k uint32

		for i := 0; i < 80; i++ {
			if i <= 19 {
				f = (b & c) | ((^b) & d)
				k = 0x5A827999
			} else if i <= 39 {
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			} else if i <= 59 {
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			} else {
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}

			temp := bits.RotateLeft32(a, 5) + f + e + k + words[i]
			e = d
			d = c
			c = bits.RotateLeft32(b, 30)
			b = a
			a = temp
		}

		h.h0 += a
		h.h1 += b
		h.h2 += c
		h.h3 += d
		h.h4 += e
	}

	{
		var digest [20]byte
		binary.BigEndian.PutUint32(digest[0:], h.h0)
		binary.BigEndian.PutUint32(digest[4:], h.h1)
		binary.BigEndian.PutUint32(digest[8:], h.h2)
		binary.BigEndian.PutUint32(digest[12:], h.h3)
		binary.BigEndian.PutUint32(digest[16:], h.h4)

		return digest
	}
}
