/*
 * Implementation of the ICE encryption algorithm.
 *
 * Go port of the original C implementation written by Matthew Kwan - July 1996.
 * More info about the algorithm: http://www.darkside.com.au/ice/
 */
package ice

import (
	"sync"
)

var (
	sMod = [][]int{
		{333, 313, 505, 369},
		{379, 375, 319, 391},
		{361, 445, 451, 397},
		{397, 425, 395, 505}}
	sXor = [][]int{
		{0x83, 0x85, 0x9b, 0xcd},
		{0xcc, 0xa7, 0xad, 0x41},
		{0x4b, 0x2e, 0xd4, 0x33},
		{0xea, 0xcb, 0x2e, 0x04}}
	pBox = []int{
		0x00000001, 0x00000080, 0x00000400, 0x00002000,
		0x00080000, 0x00200000, 0x01000000, 0x40000000,
		0x00000008, 0x00000020, 0x00000100, 0x00004000,
		0x00010000, 0x00800000, 0x04000000, 0x20000000,
		0x00000004, 0x00000010, 0x00000200, 0x00008000,
		0x00020000, 0x00400000, 0x08000000, 0x10000000,
		0x00000002, 0x00000040, 0x00000800, 0x00001000,
		0x00040000, 0x00100000, 0x02000000, 0x80000000}
	keyrot = []int{
		0, 1, 2, 3, 2, 1, 3, 0,
		1, 3, 2, 0, 3, 1, 0, 2}
	spBoxBuildOnce sync.Once
	spBox          [4][1024]int
)

type IceKey interface {
	Set(key []byte)
	Encrypt(plaintext []byte, ciphertext []byte)
	Decrypt(ciphertext []byte, plaintext []byte)
	DecryptFullArray(ciphertext []byte, plaintext []byte)
}

type iceKeyInternal struct {
	rounds      int
	size        int
	keySchedule [][]int
}

// Create a new ICE key with the specified level.
func NewIceKey(level int) IceKey {
	iceKey := iceKeyInternal{}

	if level < 1 {
		iceKey.size = 1
		iceKey.rounds = 8
	} else {
		iceKey.size = level
		iceKey.rounds = level * 16
	}

	buildSpBoxOnce()

	iceKey.keySchedule = make([][]int, iceKey.rounds)
	for i := range iceKey.keySchedule {
		iceKey.keySchedule[i] = make([]int, 3)
	}

	return iceKey
}

func buildSpBoxOnce() {
	spBoxBuildOnce.Do(buildSpBox)
}

// Initialize the substitution/permutation boxes.
// This only has to be done once.
func buildSpBox() {
	for i := 0; i < 1024; i++ {
		col := (i >> 1) & 0xff
		row := (i & 0x1) | ((i & 0x200) >> 8)

		x := gf_exp7(col^sXor[0][row], sMod[0][row]) << 24
		spBox[0][i] = perm32(x)

		x = gf_exp7(col^sXor[1][row], sMod[1][row]) << 16
		spBox[1][i] = perm32(x)

		x = gf_exp7(col^sXor[2][row], sMod[2][row]) << 8
		spBox[2][i] = perm32(x)

		x = gf_exp7(col^sXor[3][row], sMod[3][row])
		spBox[3][i] = perm32(x)
	}
}

// Galois Field multiplication of a by b, modulo m.
// Just like arithmetic multiplication, except that additions and
// subtractions are replaced by XOR.
func gf_mult(a int, b int, m int) int {
	var res int

	for b != 0 {
		if b&1 != 0 {
			res ^= a
		}

		a <<= 1
		b >>= 1

		if a >= 256 {
			a ^= m
		}
	}

	return res
}

// Galois Field exponentiation.
// Raise the base to the power of 7, modulo m.
func gf_exp7(b int, m int) int {
	if b == 0 {
		return 0
	}

	x := gf_mult(b, b, m)
	x = gf_mult(b, x, m)
	x = gf_mult(x, x, m)

	return gf_mult(b, x, m)
}

// Carry out the ICE 32-bit P-box permutation.
func perm32(x int) int {
	res := 0
	i := 0

	for x != 0 {
		if (x & 1) != 0 {
			res |= pBox[i]
		}
		i++
		x >>= 1
	}

	return res
}

// The single round ICE f function.
func roundFunc(p int, subkey []int) int {
	tl := ((p >> 16) & 0x3ff) | (((p >> 14) | (p << 18)) & 0xffc00)
	tr := (p & 0x3ff) | ((p << 2) & 0xffc00)
	al := subkey[2] & (tl ^ tr)
	ar := al ^ tr
	al ^= tl
	al ^= subkey[0]
	ar ^= subkey[1]

	return spBox[0][al>>10] | spBox[1][al&0x3ff] | spBox[2][ar>>10] | spBox[3][ar&0x3ff]
}

// Set 8 rounds [n, n+7] of the key schedule of an ICE key.
func (iceKey iceKeyInternal) scheduleBuild(kb []int, n int, krot_idx int) {
	for i := 0; i < 8; i++ {
		kr := keyrot[krot_idx+i]
		subkey := iceKey.keySchedule[n+i]

		for j := 0; j < 3; j++ {
			iceKey.keySchedule[n+i][j] = 0
		}

		for j := 0; j < 15; j++ {
			curr_sk := j % 3

			for k := 0; k < 4; k++ {
				curr_kb := kb[(kr+k)&3]
				bit := curr_kb & 1

				subkey[curr_sk] = (subkey[curr_sk] << 1) | bit
				kb[(kr+k)&3] = (curr_kb >> 1) | ((bit ^ 1) << 15)
			}
		}
	}
}

// Set the key schedule of an ICE key.
func (iceKey iceKeyInternal) Set(key []byte) {
	var kb = make([]int, 4)

	if iceKey.rounds == 8 {
		for i := 0; i < 4; i++ {
			kb[3-i] = ((int(key[i*2])&0xff)<<8 | (int(key[i*2+1]) & 0xff))
		}

		iceKey.scheduleBuild(kb, 0, 0)
		return
	}

	for i := 0; i < iceKey.size; i++ {
		for j := 0; j < 4; j++ {
			kb[3-j] = ((int(key[i*8+j*2])&0xff)<<8 | (int(key[i*8+j*2+1]) & 0xff))
		}

		iceKey.scheduleBuild(kb, i*8, 0)
		iceKey.scheduleBuild(kb, iceKey.rounds-8-i*8, 8)
	}
}

// Decrypt a block of 8 bytes of data.
func (iceKey iceKeyInternal) Decrypt(ciphertext []byte, plaintext []byte) {
	var l int
	var r int

	for i := 0; i < 4; i++ {
		l |= (int(ciphertext[i]) & 0xff) << (24 - i*8)
		r |= (int(ciphertext[i+4]) & 0xff) << (24 - i*8)
	}

	for i := iceKey.rounds - 1; i > 0; i -= 2 {
		l ^= roundFunc(r, iceKey.keySchedule[i])
		r ^= roundFunc(l, iceKey.keySchedule[i-1])
	}

	for i := 0; i < 4; i++ {
		plaintext[3-i] = (byte)(r & 0xff)
		plaintext[7-i] = (byte)(l & 0xff)

		r >>= 8
		l >>= 8
	}
}

// Encrypt a block of 8 bytes of data.
func (iceKey iceKeyInternal) Encrypt(plaintext []byte, ciphertext []byte) {
	var l int
	var r int

	for i := 0; i < 4; i++ {
		l |= (int(plaintext[i]) & 0xff) << (24 - i*8)
		r |= (int(plaintext[i+4]) & 0xff) << (24 - i*8)
	}

	for i := 0; i < iceKey.rounds; i += 2 {
		l ^= roundFunc(r, iceKey.keySchedule[i])
		r ^= roundFunc(l, iceKey.keySchedule[i+1])
	}

	for i := 0; i < 4; i++ {
		ciphertext[3-i] = (byte)(r & 0xff)
		ciphertext[7-i] = (byte)(l & 0xff)

		r >>= 8
		l >>= 8
	}
}

// Return the key size, in bytes.
func (iceKey iceKeyInternal) GetSize() int {
	return iceKey.size * 8
}

// Return the block size, in bytes.
func (iceKey iceKeyInternal) BlockSize() int {
	return 8
}

// Clear the key schedule to prevent memory snooping.
func (iceKey iceKeyInternal) Clear() {
	for i := 0; i < iceKey.rounds; i++ {
		for j := 0; j < 3; j++ {
			iceKey.keySchedule[i][j] = 0
		}
	}
}

func (iceKey iceKeyInternal) DecryptFullArray(ciphertext []byte, plaintext []byte) {
	var cipherHolder = make([]byte, 8)
	var plainHolder = make([]byte, 8)
	var from = 0
	var to = len(ciphertext)
	var k = 0

	for from+8 <= to {
		for i := 0; i < 8; i++ {
			cipherHolder[i] = ciphertext[from+i]
		}
		iceKey.Decrypt(cipherHolder, plainHolder)
		for i := 0; i < 8; i++ {
			plaintext[k+i] = plainHolder[i]
		}
		k += 8
		from += 8
	}

	if ((to - from) & 0x7) != 0 {
		for i := from; i < to; i++ {
			k++
			plaintext[k] = ciphertext[i]
		}
	}
}
