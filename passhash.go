package passhash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"hash"
)

/**
 *
 */
func Create(password, salt string) string {
	if salt == "" {
		salt = genSalt()
	}
	hash := pbkdf2([]byte(password), []byte(salt), 4096, 64, sha512.New)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(hash)))
	base64.StdEncoding.Encode(encoded, []byte(hash))
	return salt + string(encoded)
}

/**
 *
 */
func Compare(password, hash string) bool {
	salt := hash[:16]
	newhash := Create(password, salt)
	return newhash == hash
}

/**
 *
 */
func genSalt() string {
	salt := make([]byte, 16)
	rand.Read(salt)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(salt)))
	base64.StdEncoding.Encode(encoded, salt)
	return string(encoded[:16])
}

/**
 *
 */
func pbkdf2(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}
