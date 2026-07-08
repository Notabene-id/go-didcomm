package jose

import (
	"crypto/sha256"
	"encoding/binary"
)

// concatKDF implements the single-round NIST SP 800-56A §5.8.1 Concatenation
// KDF with SHA-256 that JOSE ECDH key agreement uses (RFC 7518 §4.6). Because
// the derived key never exceeds the 32-byte hash output, exactly one round is
// required; longer outputs are rejected by the caller via keyLen.
//
//	DK = SHA-256( counter(=1) || Z || OtherInfo )[:keyLen]
func concatKDF(z, otherInfo []byte, keyLen int) []byte {
	h := sha256.New()
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], 1)
	h.Write(counter[:])
	h.Write(z)
	h.Write(otherInfo)
	return h.Sum(nil)[:keyLen]
}

// lengthPrefixed returns Datalen || Data, where Datalen is the big-endian
// 32-bit length of Data in octets (the "Data" encoding of SP 800-56A OtherInfo
// fields and of the ECDH-1PU cctag).
func lengthPrefixed(data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out[:4], uint32(len(data))) //nolint:gosec // JOSE field lengths are small and non-negative
	copy(out[4:], data)
	return out
}

// otherInfo builds the SP 800-56A OtherInfo string for a JOSE ECDH derivation:
//
//	AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
//
// where each of AlgorithmID/PartyUInfo/PartyVInfo is length-prefixed, and
// SuppPubInfo is keydatalen (bits, big-endian 32-bit) optionally followed by the
// ECDH-1PU draft-04 cctag (length-prefixed content-encryption tag). Pass a nil
// tag for ECDH-ES and for ECDH-1PU draft-03, which omit the cctag.
func otherInfo(alg string, apu, apv []byte, keyLenBits int, tag []byte) []byte {
	var buf []byte
	buf = append(buf, lengthPrefixed([]byte(alg))...)
	buf = append(buf, lengthPrefixed(apu)...)
	buf = append(buf, lengthPrefixed(apv)...)

	var keyLen [4]byte
	binary.BigEndian.PutUint32(keyLen[:], uint32(keyLenBits)) //nolint:gosec // key length in bits is a small constant
	buf = append(buf, keyLen[:]...)

	if tag != nil {
		buf = append(buf, lengthPrefixed(tag)...)
	}
	return buf
}
