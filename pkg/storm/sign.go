package storm

import (
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/ldmonster/go-stormlib/internal/mpq"
)

// VerifyArchive result codes (StormLib.h ERROR_*_SIGNATURE_*).
const (
	VerifyNoSignature      uint32 = 0
	VerifyWeakSignatureOK  uint32 = 1
	VerifyWeakSignatureErr uint32 = 2
	// Strong signatures not yet implemented; reserved.
	VerifyStrongSignatureOK    uint32 = 3
	VerifyStrongSignatureError uint32 = 4
)

// blizzardWeakPublicKeyPEM is the Blizzard weak-signature RSA-512 public key
// embedded in StormLib (SFileVerify.cpp / szBlizzardWeakPublicKey).
const blizzardWeakPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJJidwS/uILMBSO5DLGsBFknIXWWjQJe
2kfdfEk3G/j66w4KkhZ1V61Rt4zLaMVCYpDun7FLwRjkMDSepO1q2DcCAwEAAQ==
-----END PUBLIC KEY-----`

// VerifyArchive verifies the archive's weak digital signature, mirroring
// SFileVerifyArchive (weak path only). Returns VerifyNoSignature when the archive
// has no (signature) file or the signature payload is fully zeroed.
func (a *Archive) VerifyArchive() (uint32, error) {
	sig, err := a.ReadFileByName("(signature)", 0, 0)
	if errors.Is(err, ErrFileNotFound) || errors.Is(err, errFileNotFound) {
		return VerifyNoSignature, nil
	}

	if err != nil {
		return 0, err
	}

	if len(sig) != 72 {
		return 0, fmt.Errorf("unexpected (signature) size %d", len(sig))
	}

	if isAllZeros(sig[8:]) {
		return VerifyNoSignature, nil
	}

	// Locate (signature) byte range to exclude during MD5 hashing.
	hashA := mpq.NameHashA("(signature)")
	hashB := mpq.NameHashB("(signature)")

	entry, ok := mpq.FindIndexedFileEntry(a.inner.FileIndex, hashA, hashB, 0, 0)
	if !ok {
		return VerifyNoSignature, nil
	}

	beginExclude := uint64(a.inner.Header.Offset) + uint64(entry.Block.FilePos)
	endExclude := beginExclude + uint64(entry.Block.CompressedSize)

	beginMpq := uint64(a.inner.Header.Offset)
	endMpq := beginMpq + uint64(a.inner.Header.ArchiveSize32)

	digest, err := computeArchiveMD5(a.inner.Path, beginMpq, endMpq, beginExclude, endExclude)
	if err != nil {
		return 0, err
	}

	pub, err := parseRSAPubKey(blizzardWeakPublicKeyPEM)
	if err != nil {
		return 0, err
	}

	revSig := make([]byte, 64)
	copy(revSig, sig[8:])

	for i, j := 0, len(revSig)-1; i < j; i, j = i+1, j-1 {
		revSig[i], revSig[j] = revSig[j], revSig[i]
	}

	if err := rsa.VerifyPKCS1v15(pub, crypto.MD5, digest[:], revSig); err != nil {
		return VerifyWeakSignatureErr, nil
	}

	return VerifyWeakSignatureOK, nil
}

// computeArchiveMD5 hashes the archive bytes from beginMpq to endMpq, zeroing the
// region [beginExclude, endExclude) before hashing — matching CalculateMpqHashMd5.
func computeArchiveMD5(
	path string,
	beginMpq, endMpq, beginExclude, endExclude uint64,
) ([16]byte, error) {
	var sum [16]byte

	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()

	if _, err := f.Seek(int64(beginMpq), io.SeekStart); err != nil {
		return sum, err
	}

	const chunk = 0x10000

	hasher := md5.New()
	pos := beginMpq

	buf := make([]byte, chunk)
	for pos < endMpq {
		n := uint64(chunk)
		if remaining := endMpq - pos; remaining < n {
			n = remaining
		}

		got, err := io.ReadFull(f, buf[:n])
		if err != nil && err != io.ErrUnexpectedEOF {
			return sum, err
		}
		// Zero the (signature) overlap inside [pos, pos+got).
		end := pos + uint64(got)
		if beginExclude < end && endExclude > pos {
			s := uint64(0)
			if beginExclude > pos {
				s = beginExclude - pos
			}

			e := uint64(got)
			if endExclude < end {
				e = endExclude - pos
			}

			for k := s; k < e; k++ {
				buf[k] = 0
			}
		}

		hasher.Write(buf[:got])

		pos = end
	}

	copy(sum[:], hasher.Sum(nil))

	return sum, nil
}

func parseRSAPubKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rk, nil
}

func isAllZeros(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}

	return true
}

// errFileNotFound is a package-internal sentinel used when internal/archive
// wraps a file-not-found error that needs to be matched at the storm boundary.
var errFileNotFound = errors.New("file not found (internal)")

// keep binary import live (unused otherwise in some build paths).
var _ = binary.LittleEndian

// blizzardStrongPublicKeyPEM is the Blizzard strong-signature RSA-2048 public
// key embedded in StormLib (SFileVerify.cpp / szBlizzardStrongPublicKey).
const blizzardStrongPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsQZ+ziT2h8h+J/iMQpgd
tH1HaJzOBE3agjU4yMPcrixaPOZoA4t8bwfey7qczfWywocYo3pleytFF+IuD4HD
Fl9OXN1SFyupSgMx1EGZlgbFAomnbq9MQJyMqQtMhRAjFgg4TndS7YNb+JMSAEKp
kXNqY28n/EVBHD5TsMuVCL579gIenbr61dI92DDEdy790IzIG0VKWLh/KOTcTJfm
Ds/7HQTkGouVW+WUsfekuqNQo7ND9DBnhLjLjptxeFE2AZqYcA1ao3S9LN3GL1tW
lVXFIX9c7fWqaVTQlZ2oNsI/ARVApOK3grNgqvwH6YoVYVXjNJEo5sQJsPsdV/hk
dwIDAQAB
-----END PUBLIC KEY-----`

// Additional Blizzard strong-signature public keys (SFileVerify.cpp).
const warcraft3MapPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1BwklUUQ3UvjizOBRoF5
yyOVc7KD+oGOQH5i6eUk1yfs0luCC70kNucNrfqhmviywVtahRse1JtXCPrx2bd3
iN8Dx91fbkxjYIOGTsjYoHKTp0BbaFkJih776fcHgnFSb+7mJcDuJVvJOXxEH6w0
1vo6VtujCqj1arqbyoal+xtAaczF3us5cOEp45sR1zAWTn1+7omN7VWV4QqJPaDS
gBSESc0l1grO0i1VUSumayk7yBKIkb+LBvcG6WnYZHCi7VdLmaxER5m8oZfER66b
heHoiSQIZf9PAY6Guw2DT5BTc54j/AaLQAKf2qcRSgQLVo5kQaddF3rCpsXoB/74
6QIDAQAB
-----END PUBLIC KEY-----`

const wowPatchPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwOsMV0LagAWPEtEQM6b9
6FHFkUyGbbyda2/Dfc9dyl21E9QvX+Yw7qKRMAKPzA2TlQQLZKvXpnKXF/YIK5xa
5uwg9CEHCEAYolLG4xn0FUOE0E/0PuuytI0p0ICe6rk00PifZzTr8na2wI/l/GnQ
bvnIVF1ck6cslATpQJ5JJVMXzoFlUABS19WESw4MXuJAS3AbMhxNWdEhVv7eO51c
yGjRLy9QjogZODZTY0fSEksgBqQxNCoYVJYI/sF5K2flDsGqrIp0OdJ6teJlzg1Y
UjYnb6bKjlidXoHEXI2TgA/mD6O3XFIt08I9s3crOCTgICq7cgX35qrZiIVWZdRv
TwIDAQAB
-----END PUBLIC KEY-----`

const wowSurveyPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnIt1DR6nRyyKsy2qahHe
MKLtacatn/KxieHcwH87wLBxKy+jZ0gycTmJ7SaTdBAEMDs/V5IPIXEtoqYnid2c
63TmfGDU92oc3Ph1PWUZ2PWxBhT06HYxRdbrgHw9/I29pNPi/607x+lzPORITOgU
BR6MR8au8HsQP4bn4vkJNgnSgojh48/XQOB/cAln7As1neP61NmVimoLR4Bwi3zt
zfgrZaUpyeNCUrOYJmH09YIjbBySTtXOUidoPHjFrMsCWpr6xs8xbETbs7MJFL6a
vcUfTT67qfIZ9RsuKfnXJTIrV0kwDSjjuNXiPTmWAehSsiHIsrUXX5RNcwsSjClr
nQIDAQAB
-----END PUBLIC KEY-----`

const starcraft2MapPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmk4GT8zb+ICC25a17KZB
q/ygKGJ2VSO6IT5PGHJlm1KfnHBA4B6SH3xMlJ4c6eG2k7QevZv+FOhjsAHubyWq
2VKqWbrIFKv2ILc2RfMn8J9EDVRxvcxh6slRrVL69D0w1tfVGjMiKq2Fym5yGoRT
E7CRgDqbAbXP9LBsCNWHiJLwfxMGzHbk8pIl9oia5pvM7ofZamSHchxlpy6xa4GJ
7xKN01YCNvklTL1D7uol3wkwcHc7vrF8QwuJizuA5bSg4poEGtH62BZOYi+UL/z0
31YK+k9CbQyM0X0pJoJoYz1TK+Y5J7vBnXCZtfcTYQ/ZzN6UcxTa57dJaiOlCh9z
nQIDAQAB
-----END PUBLIC KEY-----`

const (
	mpqStrongSigSize  = 256
	mpqStrongSigMagic = 0x5349474e // 'NGIS'
)

// VerifyArchiveStrong checks for a Blizzard strong RSA-2048/SHA-1 signature
// stored after the MPQ data block (ExtraBytes >= 260 with 'NGIS' magic).
// Returns VerifyNoSignature when no strong signature trailer is present.
func (a *Archive) VerifyArchiveStrong() (uint32, error) {
	beginMpq := uint64(a.inner.Header.Offset)

	endMpq := beginMpq + uint64(a.inner.Header.ArchiveSize32)
	if a.inner.Header.FormatVersion >= 2 && a.inner.Header.ArchiveSize64 != 0 {
		endMpq = beginMpq + a.inner.Header.ArchiveSize64
	}

	f, err := os.Open(a.inner.Path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return 0, err
	}

	fileSize := uint64(st.Size())
	if fileSize < endMpq+mpqStrongSigSize+4 {
		return VerifyNoSignature, nil
	}

	trailer := make([]byte, mpqStrongSigSize+4)
	if _, err := f.ReadAt(trailer, int64(endMpq)); err != nil {
		return 0, err
	}

	if binary.LittleEndian.Uint32(trailer[0:4]) != mpqStrongSigMagic {
		return VerifyNoSignature, nil
	}

	rawSig := trailer[4:]

	// SHA-1 over [beginMpq, endMpq).
	if _, err := f.Seek(int64(beginMpq), io.SeekStart); err != nil {
		return 0, err
	}

	h := sha1.New()
	if _, err := io.CopyN(h, f, int64(endMpq-beginMpq)); err != nil {
		return 0, err
	}

	digest := h.Sum(nil)

	// Build padded_digest (256 bytes): 0x0b || 0xbb*235 || sha1_reversed.
	padded := make([]byte, mpqStrongSigSize)

	padded[0] = 0x0b
	for i := 1; i < mpqStrongSigSize-sha1.Size; i++ {
		padded[i] = 0xbb
	}

	for i := 0; i < sha1.Size; i++ {
		padded[mpqStrongSigSize-1-i] = digest[i]
	}

	// Reverse the on-disk signature bytes.
	revSig := make([]byte, mpqStrongSigSize)
	for i := 0; i < mpqStrongSigSize; i++ {
		revSig[mpqStrongSigSize-1-i] = rawSig[i]
	}

	// Try each known Blizzard strong-signature key in turn.
	keys := []string{
		blizzardStrongPublicKeyPEM,
		warcraft3MapPublicKeyPEM,
		wowPatchPublicKeyPEM,
		wowSurveyPublicKeyPEM,
		starcraft2MapPublicKeyPEM,
	}
	sigInt := new(big.Int).SetBytes(revSig)

	for _, pemStr := range keys {
		pub, err := parseRSAPubKey(pemStr)
		if err != nil {
			return 0, err
		}

		mInt := new(big.Int).Exp(sigInt, big.NewInt(int64(pub.E)), pub.N)
		got := mInt.FillBytes(make([]byte, mpqStrongSigSize))
		match := true

		for i := 0; i < mpqStrongSigSize; i++ {
			if got[i] != padded[i] {
				match = false
				break
			}
		}

		if match {
			return VerifyStrongSignatureOK, nil
		}
	}

	return VerifyStrongSignatureError, nil
}

// keep crypto.MD5 reference live for older code paths.
var _ = crypto.MD5

// Verify result codes for header MD5 (v4).
const (
	VerifyHeaderNoMD5  uint32 = 5
	VerifyHeaderMD5OK  uint32 = 6
	VerifyHeaderMD5Err uint32 = 7
)

// VerifyHeaderMD5 verifies the v4 MPQ header MD5 stored at offset 192 against
// the MD5 of the first 192 bytes of the header (parity with
// SFileVerifyRawData / SFILE_VERIFY_MPQ_HEADER).
//
// Returns VerifyHeaderNoMD5 for archives older than v4 (no header MD5 stored).
func (a *Archive) VerifyHeaderMD5() (uint32, error) {
	if a.inner.Header.FormatVersion < 3 || a.inner.Header.HeaderSize < 208 {
		return VerifyHeaderNoMD5, nil
	}

	// All-zero stored MD5 means the field was never populated.
	if isAllZeros(a.inner.Header.MPQHeaderMD5[:]) {
		return VerifyHeaderNoMD5, nil
	}

	got := md5.Sum(a.inner.Header.HeaderHashRegion[:])
	for i := 0; i < md5.Size; i++ {
		if got[i] != a.inner.Header.MPQHeaderMD5[i] {
			return VerifyHeaderMD5Err, nil
		}
	}

	return VerifyHeaderMD5OK, nil
}

// VerifyHashTableMD5 verifies the v4 stored MD5 of the hash table block.
// Returns VerifyHeaderNoMD5 when the archive has no v4 raw-MD5 metadata or
// the field is zeroed.
func (a *Archive) VerifyHashTableMD5() (uint32, error) {
	if a.inner.Header.HeaderSize < 208 {
		return VerifyHeaderNoMD5, nil
	}

	if isAllZeros(a.inner.Header.MD5HashTable[:]) {
		return VerifyHeaderNoMD5, nil
	}

	size := a.inner.Header.HashTableSize64
	if size == 0 {
		size = uint64(a.inner.Header.HashTableSize) * 16
	}

	if size == 0 {
		return VerifyHeaderNoMD5, nil
	}

	pos := uint64(
		a.inner.Header.Offset,
	) + (uint64(a.inner.Header.HashTablePosHi)<<32 | uint64(a.inner.Header.HashTablePos))

	return verifyRangeMD5(a.inner.Path, pos, size, a.inner.Header.MD5HashTable[:])
}

// VerifyBlockTableMD5 verifies the v4 stored MD5 of the block table block.
func (a *Archive) VerifyBlockTableMD5() (uint32, error) {
	if a.inner.Header.HeaderSize < 208 {
		return VerifyHeaderNoMD5, nil
	}

	if isAllZeros(a.inner.Header.MD5BlockTable[:]) {
		return VerifyHeaderNoMD5, nil
	}

	size := a.inner.Header.BlockTableSize64
	if size == 0 {
		size = uint64(a.inner.Header.BlockTableSize) * 16
	}

	if size == 0 {
		return VerifyHeaderNoMD5, nil
	}

	pos := uint64(
		a.inner.Header.Offset,
	) + (uint64(a.inner.Header.BlockTablePosHi)<<32 | uint64(a.inner.Header.BlockTablePos))

	return verifyRangeMD5(a.inner.Path, pos, size, a.inner.Header.MD5BlockTable[:])
}

func verifyRangeMD5(path string, pos, size uint64, want []byte) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return 0, err
	}

	if pos+size > uint64(st.Size()) {
		return VerifyHeaderMD5Err, nil
	}

	h := md5.New()

	if _, err := f.Seek(int64(pos), io.SeekStart); err != nil {
		return 0, err
	}

	if _, err := io.CopyN(h, f, int64(size)); err != nil {
		return 0, err
	}

	got := h.Sum(nil)
	for i := 0; i < md5.Size; i++ {
		if got[i] != want[i] {
			return VerifyHeaderMD5Err, nil
		}
	}

	return VerifyHeaderMD5OK, nil
}
