// Copyright 2026 go-stormlib Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package naming implements StormLib UTF-8 filename conversion (src/SMemUtf8.cpp, narrow TCHAR = UTF-8).
package naming

import (
	"errors"
	"fmt"
	"strings"
)

// StormLib-compatible flags (StormLib.h).
const (
	UTF8ReplaceInvalid uint32 = 0x01 // SFILE_UTF8_REPLACE_INVALID
	UTF8KeepInvalidFCH uint32 = 0x02 // SFILE_UTF8_KEEP_INVALID_FCH
)

const utf8InvalidCharacter rune = 0xFFFD // SFILE_UTF8_INVALID_CHARACTER

const (
	maxInvalidChars = 128

	errStormSuccess              uint32 = 0
	errNoUnicodeTranslationStorm uint32 = 1007 // StormPort.h ERROR_NO_UNICODE_TRANSLATION (non-Windows)
	errBufferOverflowStorm       uint32 = 111  // ERROR_BUFFER_OVERFLOW — decode guard
)

// ErrNoUnicodeTranslation matches StormLib ERROR_NO_UNICODE_TRANSLATION outcome for calling code.
var ErrNoUnicodeTranslation = errors.New("no unicode translation")

// FileNameSafeChars matches SMemUtf8.cpp / UTF8_IsBadFileNameCharacter.
var fileNameSafeChars = [4]uint32{
	0x00000000, 0x2BFF7BFB, 0xFFFFFFFF, 0xEFFFFFFF,
}

func isBadFileNameASCII(b byte) bool {
	if b >= 0x80 {
		return false
	}

	ch := uint32(b)

	return (fileNameSafeChars[ch/32] & (1 << (ch % 32))) == 0
}

func decodeSequence(
	pb []byte,
	bitsMask byte,
	follow int,
	minV, maxV uint32,
) (rune, int, uint32) {
	if len(pb) < 1+follow {
		return utf8InvalidCharacter, 1, errNoUnicodeTranslationStorm
	}

	acc := uint32(pb[0] & bitsMask)
	for i := 0; i < follow; i++ {
		if (pb[1+i] & 0xC0) != 0x80 {
			return utf8InvalidCharacter, 1, errNoUnicodeTranslationStorm
		}

		acc = (acc << 6) | uint32(pb[1+i]&0x3F)
	}

	if acc < minV || acc > maxV {
		return utf8InvalidCharacter, 1, errNoUnicodeTranslationStorm
	}

	return rune(acc), 1 + follow, errStormSuccess
}

// utf8DecodeCodePoint mirrors UTF8_DecodeCodePoint for narrow builds (filename check on ASCII).
func utf8DecodeCodePoint(pb []byte, flags uint32) (rune, int, uint32) {
	if len(pb) == 0 {
		return utf8InvalidCharacter, 0, errBufferOverflowStorm
	}

	b0 := pb[0]
	if b0 <= 0x7F {
		if (flags&UTF8KeepInvalidFCH) == 0 && isBadFileNameASCII(b0) {
			return utf8InvalidCharacter, 1, errNoUnicodeTranslationStorm
		}

		return rune(b0), 1, errStormSuccess
	}

	if len(pb) >= 2 && (b0&0xE0) == 0xC0 {
		return decodeSequence(pb, 0x1F, 1, 0x80, 0x7FF)
	}

	if len(pb) >= 3 && (b0&0xF0) == 0xE0 {
		return decodeSequence(pb, 0x0F, 2, 0x800, 0xFFFF)
	}

	if len(pb) >= 4 && (b0&0xF8) == 0xF0 {
		return decodeSequence(pb, 0x07, 3, 0x10000, 0x10FFFF)
	}

	return utf8InvalidCharacter, 1, errNoUnicodeTranslationStorm
}

func utf8EncodeCodePoint(cp rune) []byte {
	u := uint32(cp)
	switch {
	case u < 0x80:
		return utf8EncodeSequence(u, 0x00, 0)
	case u < 0x800:
		return utf8EncodeSequence(u, 0xC0, 1)
	case u < 0x10000:
		return utf8EncodeSequence(u, 0xE0, 2)
	case u < 0x110000:
		return utf8EncodeSequence(u, 0xF0, 3)
	default:
		return nil
	}
}

func utf8EncodeSequence(cp uint32, leading byte, follow uint32) []byte {
	out := make([]byte, follow+1)
	shift := uint(follow * 6)
	out[0] = byte(uint32(leading) | (cp >> shift))

	shift -= 6
	for i := uint32(0); i < follow; i++ {
		out[i+1] = byte(0x80 | ((cp >> shift) & 0x3F))
		shift -= 6
	}

	return out
}

func binToStrLowerHex(p []byte) string {
	const hexd = "0123456789abcdef"

	var b strings.Builder
	b.Grow(len(p) * 2)

	for _, v := range p {
		b.WriteByte(hexd[v>>4])
		b.WriteByte(hexd[v&0x0F])
	}

	return b.String()
}

func strToBinPair(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd hex length")
	}

	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := fromHexChar(s[i])

		lo := fromHexChar(s[i+1])
		if hi == 0xff || lo == 0xff {
			return nil, errors.New("invalid hex digit")
		}

		out[i/2] = hi<<4 | lo
	}

	return out, nil
}

func fromHexChar(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xff
	}
}

func flushInvalid(sb *strings.Builder, invalid []byte) {
	n := len(invalid)
	if n == 0 {
		return
	}

	if n == 1 {
		sb.WriteByte('%')
		sb.WriteString(binToStrLowerHex(invalid[:1]))

		return
	}

	sb.WriteString("%u[")
	sb.WriteString(binToStrLowerHex(invalid))
	sb.WriteByte(']')
}

func utf16IsEncodedCharSequence(s string) (int, []byte) {
	if len(s) < 4 || s[0] != '%' || s[1] != 'u' || s[2] != '[' {
		return 0, nil
	}

	i := 3

	nPairs := 0
	for i+1 < len(s) && nPairs < maxInvalidChars {
		if s[i] == ']' {
			break
		}

		nPairs++
		i += 2
	}

	if i >= len(s) || s[i] != ']' {
		return 0, nil
	}

	hexLen := nPairs * 2
	if hexLen <= 0 || 3+hexLen > len(s) {
		return 0, nil
	}

	dec, err := strToBinPair(s[3 : 3+hexLen])
	if err != nil || len(dec) != nPairs {
		return 0, nil
	}

	return 3 + hexLen + 1, dec
}

// UTF8ToFileName mirrors SMemUTF8ToFileName for StormLib narrow (UTF-8 I/O) builds.
// When invalid UTF-8 / filename-unsafe characters are escaped without REPLACE_INVALID, err reports
// ErrNoUnicodeTranslation (Storm ERROR_NO_UNICODE_TRANSLATION = 1007) while dst still holds the escaped bytes.
func UTF8ToFileName(src string, flags uint32) (string, error) {
	pb := []byte(src)

	var (
		dwErrCode  uint32
		invalidBuf [maxInvalidChars]byte
	)

	nInvalid := 0

	var out strings.Builder

	for i := 0; i < len(pb); {
		dwCodePoint, ccBytesEaten, decErr := utf8DecodeCodePoint(pb[i:], flags)

		dwErrCode = decErr
		if decErr != errStormSuccess {
			if ccBytesEaten != 1 {
				ccBytesEaten = 1
			}

			if flags&UTF8ReplaceInvalid != 0 {
				dwCodePoint = utf8InvalidCharacter
				dwErrCode = errStormSuccess
			} else {
				if nInvalid >= maxInvalidChars {
					flushInvalid(&out, invalidBuf[:nInvalid])
					nInvalid = 0
				}

				invalidBuf[nInvalid] = pb[i]
				nInvalid++
				i++

				continue
			}
		}

		i += ccBytesEaten

		flushInvalid(&out, invalidBuf[:nInvalid])
		nInvalid = 0

		out.Write(utf8EncodeCodePoint(dwCodePoint))
	}

	flushInvalid(&out, invalidBuf[:nInvalid])

	s := out.String()

	var err error
	if dwErrCode != errStormSuccess {
		err = fmt.Errorf("%w (storm %d)", ErrNoUnicodeTranslation, dwErrCode)
	}

	return s, err
}

// FileNameToUTF8 mirrors SMemFileNameToUTF8 (narrow UTF-8 build; dwFlags unused in Storm).
func FileNameToUTF8(src string) (string, error) {
	var out strings.Builder

	s := src
	for len(s) > 0 {
		if s[0] == '%' {
			if len(s) >= 3 {
				if b, e := strToBinPair(s[1:3]); e == nil && len(b) == 1 {
					out.Write(b)

					s = s[3:]

					continue
				}
			}

			if adv, dec := utf16IsEncodedCharSequence(s); adv > 0 {
				out.Write(dec)

				s = s[adv:]

				continue
			}
		}

		cp, eaten, decErr := utf8DecodeCodePoint([]byte(s), 0)
		if decErr != errStormSuccess {
			return "", ErrNoUnicodeTranslation
		}

		out.Write(utf8EncodeCodePoint(cp))

		s = s[eaten:]
	}

	return out.String(), nil
}
