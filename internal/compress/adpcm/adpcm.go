// Package adpcm implements decompression of Blizzard's ADPCM-compressed WAVE
// audio used inside MPQ archives. It is a pure-Go port of
// stormlib/src/adpcm/adpcm.cpp (DecompressADPCM only).
package adpcm

import (
	"encoding/binary"
	"errors"
)

const (
	maxChannels      = 2
	initialStepIndex = 0x2C
)

var (
	ErrInvalidChannels = errors.New("adpcm: invalid channel count")
	ErrTruncatedHeader = errors.New("adpcm: truncated header")
)

var nextStepTable = [...]int{
	-1, 0, -1, 4, -1, 2, -1, 6,
	-1, 1, -1, 5, -1, 3, -1, 7,
	-1, 1, -1, 5, -1, 3, -1, 7,
	-1, 2, -1, 4, -1, 6, -1, 8,
}

var stepSizeTable = [...]int{
	7, 8, 9, 10, 11, 12, 13, 14,
	16, 17, 19, 21, 23, 25, 28, 31,
	34, 37, 41, 45, 50, 55, 60, 66,
	73, 80, 88, 97, 107, 118, 130, 143,
	157, 173, 190, 209, 230, 253, 279, 307,
	337, 371, 408, 449, 494, 544, 598, 658,
	724, 796, 876, 963, 1060, 1166, 1282, 1411,
	1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024,
	3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484,
	7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899,
	15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794,
	32767,
}

func clampStepIndex(idx int) int {
	switch {
	case idx < 0:
		return 0
	case idx > 88:
		return 88
	default:
		return idx
	}
}

func updatePredicted(pred, encoded, diff, bitMask int) int {
	if encoded&bitMask != 0 {
		pred -= diff
		if pred <= -32768 {
			pred = -32768
		}
	} else {
		pred += diff
		if pred >= 32767 {
			pred = 32767
		}
	}

	return pred
}

// Decompress decodes a Blizzard ADPCM block. channels must be 1 or 2.
// The output is little-endian 16-bit signed PCM.
func Decompress(src []byte, channels int) ([]byte, error) {
	if channels < 1 || channels > maxChannels {
		return nil, ErrInvalidChannels
	}

	if len(src) < 2 {
		return nil, ErrTruncatedHeader
	}

	// Byte 0: zero (unused). Byte 1: bit shift = compression level - 1.
	bitShift := uint(src[1])
	pos := 2

	predicted := [maxChannels]int{}
	stepIdx := [maxChannels]int{initialStepIndex, initialStepIndex}

	out := make([]byte, 0, len(src)*4)
	writeSample := func(v int) {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(int16(v)))
		out = append(out, b[:]...)
	}

	// Initial sample per channel.
	for c := 0; c < channels; c++ {
		if pos+2 > len(src) {
			return out, nil
		}

		v := int16(binary.LittleEndian.Uint16(src[pos : pos+2]))
		pos += 2
		predicted[c] = int(v)
		writeSample(int(v))
	}

	channel := channels - 1

	for pos < len(src) {
		encoded := int(src[pos])
		pos++
		channel = (channel + 1) % channels

		switch encoded {
		case 0x80:
			if stepIdx[channel] != 0 {
				stepIdx[channel]--
			}

			writeSample(predicted[channel])
		case 0x81:
			stepIdx[channel] += 8
			if stepIdx[channel] > 0x58 {
				stepIdx[channel] = 0x58
			}
			// Mirror C: extra channel advance (keeps next sample on same channel for stereo).
			channel = (channel + 1) % channels
		default:
			si := stepIdx[channel]
			stepSize := stepSizeTable[si]

			diff := stepSize >> bitShift
			if encoded&0x01 != 0 {
				diff += stepSize >> 0
			}

			if encoded&0x02 != 0 {
				diff += stepSize >> 1
			}

			if encoded&0x04 != 0 {
				diff += stepSize >> 2
			}

			if encoded&0x08 != 0 {
				diff += stepSize >> 3
			}

			if encoded&0x10 != 0 {
				diff += stepSize >> 4
			}

			if encoded&0x20 != 0 {
				diff += stepSize >> 5
			}

			predicted[channel] = updatePredicted(predicted[channel], encoded, diff, 0x40)
			writeSample(predicted[channel])
			stepIdx[channel] = clampStepIndex(si + nextStepTable[encoded&0x1F])
		}
	}

	return out, nil
}
