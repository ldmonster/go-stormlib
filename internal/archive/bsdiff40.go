package archive

import (
	"encoding/binary"
	"fmt"
)

// MPQ patch (PTCH) and Blizzard BSDIFF40 binary patch format.
// Layout matches StormLib's MPQ_PATCH_HEADER + LoadFilePatch_BSD0/ApplyFilePatch_BSD0
// (stormlib/src/SFilePatchArchives.cpp).

const (
	mpqPatchHeaderSize = 68 // sizeof(MPQ_PATCH_HEADER)
	xfrmHeaderSize     = 12 // 'XFRM' + dwXfrmBlockSize + dwPatchType

	patchSigPTCH  = 0x48435450 // 'PTCH'
	patchSigMD5   = 0x5F35444D // 'MD5_'
	patchSigXFRM  = 0x4D524658 // 'XFRM'
	patchTypeCOPY = 0x59504F43 // 'COPY'
	patchTypeBSD0 = 0x30445342 // 'BSD0'

	bsdiff40Signature = 0x3034464649445342 // "BSDIFF40" little-endian
)

type mpqPatchHeader struct {
	SizeOfPatchData uint32
	SizeBeforePatch uint32
	SizeAfterPatch  uint32
	XfrmBlockSize   uint32
	PatchType       uint32
	PayloadOffset   uint32 // offset of patch payload within the patch file = mpqPatchHeaderSize
}

func parseMPQPatchHeader(b []byte) (*mpqPatchHeader, error) {
	if len(b) < mpqPatchHeaderSize {
		return nil, fmt.Errorf("patch file too small for PTCH header")
	}

	if binary.LittleEndian.Uint32(b[0:4]) != patchSigPTCH {
		return nil, fmt.Errorf("missing PTCH signature")
	}

	if binary.LittleEndian.Uint32(b[16:20]) != patchSigMD5 {
		return nil, fmt.Errorf("missing MD5_ signature")
	}

	if binary.LittleEndian.Uint32(b[56:60]) != patchSigXFRM {
		return nil, fmt.Errorf("missing XFRM signature")
	}

	h := &mpqPatchHeader{
		SizeOfPatchData: binary.LittleEndian.Uint32(b[4:8]),
		SizeBeforePatch: binary.LittleEndian.Uint32(b[8:12]),
		SizeAfterPatch:  binary.LittleEndian.Uint32(b[12:16]),
		XfrmBlockSize:   binary.LittleEndian.Uint32(b[60:64]),
		PatchType:       binary.LittleEndian.Uint32(b[64:68]),
		PayloadOffset:   mpqPatchHeaderSize,
	}

	if h.SizeOfPatchData < mpqPatchHeaderSize {
		return nil, fmt.Errorf("PTCH dwSizeOfPatchData too small")
	}

	if h.XfrmBlockSize < xfrmHeaderSize {
		return nil, fmt.Errorf("PTCH XFRM block too small")
	}

	return h, nil
}

// applyMPQPatch applies a single PTCH patch file's content to base bytes,
// returning the patched output. Supports COPY and BSD0 patch types.
func applyMPQPatch(base, patch []byte) ([]byte, error) {
	hdr, err := parseMPQPatchHeader(patch)
	if err != nil {
		return nil, err
	}

	if uint32(len(base)) != hdr.SizeBeforePatch {
		return nil, fmt.Errorf(
			"patch source size mismatch: have %d want %d",
			len(base),
			hdr.SizeBeforePatch,
		)
	}

	cbDecompressed := hdr.SizeOfPatchData - mpqPatchHeaderSize
	cbCompressed := hdr.XfrmBlockSize - xfrmHeaderSize

	if uint32(len(patch)) < mpqPatchHeaderSize+cbCompressed {
		return nil, fmt.Errorf("patch payload truncated")
	}

	rawPayload := patch[mpqPatchHeaderSize : mpqPatchHeaderSize+cbCompressed]

	var payload []byte
	if cbCompressed < cbDecompressed {
		// Patch payload is RLE-compressed (StormLib Decompress_RLE).
		payload = make([]byte, cbDecompressed)
		decompressMPQPatchRLE(payload, rawPayload)
	} else {
		payload = rawPayload[:cbDecompressed]
	}

	switch hdr.PatchType {
	case patchTypeCOPY:
		out := make([]byte, len(payload))
		copy(out, payload)

		if uint32(len(out)) != hdr.SizeAfterPatch {
			return nil, fmt.Errorf(
				"COPY patch size mismatch: have %d want %d",
				len(out),
				hdr.SizeAfterPatch,
			)
		}

		return out, nil
	case patchTypeBSD0:
		return applyBSDIFF40(base, payload, hdr.SizeAfterPatch)
	default:
		return nil, fmt.Errorf(
			"%w: unknown patch type 0x%08x",
			ErrPatchDeltaUnsupported,
			hdr.PatchType,
		)
	}
}

// decompressMPQPatchRLE matches StormLib Decompress_RLE: a Blizzard-style
// run-length scheme prefixed by one DWORD (skipped) where each control byte
// either signals N+1 literal copies (high bit set) or N+1 zero-bytes to skip.
func decompressMPQPatchRLE(dst, src []byte) {
	for i := range dst {
		dst[i] = 0
	}

	if len(src) < 4 {
		return
	}

	src = src[4:]

	di, si := 0, 0
	for si < len(src) && di < len(dst) {
		c := src[si]
		si++

		if c&0x80 != 0 {
			n := int(c&0x7F) + 1
			for k := 0; k < n; k++ {
				if di >= len(dst) || si >= len(src) {
					return
				}

				dst[di] = src[si]
				di++
				si++
			}
		} else {
			di += int(c) + 1
		}
	}
}

// applyBSDIFF40 implements the Blizzard variant of BSDIFF40 used by StormLib
// (32-bit control entries instead of upstream's 64-bit). See
// stormlib/src/SFilePatchArchives.cpp ApplyFilePatch_BSD0.
func applyBSDIFF40(oldData, payload []byte, newSize uint32) ([]byte, error) {
	const headerSize = 32
	if len(payload) < headerSize {
		return nil, fmt.Errorf("BSDIFF40 payload too small")
	}

	sig := binary.LittleEndian.Uint64(payload[0:8])
	if sig != bsdiff40Signature {
		return nil, fmt.Errorf("BSDIFF40 signature mismatch")
	}

	ctrlBlockSize := binary.LittleEndian.Uint64(payload[8:16])
	dataBlockSize := binary.LittleEndian.Uint64(payload[16:24])
	declaredNewSize := binary.LittleEndian.Uint64(payload[24:32])

	if declaredNewSize != uint64(newSize) {
		return nil, fmt.Errorf(
			"BSDIFF40 new-size mismatch: header=%d patch-header=%d",
			declaredNewSize,
			newSize,
		)
	}

	if uint64(len(payload)) < uint64(headerSize)+ctrlBlockSize+dataBlockSize {
		return nil, fmt.Errorf("BSDIFF40 blocks truncated")
	}

	ctrl := payload[headerSize : headerSize+ctrlBlockSize]
	data := payload[headerSize+ctrlBlockSize : headerSize+ctrlBlockSize+dataBlockSize]
	extra := payload[headerSize+ctrlBlockSize+dataBlockSize:]

	out := make([]byte, newSize)

	var newOff, oldOff, dataOff, extraOff uint32

	oldSize := uint32(len(oldData))

	for newOff < newSize {
		if len(ctrl) < 12 {
			return nil, fmt.Errorf("BSDIFF40 control block truncated")
		}

		addLen := binary.LittleEndian.Uint32(ctrl[0:4])
		movLen := binary.LittleEndian.Uint32(ctrl[4:8])
		oldMov := binary.LittleEndian.Uint32(ctrl[8:12])
		ctrl = ctrl[12:]

		if newOff+addLen > newSize {
			return nil, fmt.Errorf("BSDIFF40 add overrun")
		}

		if dataOff+addLen > uint32(len(data)) {
			return nil, fmt.Errorf("BSDIFF40 data overrun")
		}

		copy(out[newOff:newOff+addLen], data[dataOff:dataOff+addLen])
		dataOff += addLen

		// Combine with old data byte-by-byte (clamped to oldSize-oldOff).
		combine := addLen
		if oldOff+combine > oldSize {
			combine = oldSize - oldOff
		}

		for i := uint32(0); i < combine; i++ {
			out[newOff+i] += oldData[oldOff+i]
		}

		newOff += addLen
		oldOff += addLen

		if newOff+movLen > newSize {
			return nil, fmt.Errorf("BSDIFF40 mov overrun")
		}

		if extraOff+movLen > uint32(len(extra)) {
			return nil, fmt.Errorf("BSDIFF40 extra overrun")
		}

		copy(out[newOff:newOff+movLen], extra[extraOff:extraOff+movLen])
		extraOff += movLen
		newOff += movLen

		// 32-bit signed-ish move (high bit toggles direction; matches StormLib).
		if oldMov&0x80000000 != 0 {
			delta := 0x80000000 - oldMov
			if delta > oldOff {
				return nil, fmt.Errorf("BSDIFF40 negative old move underflow")
			}

			oldOff -= delta
		} else {
			oldOff += oldMov
		}
	}

	if newOff != newSize {
		return nil, fmt.Errorf("BSDIFF40 size mismatch after apply: %d != %d", newOff, newSize)
	}

	return out, nil
}
