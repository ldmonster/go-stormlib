package archive

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildMPQPatch constructs a PTCH-format patch file wrapping the given XFRM type and payload.
// payload is stored uncompressed (cbCompressed == cbDecompressed).
func buildMPQPatch(t *testing.T, sizeBefore, sizeAfter uint32, patchType uint32, payload []byte) []byte {
	t.Helper()
	cb := uint32(len(payload))
	xfrmBlockSize := xfrmHeaderSize + cb
	sizeOfPatch := mpqPatchHeaderSize + cb

	b := make([]byte, sizeOfPatch)
	binary.LittleEndian.PutUint32(b[0:4], patchSigPTCH)
	binary.LittleEndian.PutUint32(b[4:8], sizeOfPatch)
	binary.LittleEndian.PutUint32(b[8:12], sizeBefore)
	binary.LittleEndian.PutUint32(b[12:16], sizeAfter)
	binary.LittleEndian.PutUint32(b[16:20], patchSigMD5)
	binary.LittleEndian.PutUint32(b[20:24], 40)
	// md5_before [24:40], md5_after [40:56] left as zeros.
	binary.LittleEndian.PutUint32(b[56:60], patchSigXFRM)
	binary.LittleEndian.PutUint32(b[60:64], xfrmBlockSize)
	binary.LittleEndian.PutUint32(b[64:68], patchType)
	copy(b[68:], payload)
	return b
}

func TestApplyMPQPatch_COPY(t *testing.T) {
	want := []byte("brand new contents from COPY patch")
	patch := buildMPQPatch(t, 4, uint32(len(want)), patchTypeCOPY, want)

	got, err := applyMPQPatch([]byte("base"), patch)
	if err != nil {
		t.Fatalf("applyMPQPatch: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("COPY mismatch: got %q want %q", got, want)
	}
}

func TestApplyMPQPatch_BSD0_AddOnly(t *testing.T) {
	// Construct a BSDIFF40 payload that produces newData = oldData + delta with no extra block,
	// using a single control entry that adds 5 bytes from the data block to the old prefix.
	old := []byte{1, 2, 3, 4, 5}
	delta := []byte{10, 20, 30, 40, 50}
	wantNew := make([]byte, len(old))
	for i := range old {
		wantNew[i] = old[i] + delta[i]
	}

	// Control block: addLen=5, movLen=0, oldMov=0
	ctrl := make([]byte, 12)
	binary.LittleEndian.PutUint32(ctrl[0:4], 5)
	binary.LittleEndian.PutUint32(ctrl[4:8], 0)
	binary.LittleEndian.PutUint32(ctrl[8:12], 0)

	bsdiffHeader := make([]byte, 32)
	binary.LittleEndian.PutUint64(bsdiffHeader[0:8], bsdiff40Signature)
	binary.LittleEndian.PutUint64(bsdiffHeader[8:16], uint64(len(ctrl)))
	binary.LittleEndian.PutUint64(bsdiffHeader[16:24], uint64(len(delta)))
	binary.LittleEndian.PutUint64(bsdiffHeader[24:32], uint64(len(wantNew)))

	payload := append([]byte{}, bsdiffHeader...)
	payload = append(payload, ctrl...)
	payload = append(payload, delta...)
	// no extra block

	patch := buildMPQPatch(t, uint32(len(old)), uint32(len(wantNew)), patchTypeBSD0, payload)

	got, err := applyMPQPatch(old, patch)
	if err != nil {
		t.Fatalf("applyMPQPatch BSD0: %v", err)
	}
	if !bytes.Equal(got, wantNew) {
		t.Fatalf("BSD0 mismatch: got %v want %v", got, wantNew)
	}
}

func TestApplyMPQPatch_BSD0_WithExtraBlock(t *testing.T) {
	// New file = (old[0:3] combined with delta) ++ extra("XYZ").
	old := []byte{100, 100, 100}
	delta := []byte{1, 2, 3}
	extra := []byte("XYZ")
	expected := []byte{101, 102, 103, 'X', 'Y', 'Z'}

	ctrl := make([]byte, 12)
	binary.LittleEndian.PutUint32(ctrl[0:4], 3) // addLen
	binary.LittleEndian.PutUint32(ctrl[4:8], 3) // movLen (extra block)
	binary.LittleEndian.PutUint32(ctrl[8:12], 0)

	bsdiffHeader := make([]byte, 32)
	binary.LittleEndian.PutUint64(bsdiffHeader[0:8], bsdiff40Signature)
	binary.LittleEndian.PutUint64(bsdiffHeader[8:16], uint64(len(ctrl)))
	binary.LittleEndian.PutUint64(bsdiffHeader[16:24], uint64(len(delta)))
	binary.LittleEndian.PutUint64(bsdiffHeader[24:32], uint64(len(expected)))

	payload := append([]byte{}, bsdiffHeader...)
	payload = append(payload, ctrl...)
	payload = append(payload, delta...)
	payload = append(payload, extra...)

	patch := buildMPQPatch(t, uint32(len(old)), uint32(len(expected)), patchTypeBSD0, payload)

	got, err := applyMPQPatch(old, patch)
	if err != nil {
		t.Fatalf("applyMPQPatch BSD0 extra: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("BSD0 extra mismatch: got %v want %v", got, expected)
	}
}

func TestApplyMPQPatch_RejectsSizeBeforeMismatch(t *testing.T) {
	patch := buildMPQPatch(t, 99 /* wrong */, 4, patchTypeCOPY, []byte("data"))
	_, err := applyMPQPatch([]byte("base"), patch)
	if err == nil {
		t.Fatal("expected size-before mismatch error")
	}
}
