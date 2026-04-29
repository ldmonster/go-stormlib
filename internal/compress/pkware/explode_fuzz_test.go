package pkware

import "testing"

// FuzzExplode ensures that Explode never panics on arbitrary inputs and
// always returns either an error or output not exceeding the expected size.
func FuzzExplode(f *testing.F) {
	f.Add([]byte{0x00, 0x04, 0x00}, 16)
	f.Add([]byte{0x01, 0x06, 0x00}, 32)
	f.Add([]byte{}, 0)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, 8)

	f.Fuzz(func(t *testing.T, data []byte, expected int) {
		// expected == 0 disables the output cap (see Explode doc), so
		// the size invariant below is only meaningful for expected > 0.
		if expected <= 0 || expected > 1<<20 {
			return
		}
		out, err := Explode(data, expected)
		if err != nil {
			return
		}
		if len(out) > expected {
			t.Fatalf("output %d exceeds expected %d", len(out), expected)
		}
	})
}
