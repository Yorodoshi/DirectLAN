package httpsrelay

import (
	"bytes"
	"testing"
)

func TestPaddingPreservesCiphertext(t *testing.T) {
	data := bytes.Repeat([]byte{0xa6}, 1420)
	for range 32 {
		frame, err := encode(data, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(frame)%256 != 0 || len(frame) > MaxFrame {
			t.Fatal("invalid padded length")
		}
		decoded, err := decode(frame)
		if err != nil || !bytes.Equal(decoded, data) {
			t.Fatalf("ciphertext changed: %v", err)
		}
	}
	if _, err := decode([]byte{255, 255, 1}); err == nil {
		t.Fatal("oversized declared payload accepted")
	}
}
