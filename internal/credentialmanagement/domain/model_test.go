package domain

import (
	"strings"
	"testing"
)

func TestLabelBoundaries(t *testing.T) {
	for input, want := range map[string]string{"": "", " \tDevice\n ": "Device", "e\u0301": "e\u0301", strings.Repeat("字", 64): strings.Repeat("字", 64)} {
		got, err := Label(input)
		if err != nil || got != want {
			t.Fatal(input, got, err)
		}
	}
	for _, input := range []string{strings.Repeat("字", 65), "A\x00B", "A\u200dB", string([]byte{0xff})} {
		if _, err := Label(input); err == nil {
			t.Fatal("accepted invalid label")
		}
	}
}
