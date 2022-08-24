package linuxfw

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

func btos(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		return ""
	}
	return string(b[:n])
}

func formatMaybePrintable(b []byte) string {
	// Remove a single trailing null, if any
	if len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}

	nonprintable := strings.IndexFunc(string(b), func(r rune) bool {
		return r > unicode.MaxASCII || !unicode.IsPrint(r)
	})
	if nonprintable >= 0 {
		return "<hex>" + hex.EncodeToString(b)
	}
	return string(b)
}

func formatPortRange(r [2]uint16) string {
	if r == [2]uint16{0, 65535} {
		return fmt.Sprintf(`any`)
	} else if r[0] == r[1] {
		return fmt.Sprintf(`%d`, r[0])
	}
	return fmt.Sprintf(`%d-%d`, r[0], r[1])
}
