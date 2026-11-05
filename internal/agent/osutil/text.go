package osutil

import (
	"strings"
	"unicode/utf8"
)

// Clean makes s safe for a protobuf string field and for display: invalid
// UTF-8 is replaced, control characters become spaces, and the result is
// truncated to at most max bytes on a rune boundary (max <= 0: no limit).
//
// Every string that originates from the host (file contents, command output,
// paths) must pass through Clean before it is put into a message: proto3
// marshaling fails on invalid UTF-8, which would drop the whole report.
func Clean(s string, max int) string {
	if isClean(s) {
		return truncate(s, max)
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			b.WriteRune(utf8.RuneError)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			b.WriteByte(' ')
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
		if max > 0 && b.Len() >= max+utf8.UTFMax {
			break
		}
	}
	return truncate(b.String(), max)
}

// isClean reports whether s is printable ASCII (the common case). Anything
// else takes the slow path in Clean.
func isClean(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	i := max
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
}
