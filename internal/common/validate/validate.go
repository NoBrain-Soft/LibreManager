// Package validate holds input validators shared by central (signer, API)
// and agent-side code, so both ends apply identical rules.
package validate

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	packageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_~:-]{0,127}$`)
	unitName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@\\-]{0,250}\.(service|socket|timer|target|path|mount)$`)
	accountName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	hostname    = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_.-]{0,252})$`)
	checkID     = regexp.MustCompile(`^[A-Z]{2,5}-[0-9]{3}$`)
	metricName  = regexp.MustCompile(`^stellwerk_[a-zA-Z0-9_]{1,120}$`)
	labelName   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)
	labelKey    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,62}$`)
)

// PackageName reports whether s is an acceptable package name (no leading '-').
func PackageName(s string) bool { return packageName.MatchString(s) }

// UnitName reports whether s is an acceptable systemd unit name.
func UnitName(s string) bool { return unitName.MatchString(s) }

// AccountName reports whether s is an acceptable unix account name.
func AccountName(s string) bool { return accountName.MatchString(s) }

// Hostname reports whether s looks like a hostname.
func Hostname(s string) bool { return hostname.MatchString(s) }

// CheckID reports whether s is a check id like "SSH-001".
func CheckID(s string) bool { return checkID.MatchString(s) }

// MetricName reports whether s is an acceptable agent metric name.
func MetricName(s string) bool { return metricName.MatchString(s) }

// LabelName reports whether s is an acceptable metric label name.
func LabelName(s string) bool { return labelName.MatchString(s) && !strings.HasPrefix(s, "__") }

// LabelKey reports whether s is an acceptable host label key.
func LabelKey(s string) bool { return labelKey.MatchString(s) }

// Text truncates s to max bytes on a rune boundary and replaces invalid
// UTF-8 and control characters (except tab) so it is safe to store/display.
func Text(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		if r == utf8.RuneError || (r < 0x20 && r != '\t') || r == 0x7f {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
