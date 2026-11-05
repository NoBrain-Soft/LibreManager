package collect

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/nobrain-soft/libremanager/internal/agent/osutil"
)

var (
	errNotExist  = fs.ErrNotExist
	errNoSupport = syscall.EOPNOTSUPP
	errNotDir    = syscall.ENOTDIR
)

// userHZ is USER_HZ (clock ticks per second in /proc), fixed at 100 on all
// architectures the agent supports.
const userHZ = 100.0

// Size limits for /proc files.
const (
	smallFile = 64 << 10
	largeFile = 4 << 20
)

func readProc(root string, elem ...string) ([]byte, error) {
	return osutil.ReadFileLimit(filepath.Join(append([]string{root}, elem...)...), largeFile)
}

// eachLine calls fn for every line of data.
func eachLine(data []byte, fn func(line []byte)) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		fn(sc.Bytes())
	}
}

func parseFloat(b []byte) (float64, bool) {
	v, err := strconv.ParseFloat(string(b), 64)
	return v, err == nil
}

func parseUint(b []byte) (uint64, bool) {
	v, err := strconv.ParseUint(string(b), 10, 64)
	return v, err == nil
}

// fieldsN splits like bytes.Fields but reuses dst.
func fieldsN(dst [][]byte, line []byte) [][]byte {
	dst = dst[:0]
	i := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		start := i
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		if i > start {
			dst = append(dst, line[start:i])
		}
	}
	return dst
}

func openDir(p string) (*os.File, error) { return os.Open(p) } //nolint:gosec // fixed /proc path
