// Package framing implements length-prefixed protobuf frames used on the
// agent core <-> helper unix socket, including SCM_RIGHTS fd passing.
package framing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// MaxFrame is the maximum frame payload size.
const MaxFrame = 1 << 20

// ErrFrameTooLarge is returned for frames exceeding MaxFrame.
var ErrFrameTooLarge = errors.New("framing: frame too large")

// Write writes one frame.
func Write(w io.Writer, m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("framing: marshal: %w", err)
	}
	if len(b) > MaxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b))) //nolint:gosec // bounded by MaxFrame
	copy(buf[4:], b)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("framing: write: %w", err)
	}
	return nil
}

// Read reads one frame into m.
func Read(r io.Reader, m proto.Message) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err //nolint:wrapcheck // io.EOF must stay recognizable
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return ErrFrameTooLarge
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return fmt.Errorf("framing: read: %w", err)
	}
	if err := proto.Unmarshal(b, m); err != nil {
		return fmt.Errorf("framing: unmarshal: %w", err)
	}
	return nil
}

// Conn wraps a unix socket connection and supports receiving file
// descriptors attached to frames.
type Conn struct {
	c   *net.UnixConn
	wmu sync.Mutex
	buf []byte
	fds []int
}

// NewConn wraps c.
func NewConn(c *net.UnixConn) *Conn { return &Conn{c: c} }

// Unix returns the underlying connection.
func (c *Conn) Unix() *net.UnixConn { return c.c }

// Write writes one frame.
func (c *Conn) Write(m proto.Message) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return Write(c.c, m)
}

// WriteWithFile writes one frame with f's descriptor attached via SCM_RIGHTS.
func (c *Conn) WriteWithFile(m proto.Message, f *os.File) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("framing: marshal: %w", err)
	}
	if len(b) > MaxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b))) //nolint:gosec // bounded by MaxFrame
	copy(buf[4:], b)
	oob := unix.UnixRights(int(f.Fd())) //nolint:gosec // fd fits in int
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n, oobn, err := c.c.WriteMsgUnix(buf, oob, nil)
	if err != nil {
		return fmt.Errorf("framing: write: %w", err)
	}
	if oobn != len(oob) {
		return errors.New("framing: short oob write")
	}
	if n < len(buf) {
		if _, err := c.c.Write(buf[n:]); err != nil {
			return fmt.Errorf("framing: write: %w", err)
		}
	}
	return nil
}

func (c *Conn) fill() error {
	data := make([]byte, 64<<10)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, _, _, err := c.c.ReadMsgUnix(data, oob)
	if oobn > 0 {
		msgs, perr := unix.ParseSocketControlMessage(oob[:oobn])
		if perr == nil {
			for _, m := range msgs {
				fds, rerr := unix.ParseUnixRights(&m)
				if rerr == nil {
					c.fds = append(c.fds, fds...)
				}
			}
		}
	}
	c.buf = append(c.buf, data[:n]...)
	if n == 0 && err == nil {
		return io.EOF
	}
	if err != nil && n == 0 {
		return err //nolint:wrapcheck // keep io.EOF recognizable
	}
	return nil
}

// Read reads one frame into m. Received descriptors are queued and can be
// taken with TakeFile.
func (c *Conn) Read(m proto.Message) error {
	for len(c.buf) < 4 {
		if err := c.fill(); err != nil {
			return err
		}
	}
	n := binary.BigEndian.Uint32(c.buf[:4])
	if n > MaxFrame {
		return ErrFrameTooLarge
	}
	for uint32(len(c.buf)-4) < n { //nolint:gosec // len is non-negative
		if err := c.fill(); err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	payload := c.buf[4 : 4+n]
	err := proto.Unmarshal(payload, m)
	c.buf = append(c.buf[:0], c.buf[4+n:]...)
	if err != nil {
		return fmt.Errorf("framing: unmarshal: %w", err)
	}
	return nil
}

// TakeFile returns the oldest received descriptor as *os.File, or nil.
func (c *Conn) TakeFile(name string) *os.File {
	if len(c.fds) == 0 {
		return nil
	}
	fd := c.fds[0]
	c.fds = c.fds[1:]
	return os.NewFile(uintptr(fd), name) //nolint:gosec // fd from kernel is non-negative
}

// Close closes the connection and any untaken descriptors.
func (c *Conn) Close() error {
	for _, fd := range c.fds {
		_ = unix.Close(fd)
	}
	c.fds = nil
	return c.c.Close()
}

// PeerCred returns the credentials of the connected peer (SO_PEERCRED).
func PeerCred(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("framing: %w", err)
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) //nolint:gosec // fd fits in int
	}); err != nil {
		return nil, fmt.Errorf("framing: %w", err)
	}
	if serr != nil {
		return nil, fmt.Errorf("framing: SO_PEERCRED: %w", serr)
	}
	return cred, nil
}
