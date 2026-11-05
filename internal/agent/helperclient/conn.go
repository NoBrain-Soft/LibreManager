package helperclient

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/common/framing"
)

// conn reads length-prefixed frames plus SCM_RIGHTS descriptors.
//
// It mirrors framing.Conn's reader but handles failed reads: framing.Conn
// slices data[:n] before checking the error, and ReadMsgUnix returns n == -1
// when recvmsg fails (socket closed on cancellation, ECONNRESET, deadline),
// which panics. Replace with framing.Conn once that is fixed.
type conn struct {
	uc  *net.UnixConn
	buf []byte
	fds []int
}

func (c *conn) write(m proto.Message) error { return framing.Write(c.uc, m) } //nolint:wrapcheck

func (c *conn) fill() error {
	data := make([]byte, 64<<10)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, _, _, err := c.uc.ReadMsgUnix(data, oob)
	if oobn > 0 && oobn <= len(oob) {
		if msgs, perr := unix.ParseSocketControlMessage(oob[:oobn]); perr == nil {
			for i := range msgs {
				if fds, rerr := unix.ParseUnixRights(&msgs[i]); rerr == nil {
					c.fds = append(c.fds, fds...)
				}
			}
		}
	}
	if n > 0 {
		c.buf = append(c.buf, data[:n]...)
		return nil
	}
	if err != nil {
		return err //nolint:wrapcheck // keep io.EOF recognizable
	}
	return io.EOF
}

func (c *conn) read(m proto.Message) error {
	for len(c.buf) < 4 {
		if err := c.fill(); err != nil {
			return err
		}
	}
	n := binary.BigEndian.Uint32(c.buf[:4])
	if n > framing.MaxFrame {
		return framing.ErrFrameTooLarge
	}
	for uint32(len(c.buf)-4) < n { //nolint:gosec // non-negative
		if err := c.fill(); err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	err := proto.Unmarshal(c.buf[4:4+n], m)
	c.buf = append(c.buf[:0], c.buf[4+n:]...)
	if err != nil {
		return fmt.Errorf("helperclient: unmarshal: %w", err)
	}
	return nil
}

// takeFile returns the oldest received descriptor, or nil.
func (c *conn) takeFile(name string) *os.File {
	if len(c.fds) == 0 {
		return nil
	}
	fd := c.fds[0]
	c.fds = c.fds[1:]
	return os.NewFile(uintptr(fd), name) //nolint:gosec // fd from kernel
}

// close closes the socket and any descriptors not taken.
func (c *conn) close() {
	for _, fd := range c.fds {
		_ = unix.Close(fd)
	}
	c.fds = nil
	_ = c.uc.Close()
}
