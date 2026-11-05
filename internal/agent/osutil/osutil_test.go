package osutil

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestClean(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"ascii", "hello", 0, "hello"},
		{"truncate ascii", "hello world", 5, "hello"},
		{"control chars", "a\nb\tc\x00d", 0, "a b c d"},
		{"invalid utf8", "a\xffb", 0, "a\uFFFDb"},
		{"utf8 kept", "Grüße", 0, "Grüße"},
		{"truncate on rune boundary", "äöü", 3, "ä"},
		{"c1 control", "a\u0085b", 0, "a b"},
		{"empty", "", 10, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Clean(tt.in, tt.max); got != tt.want {
				t.Fatalf("Clean(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

func TestReadFileLimit(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		path    string
		max     int64
		want    string
		wantErr error
	}{
		{"fits", small, 5, "12345", nil},
		{"too large", small, 4, "", ErrTooLarge},
		{"fifo never blocks", fifo, 10, "", ErrNotRegular},
		{"directory", dir, 10, "", ErrNotRegular},
		{"missing", filepath.Join(dir, "nope"), 10, "", os.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadFileLimit(tt.path, tt.max)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
	if v, err := ReadUint(small); err != nil || v != 12345 {
		t.Fatalf("ReadUint = %d, %v", v, err)
	}
}

func TestExecRunner(t *testing.T) {
	for _, tool := range []string{"echo", "env", "cat", "head", "sleep"} {
		if _, err := (ExecRunner{}).lookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	r := ExecRunner{Timeout: 5 * time.Second, MaxOutput: 64}
	ctx := context.Background()

	t.Run("argv is not shell-interpreted", func(t *testing.T) {
		out, err := r.Run(ctx, "echo", "$(id)", ";", "|")
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(out)) != "$(id) ; |" {
			t.Fatalf("out = %q", out)
		}
	})
	t.Run("clean environment", func(t *testing.T) {
		t.Setenv("STELLWERK_SECRET_TEST", "leak")
		out, err := ExecRunner{}.Run(ctx, "env")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "STELLWERK_SECRET_TEST") || !strings.Contains(string(out), "LC_ALL=C") {
			t.Fatalf("unexpected env: %s", out)
		}
	})
	t.Run("exit error keeps stdout", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "state")
		if err := os.WriteFile(f, []byte("inactive\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// cat prints the first file, then fails on the missing one.
		out, err := r.Run(ctx, "cat", f, filepath.Join(t.TempDir(), "missing"))
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() == 0 {
			t.Fatalf("err = %v", err)
		}
		if strings.TrimSpace(string(out)) != "inactive" {
			t.Fatalf("out = %q", out)
		}
	})
	t.Run("output limit", func(t *testing.T) {
		_, err := r.Run(ctx, "head", "-c", "100000", "/dev/zero")
		if !errors.Is(err, ErrOutputTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		start := time.Now()
		_, err := ExecRunner{Timeout: 200 * time.Millisecond}.Run(ctx, "sleep", "10")
		if err == nil || time.Since(start) > 5*time.Second {
			t.Fatalf("err = %v after %s", err, time.Since(start))
		}
	})
	t.Run("not found", func(t *testing.T) {
		_, err := r.Run(ctx, "definitely-not-a-command-xyz")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("relative path rejected", func(t *testing.T) {
		_, err := r.Run(ctx, "./sh")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("PATH ignored", func(t *testing.T) {
		dir := t.TempDir()
		fake := filepath.Join(dir, "stellwerk-fake-tool")
		if err := os.WriteFile(fake, []byte("#!/bin/sh\necho pwned\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir)
		if _, err := r.Run(ctx, "stellwerk-fake-tool"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestParseMountInfo(t *testing.T) {
	data := []byte(`22 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw
28 1 253:0 / / rw,relatime shared:1 - ext4 /dev/mapper/vg0-root rw,errors=remount-ro
30 28 8:1 / /boot ro,relatime shared:30 - ext4 /dev/sda1 rw
31 28 253:0 /srv/data /data rw,relatime shared:1 - ext4 /dev/mapper/vg0-root rw
32 28 0:30 / /run rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,size=814900k,mode=755
33 32 0:31 / /run/user/1000 rw,nosuid,nodev,relatime shared:250 - tmpfs tmpfs rw,size=407448k
34 28 0:32 / /dev/shm rw,nosuid,nodev shared:4 - tmpfs tmpfs rw
35 28 7:0 / /snap/core/123 ro,nodev,relatime shared:40 - squashfs /dev/loop0 ro
36 28 0:40 / /var/lib/docker/overlay2/abc/merged rw,relatime - overlay overlay rw,lowerdir=x
37 28 8:2 / /mnt/my\040disk rw,relatime shared:31 - xfs /dev/sda2 rw
38 28 0:50 / /home rw,relatime shared:32 - btrfs /dev/sdb rw,subvol=/@home
39 28 0:50 /@srv /srv rw,relatime shared:33 - btrfs /dev/sdb rw,subvol=/@srv
40 28 0:60 / /mnt/nfs rw,relatime shared:34 - nfs4 server:/export rw,vers=4.2
garbage line
41 28 8:3 / /broken rw -
`)
	mounts, err := ParseMountInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 14 {
		t.Fatalf("parsed %d mounts, want 14", len(mounts))
	}
	boot := mounts[3]
	if boot.MountPoint != "/boot" || !boot.ReadOnly() || boot.Device() != "8:1" || boot.Source != "/dev/sda1" {
		t.Fatalf("boot = %+v", boot)
	}
	if mounts[10].MountPoint != "/mnt/my disk" {
		t.Fatalf("unescape: %q", mounts[10].MountPoint)
	}

	got := SelectFilesystems(mounts, 0)
	var mps []string
	for _, m := range got {
		mps = append(mps, m.MountPoint)
	}
	want := []string{"/", "/boot", "/run", "/dev/shm", "/mnt/my disk", "/home", "/mnt/nfs"}
	if strings.Join(mps, ",") != strings.Join(want, ",") {
		t.Fatalf("selected %v, want %v", mps, want)
	}
	if got := SelectFilesystems(mounts, 2); len(got) != 2 {
		t.Fatalf("max not applied: %d", len(got))
	}
}

func TestUnescapeMount(t *testing.T) {
	tests := map[string]string{
		`plain`:         "plain",
		`a\040b`:        "a b",
		`tab\011x`:      "tab\tx",
		`back\134slash`: `back\slash`,
		`bad\09`:        `bad\09`,
		`end\04`:        `end\04`,
		`big\777`:       `big\777`,
	}
	for in, want := range tests {
		if got := UnescapeMount(in); got != want {
			t.Errorf("UnescapeMount(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePasswdGroup(t *testing.T) {
	pw := ParsePasswd([]byte(`root:x:0:0:root:/root:/bin/bash
# comment
+nisuser::::::
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bad:x:notanumber:1::/:/bin/sh
short:x:1
alice:x:1000:1000:Alice,,,:/home/alice:/bin/zsh
`), 0)
	if len(pw) != 3 || pw[2].Name != "alice" || pw[2].UID != 1000 || pw[2].Shell != "/bin/zsh" {
		t.Fatalf("passwd = %+v", pw)
	}
	if got := ParsePasswd([]byte("a:x:1:1::/:/bin/sh\nb:x:2:2::/:/bin/sh\n"), 1); len(got) != 1 {
		t.Fatalf("max not applied")
	}
	gr := ParseGroup([]byte("root:x:0:\nsudo:x:27:alice, bob\nbad:x:z:\n"), 0)
	if len(gr) != 2 || len(gr[1].Members) != 2 || gr[1].Members[1] != "bob" {
		t.Fatalf("group = %+v", gr)
	}
}

func TestGuardedStatfs(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	g := &GuardedStatfs{
		Timeout: 50 * time.Millisecond,
		Fn: func(path string) (FSStats, error) {
			calls.Add(1)
			if path == "/hung" {
				<-release
			}
			return FSStats{Blocks: 10}, nil
		},
	}
	ctx := context.Background()
	if st, err := g.Statfs(ctx, "/ok"); err != nil || st.Blocks != 10 {
		t.Fatalf("ok: %v %v", st, err)
	}
	if _, err := g.Statfs(ctx, "/hung"); !errors.Is(err, ErrStatfsTimeout) {
		t.Fatalf("hung: %v", err)
	}
	if _, err := g.Statfs(ctx, "/hung"); !errors.Is(err, ErrStatfsStuck) {
		t.Fatalf("stuck: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("calls = %d, want 2 (no second goroutine for a stuck path)", n)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := g.Statfs(ctx, "/hung")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("path never recovered: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func FuzzParseMountInfo(f *testing.F) {
	f.Add([]byte("28 1 253:0 / / rw,relatime shared:1 - ext4 /dev/mapper/vg0-root rw\n"))
	f.Add([]byte("1 2 3:4 \\040 \\134 rw - - - -\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		mounts, _ := ParseMountInfo(data)
		_ = SelectFilesystems(mounts, 10)
	})
}
