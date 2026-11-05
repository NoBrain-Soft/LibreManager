package inventory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nobrain-soft/libremanager/internal/pki"
	agentv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/agent/v1"
)

func TestServices(t *testing.T) {
	s, err := debianCollector(t).Services(context.Background())
	sl := section[*agentv1.ServiceList](t, s, err)
	var got []string
	for _, u := range sl.GetUnits() {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%s|%s", u.GetName(), u.GetLoadState(), u.GetActiveState(), u.GetSubState(), u.GetUnitFileState(), u.GetDescription()))
	}
	want := []string{
		"apache2.service||inactive|dead|disabled|",
		"cron.service|loaded|active|running|enabled|Regular background program processing daemon",
		"ghost.service|not-found|inactive|dead||ghost.service",
		"nginx.service|loaded|failed|failed|enabled|A high performance web server",
		"ssh.service|loaded|active|running|enabled|OpenBSD Secure Shell server",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("units:\n%s", strings.Join(got, "\n"))
	}
	t.Run("not systemd", func(t *testing.T) {
		c := &Collector{Root: t.TempDir(), Exec: &fakeRunner{}, Logger: discard}
		if _, err := c.Services(context.Background()); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("list-units fails", func(t *testing.T) {
		c := debianCollector(t)
		c.Exec = &fakeRunner{outputs: map[string]fakeResult{cmdListUnits: {err: errors.New("dbus")}}}
		if _, err := c.Services(context.Background()); err == nil {
			t.Fatal("expected error")
		}
	})
}

type fakePriv struct {
	sudo    []string
	owners  map[string]string
	sudoErr error
}

func (f fakePriv) SudoRules(context.Context) ([]string, error) { return f.sudo, f.sudoErr }
func (f fakePriv) SocketOwners(context.Context) (map[string]string, error) {
	return f.owners, nil
}

func TestPorts(t *testing.T) {
	// Build a /proc where PID 4242 (our own) owns the tcp6 :80 socket.
	procRoot := t.TempDir()
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := os.ReadFile(filepath.Join("testdata/debian/proc/net", f))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(procRoot, "net", f), string(data))
	}
	writeFile(t, filepath.Join(procRoot, "4242", "comm"), "nginx\n")
	if err := os.MkdirAll(filepath.Join(procRoot, "4242", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	for fd, target := range map[string]string{"0": "/dev/null", "3": "socket:[50001]", "4": "socket:[99999]", "5": "pipe:[1]"} {
		if err := os.Symlink(target, filepath.Join(procRoot, "4242", "fd", fd)); err != nil {
			t.Fatal(err)
		}
	}
	c := debianCollector(t)
	c.ProcRoot = procRoot
	c.Privileged = fakePriv{owners: map[string]string{"21345": "812/sshd", "31337": "postgres", "50001": "1/systemd"}}
	s, err := c.Ports(context.Background())
	lp := section[*agentv1.ListeningPorts](t, s, err)
	var got []string
	for _, p := range lp.GetPorts() {
		got = append(got, fmt.Sprintf("%s %s:%d %s/%d", p.GetProtocol(), p.GetAddress(), p.GetPort(), p.GetProcess(), p.GetPid()))
	}
	want := []string{
		"tcp 0.0.0.0:22 sshd/812",
		"tcp 127.0.0.1:5432 postgres/0",
		"tcp6 :::22 /0",
		"tcp6 ::1:80 nginx/4242",
		"udp 127.0.0.53:53 /0",
		"udp6 fe80::250:56ff:fe00:1:546 /0",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ports:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseSockAddr(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"0100007F:0016", "127.0.0.1:22", true},
		{"00000000000000000000000001000000:01BB", "::1:443", true},
		{"0000000000000000FFFF00000F02000A:0050", "10.0.2.15:80", true},
		{"0100007F", "", false},
		{"zz00007F:0016", "", false},
		{"0100:0016", "", false},
		{"0100007F:FFFFF", "", false},
	}
	for _, tt := range tests {
		a, p, ok := parseSockAddr(tt.in)
		if ok != tt.ok || (ok && fmt.Sprintf("%s:%d", a, p) != tt.want) {
			t.Errorf("parseSockAddr(%q) = %s:%d %v", tt.in, a, p, ok)
		}
	}
}

// utmpRecord builds one 384-byte x86_64 utmp record.
func utmpRecord(typ int16, user string, sec int32) []byte {
	rec := make([]byte, utmpSize)
	binary.LittleEndian.PutUint16(rec[utmpTypeOff:], uint16(typ))
	copy(rec[utmpUserOff:utmpUserOff+utmpUserLen], user)
	binary.LittleEndian.PutUint32(rec[utmpTvSecOff:], uint32(sec))
	return rec
}

func TestUsers(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{"passwd", "group"} {
		data, _ := os.ReadFile(filepath.Join("testdata/debian/etc", f))
		writeFile(t, filepath.Join(root, "etc", f), string(data))
	}
	var wtmp []byte
	wtmp = append(wtmp, utmpRecord(utmpUserProc, "alice", 1_700_000_000)...)
	wtmp = append(wtmp, utmpRecord(8, "alice", 1_790_000_000)...) // DEAD_PROCESS: ignored
	wtmp = append(wtmp, utmpRecord(utmpUserProc, "alice", 1_750_000_000)...)
	wtmp = append(wtmp, utmpRecord(utmpUserProc, "", 1_760_000_000)...)
	wtmp = append(wtmp, utmpRecord(2, "reboot", 1_760_000_000)...)
	wtmp = append(wtmp, []byte("torn")...)
	writeFile(t, filepath.Join(root, "var/log/wtmp"), string(wtmp))
	lastlog := make([]byte, lastlogSize*2)
	binary.LittleEndian.PutUint32(lastlog[0:], 1_740_000_000) // uid 0
	writeFile(t, filepath.Join(root, "var/log/lastlog"), string(lastlog))

	c := &Collector{Root: root, Logger: discard, Privileged: fakePriv{sudo: []string{"%sudo ALL=(ALL:ALL) ALL", "alice ALL=(ALL) NOPASSWD: ALL", "bad\x00rule"}}}
	s, err := c.Users(context.Background())
	ua := section[*agentv1.UserAccounts](t, s, err)
	var got []string
	for _, u := range ua.GetUsers() {
		got = append(got, fmt.Sprintf("%s %d %d %s %v %d", u.GetName(), u.GetUid(), u.GetGid(), u.GetShell(), u.GetInteractive(), u.GetLastLoginUnix()))
	}
	want := []string{
		"root 0 0 /bin/bash true 1740000000",
		"toor 0 0 /bin/sh true 1740000000",
		"daemon 1 1 /usr/sbin/nologin false 0",
		"sync 4 65534 /bin/sync false 0",
		"svc 999 999 /bin/false false 0",
		"alice 1000 1000 /bin/bash true 1750000000",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("users:\n%s", strings.Join(got, "\n"))
	}
	var groups []string
	for _, g := range ua.GetGroups() {
		groups = append(groups, fmt.Sprintf("%s:%d:%s", g.GetName(), g.GetGid(), strings.Join(g.GetMembers(), ",")))
	}
	if strings.Join(groups, " ") != "root:0: sudo:27:alice docker:998:alice,bob alice:1000:" {
		t.Errorf("groups %v", groups)
	}
	if len(ua.GetSudoRules()) != 3 || ua.GetSudoRules()[2] != "bad rule" {
		t.Errorf("sudo %q", ua.GetSudoRules())
	}

	t.Run("no privileges, no logs", func(t *testing.T) {
		c := &Collector{Root: "testdata/debian", Logger: discard, Privileged: fakePriv{sudoErr: errors.New("helper down")}}
		s, err := c.Users(context.Background())
		ua := section[*agentv1.UserAccounts](t, s, err)
		if len(ua.GetSudoRules()) != 0 || len(ua.GetUsers()) != 6 {
			t.Fatalf("got %v", ua)
		}
	})
	t.Run("missing passwd", func(t *testing.T) {
		if _, err := (&Collector{Root: t.TempDir(), Logger: discard}).Users(context.Background()); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestScheduledTasks(t *testing.T) {
	s, err := debianCollector(t).ScheduledTasks(context.Background())
	st := section[*agentv1.ScheduledTasks](t, s, err)
	var got []string
	for _, task := range st.GetTasks() {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%s", task.GetKind(), task.GetName(), task.GetSchedule(), task.GetUser(), task.GetCommand()))
	}
	want := []string{
		"cron|/etc/cron.d/certbot:2|0 */12 * * *|root|test -x /usr/bin/certbot && perl -e 'sleep int(rand(43200))' && certbot -q renew",
		"cron|/etc/crontab:4|17 * * * *|root|cd / && run-parts --report /etc/cron.hourly",
		"cron|/etc/crontab:5|25 6 * * *|root|test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }",
		"cron|/etc/crontab:6|@reboot|root|/usr/local/bin/on-boot.sh",
		"systemd-timer|apt-daily.timer|OnCalendar=*-*-* 06,18:00:00|root|apt-daily.service",
		"systemd-timer|certbot.timer|OnCalendar=*-*-* 00,12:00:00; OnBootSec=15min; OnUnitActiveSec=1d|root|certbot.service",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("tasks:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestCronFileName(t *testing.T) {
	for name, want := range map[string]bool{
		"certbot": true, "e2scrub_all": true, "php.cron": true, ".placeholder": false,
		"x~": false, "x.dpkg-old": false, "x.rpmsave": false, "": false,
	} {
		if got := cronFileName(name); got != want {
			t.Errorf("cronFileName(%q) = %v", name, got)
		}
	}
}

// serveUnix serves h on a unix socket at path.
func serveUnix(t *testing.T, path string, h http.Handler) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func TestContainers(t *testing.T) {
	root, err := os.MkdirTemp("", "inv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	serveUnix(t, filepath.Join(root, "run/docker.sock"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" || r.URL.Query().Get("all") != "1" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, `[{"Id":"`+strings.Repeat("a", 64)+`","Names":["/web"],"Image":"nginx:1.27","State":"running","Extra":1},
			{"Id":"b1","Names":[],"Image":"busybox","State":"exited"}]`)
	}))
	serveUnix(t, filepath.Join(root, "run/podman/podman.sock"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	c := &Collector{Root: root, Logger: discard}
	s, err := c.Containers(context.Background())
	cs := section[*agentv1.Containers](t, s, err)
	var got []string
	for _, ct := range cs.GetContainers() {
		got = append(got, fmt.Sprintf("%s|%d|%s|%s|%s", ct.GetRuntime(), len(ct.GetId()), ct.GetName(), ct.GetImage(), ct.GetState()))
	}
	if strings.Join(got, "\n") != "docker|2||busybox|exited\ndocker|64|web|nginx:1.27|running" {
		t.Fatalf("containers:\n%s", strings.Join(got, "\n"))
	}
	t.Run("no sockets", func(t *testing.T) {
		s, err := (&Collector{Root: t.TempDir(), Logger: discard}).Containers(context.Background())
		if cs := section[*agentv1.Containers](t, s, err); len(cs.GetContainers()) != 0 {
			t.Fatal("expected no containers")
		}
	})
}

func TestSSHHostKeys(t *testing.T) {
	s, err := debianCollector(t).SSHHostKeys(context.Background())
	keys := section[*agentv1.SshHostKeys](t, s, err)
	var got []string
	for _, k := range keys.GetKeys() {
		got = append(got, k.GetType()+" "+k.GetFingerprintSha256())
	}
	// Expected values computed independently (Python hashlib) from the
	// fixture blobs; the RSA file has a mismatched type and DSA is invalid.
	want := []string{
		"ecdsa-sha2-nistp256 SHA256:zS9hnzWeppM32oaZEwFAEXagQOJYmxUFy9OmfOm9QTI",
		"ssh-ed25519 SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("keys:\n%s", strings.Join(got, "\n"))
	}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCert(t *testing.T, cn string, isCA bool, parent *testCA, notAfter time.Time) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(1_700_000_000, 0),
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if !isCA {
		tmpl.DNSNames = []string{cn, "www." + cn}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key}
}

func pemOf(certs ...*testCA) string {
	var b strings.Builder
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
	}
	return b.String()
}

func TestCertificates(t *testing.T) {
	root := t.TempDir()
	ca := newCert(t, "Test Root", true, nil, time.Unix(2_000_000_000, 0))
	inter := newCert(t, "Test Intermediate", true, ca, time.Unix(1_950_000_000, 0))
	leaf := newCert(t, "example.com", false, inter, time.Unix(1_810_000_000, 0))
	local := newCert(t, "localhost", false, nil, time.Unix(1_900_000_000, 0))
	le := filepath.Join(root, "etc/letsencrypt/live/example.com")
	writeFile(t, filepath.Join(le, "cert.pem"), pemOf(leaf))
	writeFile(t, filepath.Join(le, "chain.pem"), pemOf(inter))
	writeFile(t, filepath.Join(le, "fullchain.pem"), pemOf(leaf, inter))
	writeFile(t, filepath.Join(le, "privkey.pem"), "-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----\n")
	writeFile(t, filepath.Join(le, "README"), "not a cert")
	certsDir := filepath.Join(root, "etc/pki/tls/certs")
	writeFile(t, filepath.Join(certsDir, "localhost.crt"), pemOf(local))
	writeFile(t, filepath.Join(certsDir, "ca-bundle.crt"), pemOf(ca))
	var bundle []*testCA
	for range maxCertsPerFile + 1 {
		bundle = append(bundle, ca)
	}
	writeFile(t, filepath.Join(certsDir, "bundle.pem"), pemOf(bundle...))
	writeFile(t, filepath.Join(certsDir, "garbage.pem"), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	writeFile(t, filepath.Join(certsDir, "a/b/c/d/deep.pem"), pemOf(local))
	if err := syscall.Mkfifo(filepath.Join(certsDir, "fifo.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "etc/ssl/certs/system.pem"), pemOf(ca))

	c := &Collector{Root: root, Logger: discard, CertDirs: []string{"/etc/letsencrypt/live", "/etc/pki/tls/certs", "/etc/ssl/certs", "/nonexistent"}}
	done := make(chan struct{})
	var cs *agentv1.Certificates
	go func() {
		defer close(done)
		s, err := c.Certificates(context.Background())
		cs = section[*agentv1.Certificates](t, s, err)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("certificate scan blocked (FIFO?)")
	}
	var got []string
	for _, cert := range cs.GetCertificates() {
		got = append(got, fmt.Sprintf("%s|%s|%s|%v|%d", cert.GetPath(), cert.GetSubject(), cert.GetIssuer(), cert.GetDnsNames(), cert.GetNotAfterUnix()))
	}
	want := []string{
		"/etc/letsencrypt/live/example.com/cert.pem|CN=example.com|CN=Test Intermediate|[example.com www.example.com]|1810000000",
		"/etc/pki/tls/certs/localhost.crt|CN=localhost|CN=localhost|[localhost www.localhost]|1900000000",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("certs:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if fp := cs.GetCertificates()[0].GetSha256Fingerprint(); fp != pki.Fingerprint(leaf.cert) {
		t.Fatalf("fingerprint %s", fp)
	}
}

func TestAgentSection(t *testing.T) {
	c := &Collector{AgentVersion: "v9", HelperAvailable: true, Policy: &agentv1.PolicySummary{Metrics: true, ShellAllowedUsers: []string{"ops", "bad\xff"}}}
	s, err := c.Agent(context.Background())
	a := section[*agentv1.AgentInfo](t, s, err)
	if a.GetVersion() != "v9" || !a.GetHelperAvailable() || !a.GetPolicy().GetMetrics() || a.GetPolicy().GetShellAllowedUsers()[1] != "bad\uFFFD" {
		t.Fatalf("agent = %v", a)
	}
	if c.Policy.ShellAllowedUsers[1] != "bad\xff" {
		t.Fatal("caller's policy was modified")
	}
}

func TestCollectAll(t *testing.T) {
	c := debianCollector(t)
	r1, err := c.CollectAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r1.GetCollectedAtMs() != 1_800_000_000_000 {
		t.Fatalf("collected_at %d", r1.GetCollectedAtMs())
	}
	kinds := map[string]bool{}
	for _, s := range r1.GetSections() {
		kinds[fmt.Sprintf("%T", s.GetData())] = true
		section[proto.Message](t, s, nil)
	}
	if len(kinds) != 12 {
		t.Fatalf("got %d section kinds: %v", len(kinds), kinds)
	}
	size := proto.Size(r1)
	if size > 4<<20 {
		t.Fatalf("report is %d bytes", size)
	}
	// Collecting again yields identical hashes (deterministic ordering).
	r2, _ := c.CollectAll(context.Background())
	for i := range r1.GetSections() {
		if string(r1.GetSections()[i].GetHash()) != string(r2.GetSections()[i].GetHash()) {
			t.Fatalf("section %T hash not stable", r1.GetSections()[i].GetData())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.CollectAll(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

func TestReportBoundedOnPathologicalHost(t *testing.T) {
	var dpkg strings.Builder
	long := strings.Repeat("x", 300)
	for i := range 40000 {
		fmt.Fprintf(&dpkg, "Package: pkg-%d-%s\xff\nStatus: install ok installed\nArchitecture: amd64\nSource: src-%d-%s (9:%s)\nVersion: 1:%d.0-%s\n\n", i, long, i, long, long, i, long)
	}
	var passwd, group strings.Builder
	for i := range 10000 {
		fmt.Fprintf(&passwd, "user%d%s:x:%d:%d:%s:/home/%s:/bin/bash\n", i, long[:20], i, i, long, long)
		fmt.Fprintf(&group, "group%d:x:%d:%s\n", i, i, strings.Repeat("member,", 300))
	}
	root := writeTree(t, map[string]string{
		"etc/os-release":      "ID=debian\nVERSION_ID=12\n",
		"var/lib/dpkg/status": dpkg.String(),
		"etc/passwd":          passwd.String(),
		"etc/group":           group.String(),
	})
	c := &Collector{Root: root, Logger: discard, Exec: &fakeRunner{}, ContainerSockets: []ContainerSocket{}, CertDirs: []string{},
		InterfaceAddrs: func() (map[string][]string, error) { return nil, nil }}
	r, err := c.CollectAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if size := proto.Size(r); size > 4<<20-64<<10 {
		t.Fatalf("report is %d bytes", size)
	}
	if _, err := proto.Marshal(r); err != nil {
		t.Fatalf("report does not marshal: %v", err)
	}
	for _, s := range r.GetSections() {
		if pl, ok := SectionData(s).(*agentv1.PackageList); ok {
			if n := len(pl.GetPackages()); n == 0 || n >= 40000 {
				t.Fatalf("packages not bounded: %d", n)
			}
			if size := proto.Size(pl); size > budgetPackages+64<<10 {
				t.Fatalf("package section %d bytes", size)
			}
		}
	}
}
