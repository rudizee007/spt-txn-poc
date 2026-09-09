//go:build unix

package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGenerate_PermissionsUnderAHostileUmask: open(2) applies the umask, so a
// 0777 umask creates every file 0000 and every directory 0000. The modes on
// disk must still be exactly what the code asked for, which only the restated
// Chmod can achieve. Run in-process: umask is per-process and the package's
// tests do not run in parallel.
func TestGenerate_PermissionsUnderAHostileUmask(t *testing.T) {
	// Every directory this test needs is created BEFORE the umask goes hostile.
	// t.TempDir() itself calls mkdir, and under umask 0777 that yields a
	// directory of mode 0000 which a normal user then cannot enter -- the
	// nested mkdir fails with EACCES and the test dies in setup.
	//
	// This ordering bug did not show up in CI or in any container run, because
	// root bypasses the permission check and creates the child happily. It
	// failed the first time the suite was run by a human on their own machine.
	// Anything that depends on a mode being ENFORCED (rather than merely
	// recorded) is untestable as root; keep such setup out of the hostile
	// window entirely rather than relying on the uid that happens to run it.
	probeDir := t.TempDir()
	outParents := [2]string{t.TempDir(), t.TempDir()}

	old := syscall.Umask(0o777)
	defer syscall.Umask(old)

	// Anti-vacuity: under this umask a plain OpenFile does NOT yield the mode
	// asked for, so an exact match below is the Chmod's doing.
	probe := filepath.Join(probeDir, "probe")
	f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if st, _ := os.Stat(probe); st.Mode().Perm() != 0 {
		t.Fatalf("umask 0777 not in effect: probe mode %o", st.Mode().Perm())
	}

	for i, cfg := range []config{mcpConfig(""), a2aConfig("")} {
		out := filepath.Join(outParents[i], "deploy")
		cfg.OutDir = out
		g := &generator{cfg: cfg, now: fixedNow, rand: rand.Reader}
		if _, err := g.run(); err != nil {
			t.Fatalf("%s: %v", cfg.Profile, err)
		}
		want := map[string]os.FileMode{
			fileLogKey: 0o600, filePublicationKey: 0o600,
			fileIssuerPub: 0o644, filePublicationPub: 0o644, fileRegistry: 0o644,
			fileManifest: 0o644, filePolicy: 0o644, fileREADME: 0o644,
			fileRunScript: 0o700,
		}
		if cfg.Profile == profileMCP {
			want[fileMintScript] = 0o700
		}
		if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o700 {
			t.Errorf("%s: directory mode %o (err=%v), want 0700", cfg.Profile, st.Mode().Perm(), err)
		}
		for name, mode := range want {
			st, err := os.Stat(filepath.Join(out, name))
			if err != nil {
				t.Fatalf("%s: %v", cfg.Profile, err)
			}
			if got := st.Mode().Perm(); got != mode {
				t.Errorf("%s: %s mode %o, want %o", cfg.Profile, name, got, mode)
			}
		}
	}
}

// signalChildEnv marks the re-executed test binary that plays the interrupted
// installer in TestGenerate_InterruptRemovesTheTemporaryDirectory.
const signalChildEnv = "SPT_TXN_INIT_TEST_SIGNAL_CHILD"

// TestGenerate_InterruptRemovesTheTemporaryDirectory: SIGINT mid-generation,
// after the private keys are on disk, leaves nothing behind and the process
// dies by SIGINT (the handler re-raises rather than swallowing it).
//
// Go's default SIGINT handler exits without running deferred functions, so
// the error-path cleanup (I-14) says nothing about this path. The installer is
// run as a child process — this test binary re-executed in child mode — that
// blocks just before writing run.sh, reports the temporary directory it has
// filled so far, and is then interrupted.
func TestGenerate_InterruptRemovesTheTemporaryDirectory(t *testing.T) {
	if parent := os.Getenv(signalChildEnv); parent != "" {
		signalChild(parent)
		return
	}

	parent := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestGenerate_InterruptRemovesTheTemporaryDirectory$", "-test.v")
	cmd.Env = append(os.Environ(), signalChildEnv+"="+parent)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Wait for the child to say the keys are on disk and where.
	var tmp string
	sc := bufio.NewScanner(stdout)
	deadline := time.After(20 * time.Second)
	ready := make(chan string, 1)
	go func() {
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "ready ") {
				ready <- strings.TrimPrefix(line, "ready ")
				return
			}
		}
		ready <- ""
	}()
	select {
	case tmp = <-ready:
	case <-deadline:
		_ = cmd.Process.Kill()
		t.Fatal("child never reported ready")
	}
	if tmp == "" {
		_ = cmd.Process.Kill()
		t.Fatal("child exited before reporting ready")
	}
	// Anti-vacuity: at this instant the temporary directory exists and holds
	// the private keys — the thing the interrupt must remove.
	for _, name := range expectedPrivateFiles(t) {
		if _, err := os.Stat(filepath.Join(tmp, name)); err != nil {
			t.Fatalf("before the interrupt, %s is not on disk: %v", name, err)
		}
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()

	// Died by SIGINT, not by exiting with some status.
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		t.Fatalf("child did not fail: %v", waitErr)
	}
	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGINT {
		t.Fatalf("child exit: %v (signaled=%v signal=%v); want killed by SIGINT", waitErr, ws.Signaled(), ws.Signal())
	}

	// And nothing is left: not the temporary directory, not the output.
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary directory survived the interrupt (err=%v)", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("left behind after SIGINT: %s", e.Name())
	}
}

// signalChild is the interrupted installer. It never returns normally: it is
// killed by the parent's signal, and if that does not happen within the sleep
// it exits with a status the parent will not accept.
func signalChild(parent string) {
	out := filepath.Join(parent, "deploy")
	g := &generator{cfg: mcpConfig(out), now: time.Now(), rand: rand.Reader,
		beforeWrite: func(rel string) error {
			if rel != fileRunScript {
				return nil
			}
			// Every key is on disk by now. Find the temporary directory the
			// way an operator would, say so, and wait to be interrupted.
			tmps, _ := filepath.Glob(filepath.Join(parent, ".spt-txn-init-*"))
			if len(tmps) != 1 {
				os.Exit(3)
			}
			os.Stdout.WriteString("ready " + tmps[0] + "\n")
			time.Sleep(30 * time.Second)
			os.Exit(4)
			return nil
		}}
	_, _ = g.run()
	os.Exit(5)
}
