// Package enklava drives the Secure Enclave through the tools macOS ships:
// sc_auth creates the identities and OpenSSH reaches them through Apple's
// ssh-keychain.dylib. No secret ever leaves the enclave; the files written
// here are a non-secret stub (or public-key reference) and its .pub.
package enklava

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Tools are the external programs enklava runs. Every path can be
// overridden through an ENKLAVA_* variable, which the tests use to swap in
// fakes.
type Tools struct {
	ScAuth    string
	SSHKeygen string
	SSHAdd    string
	SSHAgent  string
	Pbcopy    string
	Scutil    string
	GH        string
	Provider  string
}

func FromEnv() Tools {
	return Tools{
		ScAuth:    env("ENKLAVA_SC_AUTH", "/usr/sbin/sc_auth"),
		SSHKeygen: env("ENKLAVA_SSH_KEYGEN", "/usr/bin/ssh-keygen"),
		SSHAdd:    env("ENKLAVA_SSH_ADD", "/usr/bin/ssh-add"),
		SSHAgent:  env("ENKLAVA_SSH_AGENT", "/usr/bin/ssh-agent"),
		Pbcopy:    env("ENKLAVA_PBCOPY", "/usr/bin/pbcopy"),
		Scutil:    env("ENKLAVA_SCUTIL", "/usr/sbin/scutil"),
		GH:        env("ENKLAVA_GH", "gh"),
		Provider:  env("ENKLAVA_PROVIDER", "/usr/lib/ssh-keychain.dylib"),
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// output runs a command and returns its stdout. A failure carries the
// command's stderr, so callers decide whether anyone sees it.
func output(cmd *exec.Cmd) (string, error) {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return string(out), fmt.Errorf("%w: %s", err, message)
		}
		return string(out), err
	}
	return string(out), nil
}

// ExitStatus turns the result of running a child into a process exit code.
func ExitStatus(err error) int {
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exitErr) && exitErr.ExitCode() > 0:
		return exitErr.ExitCode()
	case errors.As(err, &exitErr):
		return 1
	default:
		return 127
	}
}

// Fingerprint is the SHA256 fingerprint ssh-keygen prints for a public key
// file.
func (t Tools) Fingerprint(path string) (string, error) {
	return t.fingerprint(exec.Command(t.SSHKeygen, "-lf", path))
}

func (t Tools) fingerprintLine(line string) (string, error) {
	cmd := exec.Command(t.SSHKeygen, "-lf", "/dev/stdin")
	cmd.Stdin = strings.NewReader(line + "\n")
	return t.fingerprint(cmd)
}

func (t Tools) fingerprint(cmd *exec.Cmd) (string, error) {
	out, err := output(cmd)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(out)
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected ssh-keygen output %q", out)
	}
	return fields[1], nil
}
