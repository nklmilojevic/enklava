package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeyFile(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-Y", "sign", "-n", "git", "-f", "/k", "/dev/null"}, "/k"},
		{[]string{"-f", "/a", "-f", "/b"}, "/b"},
		{[]string{"-Y", "sign", "-f"}, ""},
		{nil, ""},
	} {
		if got := keyFile(tc.args); got != tc.want {
			t.Errorf("keyFile(%q) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

func TestIsReference(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if !isReference(write("ref", "sk-ecdsa-sha2-nistp256@openssh.com AAAA ssh:\n")) {
		t.Error("a public-key reference was not recognised")
	}
	if isReference(write("stub", "fake stub for test\n")) {
		t.Error("a stub was taken for a reference")
	}
	if isReference(write("signers", "a@x sk-ecdsa-sha2-nistp256@openssh.com AAAA\n")) {
		t.Error("an allowed_signers file was taken for a reference")
	}
	if isReference(filepath.Join(dir, "missing")) || isReference(dir) {
		t.Error("a missing file or a directory was taken for a reference")
	}
}
