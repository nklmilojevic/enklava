package enklava

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// WriteStub writes the SSH stub for the identity with this SHA256
// fingerprint and keychain hash to key, and its public key to key.pub. When
// ssh-keygen cannot download a stub it writes a public-key reference to both
// files instead and reports that it did.
func (t Tools) WriteStub(key, sha, hex string) (reference bool, err error) {
	tmp, err := os.MkdirTemp("", "enklava")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)

	// KEYCHAIN_CERTIFICATES scopes the download to this one identity.
	download := exec.Command(t.SSHKeygen, "-w", t.Provider, "-K", "-N", "")
	download.Dir = tmp
	download.Env = append(os.Environ(), "KEYCHAIN_CERTIFICATES="+hex)
	_ = download.Run()

	pubs, _ := filepath.Glob(filepath.Join(tmp, "*.pub"))
	found := ""
	for _, pub := range pubs {
		if fp, err := t.Fingerprint(pub); err == nil && fp == sha {
			found = strings.TrimSuffix(pub, ".pub")
			break
		}
	}

	if err := os.MkdirAll(filepath.Dir(key), 0o755); err != nil {
		return false, err
	}
	if found != "" {
		if err := install(found, key, 0o600); err != nil {
			return false, err
		}
		return false, install(found+".pub", key+".pub", 0o644)
	}

	line, err := t.publicLineFromAgent(sha)
	if err != nil {
		return false, fmt.Errorf("could not read the public key of %s from ssh-keygen or ssh-agent", sha)
	}
	if err := WriteFile(key, []byte(line+"\n"), 0o600); err != nil {
		return false, err
	}
	return true, WriteFile(key+".pub", []byte(line+"\n"), 0o644)
}

func install(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return WriteFile(dst, data, mode)
}

// WriteFile writes data to path and sets its mode, whether or not the file
// existed and whatever the umask.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// PublicKey is the algorithm and key of the first line of a public key
// file, without its comment.
func PublicKey(path string) (algo, body string, err error) {
	line, err := FirstLine(path)
	if err != nil {
		return "", "", err
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", fmt.Errorf("%s is not a public key file", path)
	}
	return fields[0], fields[1], nil
}

func FirstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && line == "" {
		return "", nil
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func lines(s string) []string {
	var out []string
	for line := range strings.SplitSeq(s, "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
