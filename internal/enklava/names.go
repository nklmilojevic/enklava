package enklava

import (
	"os"
	"os/exec"
	"strings"
)

// MachineName is the Mac's local host name, made safe for a key title.
func (t Tools) MachineName() string {
	name, err := exec.Command(t.Scutil, "--get", "LocalHostName").Output()
	if err == nil {
		return SafeName(strings.TrimRight(string(name), "\n"))
	}
	host, _ := os.Hostname()
	host, _, _ = strings.Cut(host, ".")
	return SafeName(host)
}

// SafeName replaces everything but ASCII letters, digits and dashes with a
// dash. An empty name becomes "mac".
func SafeName(name string) string {
	if name == "" {
		return "mac"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		default:
			return '-'
		}
	}, name)
}

// KeyTitle is the default GitHub title of a key: the machine and the start
// of the fingerprint, so keys from different Macs are told apart.
func KeyTitle(machine, fingerprint string) string {
	short := strings.TrimPrefix(fingerprint, "SHA256:")
	short = short[:min(12, len(short))]
	return "enklava-" + machine + "-" + strings.NewReplacer("/", "-", "+", "-").Replace(short)
}

// AllowedSigners is the content of a Git allowed_signers file: the extra
// lines, then the principals for the key, when there is one.
func AllowedSigners(extras, principals []string, algo, body string) string {
	var b strings.Builder
	for _, extra := range extras {
		b.WriteString(extra + "\n")
	}
	if algo != "" {
		b.WriteString(strings.Join(principals, ",") + " " + algo + " " + body + "\n")
	}
	return b.String()
}

// Expand resolves a leading ~/ to the home directory.
func Expand(path string) string {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		home, _ := os.UserHomeDir()
		return home + "/" + rest
	}
	return path
}
