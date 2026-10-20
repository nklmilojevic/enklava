// enklava-sign is Git's gpg.ssh.program: ssh-keygen with Apple's Secure
// Enclave provider. A real stub signs directly. A public-key reference needs
// the key in an agent, so it gets a private agent that dies with this
// command.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/nklmilojevic/enklava/internal/enklava"
)

func main() {
	t := enklava.FromEnv()
	os.Setenv("SSH_SK_PROVIDER", t.Provider)
	args := os.Args[1:]

	if enklava.InsideAgent("sign") {
		os.Exit(signInAgent(t, args))
	}

	var err error
	if isReference(keyFile(args)) {
		err = t.ExecInAgent("sign", args)
	} else {
		err = execKeygen(t, args)
	}
	fmt.Fprintf(os.Stderr, "enklava-sign: %v\n", err)
	os.Exit(127)
}

// keyFile is the value of the last -f argument.
func keyFile(args []string) string {
	key := ""
	for i := 1; i < len(args); i++ {
		if args[i-1] == "-f" {
			key = args[i]
		}
	}
	return key
}

// isReference reports whether key is a public-key reference rather than a
// stub: its first word is an sk- key type.
func isReference(key string) bool {
	if key == "" {
		return false
	}
	if info, err := os.Stat(key); err != nil || !info.Mode().IsRegular() {
		return false
	}
	line, err := enklava.FirstLine(key)
	if err != nil {
		return false
	}
	fields := strings.Fields(line)
	return len(fields) > 0 && strings.HasPrefix(fields[0], "sk-")
}

func execKeygen(t enklava.Tools, args []string) error {
	keygen, err := exec.LookPath(t.SSHKeygen)
	if err != nil {
		return err
	}
	return syscall.Exec(keygen, append([]string{keygen}, args...), os.Environ())
}

func signInAgent(t enklava.Tools, args []string) int {
	defer enklava.StopAgent()
	if err := t.LoadKeys(); err != nil {
		fmt.Fprintln(os.Stderr, "enklava-sign: ssh-add could not load the Secure Enclave keys")
		return 1
	}
	cmd := exec.Command(t.SSHKeygen, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return enklava.ExitStatus(cmd.Run())
}
