package enklava

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// A key that is only a public-key reference has to be loaded into an agent
// before ssh-keygen can use it. enklava never touches the user's agent: it
// starts a private ssh-agent with its own binary as the command, marked by
// this variable. ssh-agent quits when that command does, and the command
// stops it as soon as it is done, so the loaded key never outlives it.
const agentEnv = "ENKLAVA_AGENT"

// InsideAgent reports whether ssh-agent started this process for mode, and
// clears the marker so the tools it runs don't inherit it.
func InsideAgent(mode string) bool {
	if os.Getenv(agentEnv) != mode {
		return false
	}
	os.Unsetenv(agentEnv)
	return true
}

func (t Tools) agentCommand(mode string, args ...string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(t.SSHAgent, append([]string{self}, args...)...)
	cmd.Env = append(os.Environ(), agentEnv+"="+mode, "SSH_SK_PROVIDER="+t.Provider)
	return cmd, nil
}

// ExecInAgent replaces this process with a private ssh-agent that runs this
// binary again in mode with args.
func (t Tools) ExecInAgent(mode string, args []string) error {
	agent, err := exec.LookPath(t.SSHAgent)
	if err != nil {
		return err
	}
	cmd, err := t.agentCommand(mode, args...)
	if err != nil {
		return err
	}
	return syscall.Exec(agent, append([]string{agent}, cmd.Args[1:]...), cmd.Env)
}

// LoadKeys adds the Secure Enclave keys to the agent in SSH_AUTH_SOCK.
func (t Tools) LoadKeys() error {
	cmd := exec.Command(t.SSHAdd, "-K")
	cmd.Env = append(os.Environ(), "SSH_SK_PROVIDER="+t.Provider)
	return cmd.Run()
}

// StopAgent stops the agent that started this process.
func StopAgent() {
	if pid, err := strconv.Atoi(os.Getenv("SSH_AGENT_PID")); err == nil && pid > 0 {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
}

// PrintAgentKeys runs inside the private agent: it loads the enclave keys
// and prints their public lines.
func (t Tools) PrintAgentKeys() int {
	defer StopAgent()
	_ = t.LoadKeys()
	cmd := exec.Command(t.SSHAdd, "-L")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return ExitStatus(cmd.Run())
}

// publicLineFromAgent is the public key line of the identity with this
// SHA256 fingerprint, read from a throwaway agent.
func (t Tools) publicLineFromAgent(sha string) (string, error) {
	cmd, err := t.agentCommand("keys")
	if err != nil {
		return "", err
	}
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	for _, line := range lines(string(out)) {
		if fp, err := t.fingerprintLine(line); err == nil && fp == sha {
			return line, nil
		}
	}
	return "", fmt.Errorf("the agent has no key %s", sha)
}
