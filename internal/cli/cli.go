// Package cli is the enklava command line.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/nklmilojevic/enklava/internal/enklava"
	"github.com/spf13/cobra"
)

var Version = "dev"

const usage = `Usage: enklava <command> [options]

Commands:
  ensure --key-file F --label L [--protection none|bio]
      Create the Secure Enclave identity and its SSH stub if missing.
      Prints nothing when everything is already in place.
  list
      List Secure Enclave identities available to SSH.
  pub --key-file F [--copy]
      Print (or copy) the public key.
  allowed-signers --output O [--key-file F --principal P...] [--extra LINE...]
      Write a Git allowed_signers file.
  github add --key-file F [--type signing|authentication|both] [--title T]
      Register the public key with GitHub through gh, skipping keys it has.
  doctor --key-file F --label L
      Check the tools, the identity and the stub. Exits non-zero on failure.
`

// exitCode ends the command with this status and no further message.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func fail(format string, args ...any) error { return fmt.Errorf(format, args...) }

func say(format string, args ...any) {
	fmt.Printf("enklava: "+format+"\n", args...)
}

func Execute(t enklava.Tools) int {
	root := newRoot(t)
	err := root.Execute()
	var code exitCode
	switch {
	case err == nil:
		return 0
	case errors.As(err, &code):
		return int(code)
	default:
		fmt.Fprintf(os.Stderr, "enklava: %v\n", err)
		return 1
	}
}

func newRoot(t enklava.Tools) *cobra.Command {
	root := &cobra.Command{
		Use:           "enklava",
		Short:         "Secure Enclave SSH keys and Git signing for macOS",
		Version:       Version,
		Args:          cobra.ArbitraryArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				fmt.Fprintf(os.Stderr, "enklava: unknown command %s\n\n", args[0])
			}
			fmt.Fprint(os.Stderr, usage)
			return exitCode(1)
		},
	}
	help := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd == root {
			fmt.Print(usage)
			return
		}
		help(cmd, args)
	})

	github := &cobra.Command{
		Use:   "github",
		Short: "Manage the key on GitHub",
		RunE: func(*cobra.Command, []string) error {
			return fail("usage: enklava github add --key-file F [--type T] [--title T]")
		},
	}
	github.AddCommand(githubAddCommand(t))

	root.AddCommand(
		ensureCommand(t),
		listCommand(t),
		pubCommand(t),
		allowedSignersCommand(),
		github,
		doctorCommand(t),
	)
	return root
}

func ensureCommand(t enklava.Tools) *cobra.Command {
	var key, label, protection string
	cmd := &cobra.Command{
		Use:   "ensure --key-file F --label L [--protection none|bio]",
		Short: "Create the Secure Enclave identity and its SSH stub if missing",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return ensure(t, enklava.Expand(key), label, protection)
		},
	}
	cmd.Flags().StringVar(&key, "key-file", "", "path of the SSH stub")
	cmd.Flags().StringVar(&label, "label", "", "CryptoTokenKit label of the identity")
	cmd.Flags().StringVar(&protection, "protection", "none", "none, or bio for Touch ID on every use")
	return cmd
}

func ensure(t enklava.Tools, key, label, protection string) error {
	if key == "" {
		return fail("ensure: --key-file is required")
	}
	if label == "" {
		return fail("ensure: --label is required")
	}
	if protection != "none" && protection != "bio" {
		return fail("ensure: --protection must be none or bio, not %s", protection)
	}
	keyExists, pubExists := exists(key), exists(key+".pub")
	if keyExists != pubExists {
		return fail("%s and %s.pub must both exist or both be absent", key, key)
	}

	sha, err := t.HashFor(label, "b64")
	switch {
	case errors.Is(err, enklava.ErrNoIdentity):
		if err := t.CreateIdentity(label, protection); err != nil {
			return fail("sc_auth could not create identity %s: %v", label, err)
		}
		if sha, err = t.HashFor(label, "b64"); err != nil {
			return fail("created identity %s but sc_auth does not list it", label)
		}
		say("created Secure Enclave identity %s", label)
	case err != nil:
		return err
	}

	if keyExists {
		if fp, _ := t.Fingerprint(key + ".pub"); fp != sha {
			return fail("%s.pub is not the key of identity %s (%s); move it away and run ensure again", key, label, sha)
		}
		return nil
	}

	hex, err := t.HashFor(label, "hex")
	if err != nil {
		return fail("could not read the keychain hash of identity %s", label)
	}
	reference, err := t.WriteStub(key, sha, hex)
	switch {
	case err != nil:
		return err
	case reference:
		say("wrote SSH public-key reference %s", key)
	default:
		say("wrote SSH stub %s", key)
	}
	return nil
}

func listCommand(t enklava.Tools) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Secure Enclave identities available to SSH",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			identities, err := t.Identities("b64")
			if err != nil {
				return err
			}
			fmt.Println("LABEL\tHASH\tPROTECTION\tTYPE")
			for _, i := range identities {
				fmt.Println(strings.Join([]string{i.Label, i.Hash, i.Protection, i.Type}, "\t"))
			}
			return nil
		},
	}
}

func pubCommand(t enklava.Tools) *cobra.Command {
	var key string
	var toClipboard bool
	cmd := &cobra.Command{
		Use:   "pub --key-file F [--copy]",
		Short: "Print (or copy) the public key",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			key := enklava.Expand(key)
			if key == "" {
				return fail("pub: --key-file is required")
			}
			pub, err := os.Open(key + ".pub")
			if err != nil {
				return fail("%s.pub not found; run enklava ensure first", key)
			}
			defer pub.Close()
			if !toClipboard {
				_, err := io.Copy(os.Stdout, pub)
				return err
			}
			pbcopy := exec.Command(t.Pbcopy)
			pbcopy.Stdin = pub
			if err := pbcopy.Run(); err != nil {
				return fail("pbcopy failed: %v", err)
			}
			say("copied %s.pub to the clipboard", key)
			return nil
		},
	}
	cmd.Flags().StringVar(&key, "key-file", "", "path of the SSH stub")
	cmd.Flags().BoolVar(&toClipboard, "copy", false, "copy to the clipboard instead of printing")
	return cmd
}

func allowedSignersCommand() *cobra.Command {
	var key, output string
	var principals, extras []string
	cmd := &cobra.Command{
		Use:   "allowed-signers --output O [--key-file F --principal P...] [--extra LINE...]",
		Short: "Write a Git allowed_signers file",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			key, output := enklava.Expand(key), enklava.Expand(output)
			if output == "" {
				return fail("allowed-signers: --output is required")
			}
			if key != "" && len(principals) == 0 {
				return fail("allowed-signers: --key-file needs at least one --principal")
			}
			var algo, body string
			if key != "" && isFile(key+".pub") {
				var err error
				if algo, body, err = enklava.PublicKey(key + ".pub"); err != nil {
					return err
				}
			}
			return writeAtomic(output, enklava.AllowedSigners(extras, principals, algo, body), 0o644)
		},
	}
	cmd.Flags().StringVar(&key, "key-file", "", "path of the SSH stub")
	cmd.Flags().StringVar(&output, "output", "", "where to write the file")
	cmd.Flags().StringArrayVar(&principals, "principal", nil, "principal trusted for the key (repeatable)")
	cmd.Flags().StringArrayVar(&extras, "extra", nil, "extra line to include (repeatable)")
	return cmd
}

func githubAddCommand(t enklava.Tools) *cobra.Command {
	var key, kind, title string
	cmd := &cobra.Command{
		Use:   "add --key-file F [--type signing|authentication|both] [--title T]",
		Short: "Register the public key with GitHub through gh, skipping keys it has",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return githubAdd(t, enklava.Expand(key), kind, title)
		},
	}
	cmd.Flags().StringVar(&key, "key-file", "", "path of the SSH stub")
	cmd.Flags().StringVar(&kind, "type", "both", "signing, authentication or both")
	cmd.Flags().StringVar(&title, "title", "", "key title on GitHub")
	return cmd
}

func githubAdd(t enklava.Tools, key, kind, title string) error {
	if key == "" {
		return fail("github add: --key-file is required")
	}
	pub := key + ".pub"
	if !isFile(pub) {
		return fail("%s not found; run enklava ensure first", pub)
	}
	var kinds []string
	switch kind {
	case "both":
		kinds = []string{"signing", "authentication"}
	case "signing", "authentication":
		kinds = []string{kind}
	default:
		return fail("github add: --type must be signing, authentication or both")
	}
	if title == "" {
		fp, err := t.Fingerprint(pub)
		if err != nil {
			return fail("could not read the fingerprint of %s: %v", pub, err)
		}
		title = enklava.KeyTitle(t.MachineName(), fp)
	}
	algo, body, err := enklava.PublicKey(pub)
	if err != nil {
		return err
	}

	for _, kind := range kinds {
		endpoint := map[string]string{
			"signing":        "/user/ssh_signing_keys",
			"authentication": "/user/keys",
		}[kind]
		list := exec.Command(t.GH, "api", "--paginate", endpoint, "--jq", ".[].key")
		list.Stderr = os.Stderr
		keys, err := list.Output()
		if err != nil {
			return fail("gh could not list your %s keys", kind)
		}
		if hasKey(string(keys), algo, body) {
			say("GitHub already has this %s key", kind)
			continue
		}
		add := exec.Command(t.GH, "ssh-key", "add", pub, "--type", kind, "--title", title)
		add.Stderr = os.Stderr
		if err := add.Run(); err != nil {
			return fail("gh could not add the %s key", kind)
		}
		say("added %s key %q to GitHub", kind, title)
	}
	return nil
}

func hasKey(keys, algo, body string) bool {
	for line := range strings.SplitSeq(keys, "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == algo && fields[1] == body {
			return true
		}
	}
	return false
}

func doctorCommand(t enklava.Tools) *cobra.Command {
	var key, label string
	cmd := &cobra.Command{
		Use:   "doctor --key-file F --label L",
		Short: "Check the tools, the identity and the stub",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			key := enklava.Expand(key)
			if key == "" {
				return fail("doctor: --key-file is required")
			}
			if label == "" {
				return fail("doctor: --label is required")
			}
			return doctor(t, key, label)
		},
	}
	cmd.Flags().StringVar(&key, "key-file", "", "path of the SSH stub")
	cmd.Flags().StringVar(&label, "label", "", "CryptoTokenKit label of the identity")
	return cmd
}

func doctor(t enklava.Tools, key, label string) error {
	failed := false
	ok := func(s string) { fmt.Printf("ok    %s\n", s) }
	bad := func(s string) {
		fmt.Printf("FAIL  %s\n", s)
		failed = true
	}
	check := func(good bool, okMsg, badMsg string) {
		if good {
			ok(okMsg)
		} else {
			bad(badMsg)
		}
	}

	check(executable(t.ScAuth), t.ScAuth, t.ScAuth+" is missing")
	check(executable(t.SSHKeygen), t.SSHKeygen, t.SSHKeygen+" is missing")
	check(exists(t.Provider), t.Provider, t.Provider+" is missing (needs macOS 26 or later)")

	sha, err := t.HashFor(label, "b64")
	var ambiguous *enklava.AmbiguousError
	switch {
	case err == nil:
		ok(fmt.Sprintf("identity %s (%s)", label, sha))
	case errors.Is(err, enklava.ErrNoIdentity):
		bad("no identity is labelled " + label)
	case errors.As(err, &ambiguous):
		bad("several identities are labelled " + label)
	default:
		bad("sc_auth could not list identities")
	}

	keyExists, pubExists := exists(key), exists(key+".pub")
	switch {
	case keyExists && pubExists:
		ok(key + " and " + key + ".pub")
		if err == nil {
			fp, _ := t.Fingerprint(key + ".pub")
			check(fp == sha, key+".pub matches "+label, key+".pub does not match "+label)
		}
	case keyExists || pubExists:
		bad("only one of " + key + " and " + key + ".pub exists")
	default:
		bad(key + " is missing; run enklava ensure")
	}

	if failed {
		return exitCode(1)
	}
	return nil
}
