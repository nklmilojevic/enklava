# Changelog

## v0.1.0 - 2026-10-20

This first release gives you `enklava`, a CLI for Secure Enclave SSH keys and Git commit signatures on macOS. It also gives you a Home Manager module for SSH identities and Git commit signatures.

### New features

- Adds Secure Enclave SSH keys for macOS, managed with the `enklava` command.
- Adds Git commit signatures through the `enklava-sign` command.
- Adds a Home Manager module. It assigns each SSH identity to named hosts.
- Writes the `allowed_signers` file during activation. Git uses this file to check commit signatures.
- Publishes macOS archives with each GitHub release. The archives cover arm64 and amd64 Macs.
- Adds `enklava --version` to show the installed version.
- Adds `enklava completion` for shell completion scripts.

### Fixes

- The `github add` command stops with an error if `gh` cannot list existing keys. It no longer treats the key as not registered.

### Other changes

- The `enklava` and `enklava-sign` commands are now Go binaries. Their commands, flags and exit codes stay the same.
