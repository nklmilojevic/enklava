# enklava

Secure Enclave SSH keys and Git signing for macOS, as a small CLI and a Home
Manager module.

It uses only what macOS ships: `sc_auth` creates a P-256 key inside the Secure
Enclave, and OpenSSH talks to it through `/usr/lib/ssh-keychain.dylib`. The
private key never leaves the enclave. The files on disk are a non-secret stub
and its `.pub`.

Needs macOS 26 or later.

## Home Manager

```nix
{
  inputs.enklava = {
    url = "github:nklmilojevic/enklava";
    inputs.nixpkgs.follows = "nixpkgs";
    inputs.home-manager.follows = "home-manager";
  };
}
```

```nix
{
  imports = [ inputs.enklava.homeManagerModules.default ];

  programs.enklava = {
    enable = true;
    identities.github.hosts = [ "github.com" ];
    git = {
      signingIdentity = "github";
      principals = [ "me@example.com" ];
    };
  };
}
```

On activation this creates the `github-enklava` identity and the stub
`~/.ssh/id_enklava_github` if they are missing. It also writes
`~/.ssh/allowed_signers` so `git log --show-signature` can verify your commits.

The module writes a `Host github.com` block to `~/.ssh/enklava.conf` with
`IdentitiesOnly yes` and `IdentityAgent none`, so other hosts keep whatever
agent they use today. If `programs.ssh` is enabled, the file is added to its
includes. Otherwise, `Include ~/.ssh/enklava.conf` it yourself before any
`Host *` block.

| Option | Default | |
| --- | --- | --- |
| `identities.<name>.keyFile` | `~/.ssh/id_enklava_<name>` | stub path; the public key is `<keyFile>.pub` |
| `identities.<name>.label` | `<name>-enklava` | CryptoTokenKit label |
| `identities.<name>.protection` | `none` | `bio` asks for Touch ID on every use |
| `identities.<name>.ensure` | `true` | create identity and stub at activation |
| `identities.<name>.hosts` | `[ ]` | SSH hosts that use this identity |
| `ssh.configFile` | `.ssh/enklava.conf` | relative to home |
| `ssh.addInclude` | `programs.ssh.enable` | add to `programs.ssh.includes` |
| `git.signingIdentity` | `null` | identity that signs commits and tags |
| `git.signByDefault` | `true` | |
| `git.principals` | `[ ]` | emails trusted for the signing key |
| `git.extraAllowedSigners` | `[ ]` | extra lines, e.g. a previous signing key |
| `git.allowedSignersFile` | `~/.ssh/allowed_signers` | |

Registering the key with GitHub is never done during activation. Run it once:

```sh
enklava github add --key-file ~/.ssh/id_enklava_github
```

## CLI

```
enklava ensure --key-file F --label L [--protection none|bio]
enklava list
enklava pub --key-file F [--copy]
enklava allowed-signers --output O [--key-file F --principal P...] [--extra LINE...]
enklava github add --key-file F [--type signing|authentication|both] [--title T]
enklava doctor --key-file F --label L
```

`enklava-sign` is the Git `gpg.ssh.program`. It runs `ssh-keygen` with the
Secure Enclave provider. When the key file is a public-key reference instead
of a stub, it signs through a private `ssh-agent` that is stopped as soon as
the signature is written.

Removing an identity is left to `sc_auth delete-ctk-identity -h <hash>`.

## Development

```sh
nix flake check   # shellcheck, CLI tests against fake Apple tools, module tests
nix fmt -- $(git ls-files '*.nix')
```

Inspired by [ryoppippi/nix-secure-enclave-key](https://github.com/ryoppippi/nix-secure-enclave-key).
