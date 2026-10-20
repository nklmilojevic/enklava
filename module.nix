{ self }:

{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib) mkOption types;

  cfg = config.programs.enklava;
  provider = "/usr/lib/ssh-keychain.dylib";

  expand =
    path:
    if lib.hasPrefix "~/" path then
      "${config.home.homeDirectory}/${lib.removePrefix "~/" path}"
    else
      path;

  identities = lib.mapAttrs (
    _: identity: identity // { path = expand identity.keyFile; }
  ) cfg.identities;
  signing =
    if cfg.git.signingIdentity == null then null else identities.${cfg.git.signingIdentity} or null;

  enklava = lib.getExe' cfg.package "enklava";
  signer = lib.getExe' cfg.package "enklava-sign";
  allowedSigners = expand cfg.git.allowedSignersFile;

  hosts = lib.concatMap (identity: identity.hosts) (lib.attrValues identities);
  duplicateHosts = lib.unique (lib.filter (host: lib.count (h: h == host) hosts > 1) hosts);

  hostBlocks = lib.concatStrings (
    lib.concatMap (
      identity:
      map (host: ''
        Host ${host}
          IdentityFile ${identity.path}
          IdentitiesOnly yes
          IdentityAgent none
          SecurityKeyProvider ${provider}
      '') identity.hosts
    ) (lib.attrValues identities)
  );

  ensureCommands = lib.concatStrings (
    lib.mapAttrsToList (
      name: identity:
      lib.optionalString identity.ensure ''
        run ${enklava} ensure --key-file ${lib.escapeShellArg identity.path} \
          --label ${lib.escapeShellArg identity.label} \
          --protection ${lib.escapeShellArg identity.protection} ||
          warnEcho "enklava: could not ensure identity ${name}; run: enklava doctor --key-file ${lib.escapeShellArg identity.path} --label ${lib.escapeShellArg identity.label}"
      ''
    ) identities
  );

  allowedSignersCommand = lib.escapeShellArgs (
    [
      "allowed-signers"
      "--key-file"
      signing.path
      "--output"
      allowedSigners
    ]
    ++ lib.concatMap (principal: [
      "--principal"
      principal
    ]) cfg.git.principals
    ++ lib.concatMap (line: [
      "--extra"
      line
    ]) cfg.git.extraAllowedSigners
  );

  identityModule =
    { name, ... }:
    {
      options = {
        keyFile = mkOption {
          type = types.str;
          default = "~/.ssh/id_enklava_${name}";
          description = "Path of the non-secret SSH stub; the public key is `<keyFile>.pub`. A leading `~/` means the home directory.";
        };

        label = mkOption {
          type = types.str;
          default = "${name}-enklava";
          description = "CryptoTokenKit label of the Secure Enclave identity.";
        };

        protection = mkOption {
          type = types.enum [
            "none"
            "bio"
          ];
          default = "none";
          description = "`bio` asks for Touch ID on every use. Only applies when the identity is created.";
        };

        ensure = mkOption {
          type = types.bool;
          default = true;
          description = "Create the identity and stub during activation when they are missing.";
        };

        hosts = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [ "github.com" ];
          description = "SSH hosts that use this identity, bypassing any other agent.";
        };
      };
    };
in
{
  options.programs.enklava = {
    enable = lib.mkEnableOption "Secure Enclave SSH keys and Git signing";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "enklava.packages.\${system}.default";
      description = "The enklava package.";
    };

    identities = mkOption {
      type = types.attrsOf (types.submodule identityModule);
      default = { };
      description = "Secure Enclave identities, by name.";
    };

    ssh = {
      configFile = mkOption {
        type = types.str;
        default = ".ssh/enklava.conf";
        description = "Where to write the Host blocks, relative to the home directory. `Include` it before any `Host *` block.";
      };

      addInclude = mkOption {
        type = types.bool;
        default = config.programs.ssh.enable;
        defaultText = lib.literalExpression "config.programs.ssh.enable";
        description = "Add the config file to `programs.ssh.includes`.";
      };
    };

    git = {
      signingIdentity = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Name of the identity that signs Git commits and tags.";
      };

      signByDefault = mkOption {
        type = types.bool;
        default = true;
        description = "Sign every commit and tag.";
      };

      principals = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "me@example.com" ];
        description = "Principals (usually commit emails) trusted for the signing key in allowed_signers.";
      };

      extraAllowedSigners = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "me@example.com ssh-ed25519 AAAA..." ];
        description = "Extra allowed_signers lines, e.g. an older key so earlier commits keep verifying.";
      };

      allowedSignersFile = mkOption {
        type = types.str;
        default = "~/.ssh/allowed_signers";
        description = "Where the allowed_signers file is written at activation.";
      };
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = pkgs.stdenv.hostPlatform.isDarwin;
            message = "programs.enklava needs macOS.";
          }
          {
            assertion = cfg.git.signingIdentity == null || signing != null;
            message = "programs.enklava.git.signingIdentity must name one of programs.enklava.identities.";
          }
          {
            assertion = cfg.git.signingIdentity == null || cfg.git.principals != [ ];
            message = "programs.enklava.git.principals must not be empty when signing is on.";
          }
          {
            assertion = duplicateHosts == [ ];
            message = "programs.enklava: hosts used by more than one identity: ${toString duplicateHosts}";
          }
        ];

        home.packages = [ cfg.package ];

        home.activation.enklava = lib.mkIf (ensureCommands != "" || signing != null) (
          lib.hm.dag.entryAfter [ "writeBoundary" ] (
            ensureCommands + lib.optionalString (signing != null) "run ${enklava} ${allowedSignersCommand}\n"
          )
        );
      }

      (lib.mkIf (hosts != [ ]) {
        home.file.${cfg.ssh.configFile}.text = hostBlocks;
        programs.ssh.includes = lib.mkIf cfg.ssh.addInclude [
          "${config.home.homeDirectory}/${cfg.ssh.configFile}"
        ];
      })

      (lib.mkIf (signing != null) {
        programs.git = {
          signing = {
            format = "ssh";
            key = signing.path;
            inherit signer;
            inherit (cfg.git) signByDefault;
          };
          settings.gpg.ssh = {
            program = signer;
            allowedSignersFile = allowedSigners;
          };
        };
      })
    ]
  );
}
