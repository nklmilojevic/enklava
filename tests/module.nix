{
  lib,
  pkgs,
  runCommand,
  self,
  home-manager,
}:

let
  evaluate =
    enklava:
    (home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        self.homeManagerModules.default
        {
          home = {
            username = "test";
            homeDirectory = "/Users/test";
            stateVersion = "25.11";
          };
          programs.git.enable = true;
          programs.enklava = enklava;
        }
      ];
    }).config;

  failedAssertions = config: map (a: a.message) (lib.filter (a: !a.assertion) config.assertions);

  # Home Manager throws on a failed assertion before the config is reachable.
  rejected = enklava: !(builtins.tryEval (evaluate enklava).home.username).success;

  full = evaluate {
    enable = true;
    identities = {
      github = {
        hosts = [ "github.com" ];
      };
      work = {
        keyFile = "/Users/test/keys/work";
        label = "work laptop";
        protection = "bio";
        hosts = [
          "gitlab.com"
          "*.corp"
        ];
      };
      spare.ensure = false;
    };
    git = {
      signingIdentity = "github";
      principals = [
        "a@example.com"
        "b@example.com"
      ];
      extraAllowedSigners = [ "a@example.com ssh-ed25519 OLD" ];
    };
  };

  minimal = evaluate {
    enable = true;
    identities.only = { };
  };

  checks = {
    "no assertion fails" = failedAssertions full == [ ];

    "ssh config has one block per host and nothing for Host *" =
      full.home.file.".ssh/enklava.conf".text == ''
        Host github.com
          IdentityFile /Users/test/.ssh/id_enklava_github
          IdentitiesOnly yes
          IdentityAgent none
          SecurityKeyProvider /usr/lib/ssh-keychain.dylib
        Host gitlab.com
          IdentityFile /Users/test/keys/work
          IdentitiesOnly yes
          IdentityAgent none
          SecurityKeyProvider /usr/lib/ssh-keychain.dylib
        Host *.corp
          IdentityFile /Users/test/keys/work
          IdentitiesOnly yes
          IdentityAgent none
          SecurityKeyProvider /usr/lib/ssh-keychain.dylib
      '';

    "ssh include is left alone when programs.ssh is off" = full.programs.ssh.includes == [ ];

    "git signs with the stub through enklava-sign" =
      full.programs.git.signing.key == "/Users/test/.ssh/id_enklava_github"
      && full.programs.git.signing.format == "ssh"
      && lib.hasSuffix "/bin/enklava-sign" full.programs.git.settings.gpg.ssh.program
      && full.programs.git.settings.gpg.ssh.allowedSignersFile == "/Users/test/.ssh/allowed_signers";

    "activation ensures identities and writes allowed_signers" =
      let
        script = full.home.activation.enklava.data;
      in
      lib.hasInfix "--label github-enklava" script
      && lib.hasInfix "--label 'work laptop'" script
      && lib.hasInfix "--protection bio" script
      && !(lib.hasInfix "spare-enklava" script)
      && lib.hasInfix "--principal a@example.com --principal b@example.com" script
      && lib.hasInfix "--extra 'a@example.com ssh-ed25519 OLD'" script;

    "an identity without hosts or signing writes no ssh config or git settings" =
      failedAssertions minimal == [ ]
      && !(minimal.home.file ? ".ssh/enklava.conf")
      && minimal.programs.git.signing.key == null;

    "ssh include is added when programs.ssh is on" =
      let
        config =
          (home-manager.lib.homeManagerConfiguration {
            inherit pkgs;
            modules = [
              self.homeManagerModules.default
              {
                home = {
                  username = "test";
                  homeDirectory = "/Users/test";
                  stateVersion = "25.11";
                };
                programs.ssh = {
                  enable = true;
                  enableDefaultConfig = false;
                };
                programs.enklava = {
                  enable = true;
                  identities.github.hosts = [ "github.com" ];
                };
              }
            ];
          }).config;
      in
      config.programs.ssh.includes == [ "/Users/test/.ssh/enklava.conf" ];

    "an unknown signing identity is rejected" = rejected {
      enable = true;
      identities.a = { };
      git = {
        signingIdentity = "b";
        principals = [ "a@example.com" ];
      };
    };

    "signing without principals is rejected" = rejected {
      enable = true;
      identities.a = { };
      git.signingIdentity = "a";
    };

    "a host shared by two identities is rejected" = rejected {
      enable = true;
      identities = {
        a.hosts = [ "github.com" ];
        b.hosts = [ "github.com" ];
      };
    };
  };

  failed = lib.attrNames (lib.filterAttrs (_: passed: !passed) checks);
in
if failed == [ ] then
  runCommand "enklava-module-tests" { } "touch $out"
else
  throw "enklava module checks failed:\n  ${lib.concatStringsSep "\n  " failed}"
