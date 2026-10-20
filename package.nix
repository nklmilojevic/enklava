{
  lib,
  symlinkJoin,
  writeShellApplication,
  coreutils,
  gawk,
  gnugrep,
  gnused,
}:

let
  version = "0.1.0";
  script =
    name:
    writeShellApplication {
      inherit name;
      runtimeInputs = [
        coreutils
        gawk
        gnugrep
        gnused
      ];
      text = builtins.readFile ./src/${name}.sh;
    };
in
symlinkJoin {
  name = "enklava-${version}";
  inherit version;
  paths = [
    (script "enklava")
    (script "enklava-sign")
  ];

  meta = {
    description = "Secure Enclave SSH keys and Git signing for macOS";
    homepage = "https://github.com/nklmilojevic/enklava";
    license = lib.licenses.mit;
    mainProgram = "enklava";
    platforms = lib.platforms.darwin;
  };
}
