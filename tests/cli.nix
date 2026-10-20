{
  runCommand,
  enklava,
  bash,
  coreutils,
  gnugrep,
}:

runCommand "enklava-cli-tests"
  {
    nativeBuildInputs = [
      bash
      coreutils
      gnugrep
    ];
  }
  ''
    cp -r ${./fake} fake
    chmod -R u+w fake
    patchShebangs fake
    bash ${./cli.sh} ${enklava}/bin "$PWD/fake"
    touch $out
  ''
