{
  lib,
  stdenv,
  buildGoModule,
  installShellFiles,
}:

buildGoModule (finalAttrs: {
  pname = "enklava";
  version = "0.1.1";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./go.mod
      ./go.sum
      ./cmd
      ./internal
    ];
  };

  vendorHash = "sha256-7K17JaXFsjf163g5PXCb5ng2gYdotnZ2IDKk8KFjNj0=";

  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
    "-X github.com/nklmilojevic/enklava/internal/cli.Version=${finalAttrs.version}"
  ];

  nativeBuildInputs = [ installShellFiles ];

  postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
    installShellCompletion --cmd enklava \
      --bash <($out/bin/enklava completion bash) \
      --fish <($out/bin/enklava completion fish) \
      --zsh <($out/bin/enklava completion zsh)
  '';

  meta = {
    description = "Secure Enclave SSH keys and Git signing for macOS";
    homepage = "https://github.com/nklmilojevic/enklava";
    license = lib.licenses.mit;
    mainProgram = "enklava";
    platforms = lib.platforms.darwin;
  };
})
