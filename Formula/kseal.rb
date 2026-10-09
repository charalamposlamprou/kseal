class Kseal < Formula
  desc "TUI and CLI for Kubernetes Secrets, with native SealedSecret sealing"
  homepage "https://github.com/charalamposlamprou/kseal"
  version "0.1.0"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.0/kseal-aarch64-apple-darwin.tar.xz"
      sha256 "6adb0390c6efa3fc0fbc898299cd340e708311158d4245d24b9e77619c3cef09"
    end
    if Hardware::CPU.intel?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.0/kseal-x86_64-apple-darwin.tar.xz"
      sha256 "aeb432ccbb99bb004d122dafeafd271d55d7aeb88f281fa8d17baf928139a725"
    end
  end
  if OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.0/kseal-aarch64-unknown-linux-musl.tar.xz"
      sha256 "03b22e7418b747d5bf19f769f1b4ff983f511361f4956a1c1dc9206e10cd694d"
    end
    if Hardware::CPU.intel?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.0/kseal-x86_64-unknown-linux-gnu.tar.xz"
      sha256 "edbd867529001ea013488193fbcb1a4de1a2a8285dc5991e54894a9810acf73d"
    end
  end
  license "MIT"

  BINARY_ALIASES = {
    "aarch64-apple-darwin":               {},
    "aarch64-unknown-linux-gnu":          {},
    "aarch64-unknown-linux-musl-dynamic": {},
    "aarch64-unknown-linux-musl-static":  {},
    "x86_64-apple-darwin":                {},
    "x86_64-pc-windows-gnu":              {},
    "x86_64-unknown-linux-gnu":           {},
    "x86_64-unknown-linux-musl-dynamic":  {},
    "x86_64-unknown-linux-musl-static":   {},
  }.freeze

  def target_triple
    cpu = Hardware::CPU.arm? ? "aarch64" : "x86_64"
    os = OS.mac? ? "apple-darwin" : "unknown-linux-gnu"

    "#{cpu}-#{os}"
  end

  def install_binary_aliases!
    BINARY_ALIASES[target_triple.to_sym].each do |source, dests|
      dests.each do |dest|
        bin.install_symlink bin/source.to_s => dest
      end
    end
  end

  def install
    if OS.mac? && Hardware::CPU.arm?
      bin.install "kseal"
    end
    if OS.mac? && Hardware::CPU.intel?
      bin.install "kseal"
    end
    if OS.linux? && Hardware::CPU.arm?
      bin.install "kseal"
    end
    if OS.linux? && Hardware::CPU.intel?
      bin.install "kseal"
    end

    install_binary_aliases!

    # Homebrew will automatically install these, so we don't need to do that
    doc_files = Dir["README.*", "readme.*", "LICENSE", "LICENSE.*", "CHANGELOG.*"]
    leftover_contents = Dir["*"] - doc_files

    # Install any leftover files in pkgshare; these are probably config or
    # sample files.
    pkgshare.install(*leftover_contents) unless leftover_contents.empty?
  end
end
