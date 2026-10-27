class Kseal < Formula
  desc "TUI and CLI for Kubernetes Secrets, with native SealedSecret sealing"
  homepage "https://github.com/charalamposlamprou/kseal"
  version "0.1.7"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.7/kseal-aarch64-apple-darwin.tar.xz"
      sha256 "5d9bf5ff164b190a71c68560085c586c5bc289257575a78c53f2f12dd00e9489"
    end
    if Hardware::CPU.intel?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.7/kseal-x86_64-apple-darwin.tar.xz"
      sha256 "6e5a725b57c99c1f92b346518abb30af8bdb42d4460ff110d97e9a170b8ee7b9"
    end
  end
  if OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.7/kseal-aarch64-unknown-linux-musl.tar.xz"
      sha256 "9378d4639abf27ac6ffafb7d996c29925bad8c020a4379694a40e0b3f98ef6f6"
    end
    if Hardware::CPU.intel?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.7/kseal-x86_64-unknown-linux-gnu.tar.xz"
      sha256 "763d14a44dd1027162b0cf6265de1f9abd93072c87a58fdc62d4b968bc498d66"
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
