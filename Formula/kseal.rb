class Kseal < Formula
  desc "TUI and CLI for Kubernetes Secrets, with native SealedSecret sealing"
  homepage "https://github.com/charalamposlamprou/kseal"
  version "0.1.2"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.2/kseal-aarch64-apple-darwin.tar.xz"
      sha256 "84c9c8ef2cd4cefc76c61a42bffbd297e95e4e6e3714b3608cc0dfa52962a219"
    end
    if Hardware::CPU.intel?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.2/kseal-x86_64-apple-darwin.tar.xz"
      sha256 "a0dfab84f8c9cd189c2d80de9c770a011374da0bba2c0e86f053f2c95cadf816"
    end
  end
  if OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.2/kseal-aarch64-unknown-linux-musl.tar.xz"
      sha256 "8ad4bb57aef609695f9eba43e49303fca8fe6175bbb2e0a4f4ae5bf89c7383fb"
    end
    if Hardware::CPU.intel?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.2/kseal-x86_64-unknown-linux-gnu.tar.xz"
      sha256 "8e564e4d819fef8fe48ae2c1ba1f8991959d80f4f6ecee2af18968a7f416c447"
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
