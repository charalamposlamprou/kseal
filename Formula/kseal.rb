class Kseal < Formula
  desc "TUI and CLI for Kubernetes Secrets, with native SealedSecret sealing"
  homepage "https://github.com/charalamposlamprou/kseal"
  version "0.1.9"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.9/kseal-aarch64-apple-darwin.tar.xz"
      sha256 "29c9c54b53e04a2890ee512295cc07a37f41fcf679d872ad8e71b6ad7c8ddabc"
    end
    if Hardware::CPU.intel?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.9/kseal-x86_64-apple-darwin.tar.xz"
      sha256 "3a441651c97f80d06bc27624a7a148429d7edd10a6ab6a7ae1d9cec45f99cbe7"
    end
  end
  if OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.9/kseal-aarch64-unknown-linux-musl.tar.xz"
      sha256 "7cdae4e892bc043b4fb9920a72fc9ec71e543cafc5ba85b32d41fccf6e98722a"
    end
    if Hardware::CPU.intel?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.9/kseal-x86_64-unknown-linux-gnu.tar.xz"
      sha256 "6e96d1a1ee559d27ac626c034c9f6092d69641746332a36584a9e8b6066cd189"
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
