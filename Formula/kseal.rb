class Kseal < Formula
  desc "TUI and CLI for Kubernetes Secrets, with native SealedSecret sealing"
  homepage "https://github.com/charalamposlamprou/kseal"
  version "0.1.3"
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.3/kseal-aarch64-apple-darwin.tar.xz"
      sha256 "b6ec9b39be197f8d7d68f5b1f8c9a52f029044eb032e1c9561673a745eaa28e4"
    end
    if Hardware::CPU.intel?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.3/kseal-x86_64-apple-darwin.tar.xz"
      sha256 "e6d9282d843659f6d8e8449f193ec8bd59e707f3aad6571aef073444a413026a"
    end
  end
  if OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.3/kseal-aarch64-unknown-linux-musl.tar.xz"
      sha256 "6a321087d785eb6fc2a11fd72e99d2701502427c8a748efb93e41ef5d0ab1e6b"
    end
    if Hardware::CPU.intel?
      url "https://github.com/charalamposlamprou/kseal/releases/download/v0.1.3/kseal-x86_64-unknown-linux-gnu.tar.xz"
      sha256 "4e41f1620475fdc10fa8f948cbf365b5b34c1f4e0d3c9837984ff44dec9838ef"
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
