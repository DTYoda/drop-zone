# Homebrew formula for the drop-zone client.
#
# Builds only the client. The rendezvous server is an operator's daemon, not
# something a `brew install` should place on a laptop; passing -DDZ_BUILD_SERVER=OFF
# is what keeps it out of the bottle.
#
# The bottle is compiled without -march=native. Every CPU-specific fast path
# (AES-NI vs ChaCha20) is selected at run time — see common/src/cpu.cpp — so a
# bottle built on a machine with VAES still runs on one without, and still takes
# the AES path where the hardware has it.
#
# Until the first git tag exists this formula is HEAD-only:
#
#   brew install --HEAD ./packaging/homebrew/drop-zone.rb
#
# After tagging vX.Y.Z, run packaging/homebrew/fill-stable.sh and paste the
# printed `url` / `sha256` below so the formula can be copied into a tap or
# submitted to homebrew-core.

class DropZone < Formula
  desc "Peer-to-peer terminal file transfer"
  homepage "https://github.com/DTYoda/drop-zone"
  license "MIT"
  head "https://github.com/DTYoda/drop-zone.git", branch: "main"

  # Stable source, filled in after the first release tag:
  # url "https://github.com/DTYoda/drop-zone/archive/refs/tags/v1.0.0.tar.gz"
  # sha256 "REPLACE_WITH_SHA256"
  # livecheck do
  #   url :stable
  #   strategy :github_latest
  # end

  depends_on "cmake" => :build
  depends_on "pkgconf" => :build
  depends_on "openssl@3"

  def install
    args = %W[
      -DDZ_BUILD_CLIENT=ON
      -DDZ_BUILD_SERVER=OFF
      -DDZ_BUILD_TESTS=OFF
      -DDZ_NATIVE_ARCH=OFF
    ]

    system "cmake", "-S", ".", "-B", "build", *std_cmake_args, *args
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end

  def caveats
    <<~EOS
      Run `drop-zone setup` once to create a username and identity.
    EOS
  end

  test do
    output = shell_output("#{bin}/drop-zone --version")
    assert_match(/drop-zone \d+\.\d+\.\d+/, output)

    help = shell_output("#{bin}/drop-zone --help")
    assert_match "drop-zone setup", help
    assert_match "send FILE", help
    assert_match "set-server", help
  end
end
