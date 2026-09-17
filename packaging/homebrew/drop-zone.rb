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
# This file is the copy kept next to the source. The installable tap lives at
# https://github.com/DTYoda/homebrew-tap (brew tap DTYoda/tap). After tagging
# a release, run packaging/homebrew/fill-stable.sh and paste url/sha256 here,
# then copy this file to Formula/drop-zone.rb in that tap.

class DropZone < Formula
  desc "Peer-to-peer terminal file transfer"
  homepage "https://github.com/DTYoda/drop-zone"
  url "https://github.com/DTYoda/drop-zone/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "397a833fe68ee88a550f1dc5679a484f0554bfdc225a2a810931d9f54b0f5337"
  license "MIT"
  head "https://github.com/DTYoda/drop-zone.git", branch: "main"

  livecheck do
    url :stable
    strategy :github_latest
  end

  depends_on "cmake" => :build
  depends_on "pkgconf" => :build
  depends_on "openssl@3"

  def install
    args = %w[
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
