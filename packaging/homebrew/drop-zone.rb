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

class DropZone < Formula
  desc "Peer-to-peer terminal file transfer"
  homepage "https://github.com/DTYoda/drop-zone"
  url "https://github.com/DTYoda/drop-zone.git", branch: "main"
  version "1.0.0"
  head "https://github.com/DTYoda/drop-zone.git", branch: "main"

  depends_on "cmake" => :build
  depends_on "openssl@3"

  def install
    args = %W[
      -DCMAKE_BUILD_TYPE=Release
      -DDZ_BUILD_CLIENT=ON
      -DDZ_BUILD_SERVER=OFF
      -DDZ_BUILD_TESTS=OFF
      -DDZ_NATIVE_ARCH=OFF
    ]

    system "cmake", "-S", ".", "-B", "build", *args, *std_cmake_args
    system "cmake", "--build", "build", "--parallel"
    system "cmake", "--install", "build"
  end

  test do
    assert_match "drop-zone 1.0.0", shell_output("#{bin}/drop-zone --version")
    help = shell_output("#{bin}/drop-zone --help")
    assert_match "drop-zone setup", help
    assert_match "send FILE", help
  end
end
