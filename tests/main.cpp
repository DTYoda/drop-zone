#include <cstdio>
#include <cstring>

#include "harness.hpp"

int main(int argc, char* argv[]) {
    // An optional substring filter, so one failing case can be re-run on its own.
    const char* filter = (argc > 1) ? argv[1] : nullptr;

    std::size_t passed = 0;
    std::size_t failed = 0;
    std::size_t skipped = 0;

    for (const dz::test::Case& test : dz::test::registry()) {
        if (filter != nullptr && test.name.find(filter) == std::string::npos) {
            ++skipped;
            continue;
        }

        try {
            test.body();
            std::printf("ok       %s\n", test.name.c_str());
            ++passed;
        } catch (const std::exception& error) {
            std::printf("FAILED   %s\n           %s\n", test.name.c_str(), error.what());
            ++failed;
        }

        // Flushed per case rather than at exit: redirected to a file, stdout is
        // fully buffered, and a case that hangs would otherwise leave no record of
        // how far the run got.
        std::fflush(stdout);
    }

    std::printf("\n%zu passed, %zu failed", passed, failed);
    if (skipped > 0) std::printf(", %zu filtered out", skipped);
    std::printf("\n");

    return (failed == 0) ? 0 : 1;
}
