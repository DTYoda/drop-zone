// Path handling.
//
// A receiver creates files at paths chosen by whoever is sending. If a "../"
// slipped through, a sender could write anywhere the receiving user can -- their
// shell profile, their SSH authorised keys. These are the checks standing between
// those two facts.

#include <string>
#include <vector>

#include "dz/client/manifest.hpp"
#include "dz/fileio.hpp"
#include "dz/protocol.hpp"
#include "harness.hpp"

using namespace dz;
using namespace dz::client;

DZ_TEST(ordinary_relative_paths_are_accepted) {
    DZ_CHECK(is_safe_relative_path("report.pdf"));
    DZ_CHECK(is_safe_relative_path("photos/holiday.jpg"));
    DZ_CHECK(is_safe_relative_path("a/b/c/d/e.txt"));
    DZ_CHECK(is_safe_relative_path("with spaces.txt"));
    DZ_CHECK(is_safe_relative_path("dotted.name.tar.gz"));
    // A leading dot is a hidden file, not an escape.
    DZ_CHECK(is_safe_relative_path(".hidden"));
    DZ_CHECK(is_safe_relative_path("dir/.hidden"));
    // "..." is three ordinary dots, not a parent reference.
    DZ_CHECK(is_safe_relative_path("..."));
}

DZ_TEST(paths_that_escape_the_output_directory_are_rejected) {
    DZ_CHECK(!is_safe_relative_path(".."));
    DZ_CHECK(!is_safe_relative_path("../outside"));
    DZ_CHECK(!is_safe_relative_path("a/../../outside"));
    DZ_CHECK(!is_safe_relative_path("a/b/.."));
    // The classic one: a path that looks contained until the components are read.
    DZ_CHECK(!is_safe_relative_path("photos/../../.ssh/authorized_keys"));
}

DZ_TEST(absolute_paths_are_rejected) {
    DZ_CHECK(!is_safe_relative_path("/etc/passwd"));
    DZ_CHECK(!is_safe_relative_path("/"));
}

DZ_TEST(odd_separators_and_empty_components_are_rejected) {
    DZ_CHECK(!is_safe_relative_path(""));
    DZ_CHECK(!is_safe_relative_path("a//b"));      // Empty component.
    DZ_CHECK(!is_safe_relative_path("a/"));        // Trailing slash.
    DZ_CHECK(!is_safe_relative_path("./a"));       // Current-directory component.
    // A backslash is ordinary here but a separator elsewhere, so a path that is safe
    // on this machine could stop being safe once the files are copied to another.
    DZ_CHECK(!is_safe_relative_path("a\\..\\b"));
}

DZ_TEST(a_path_containing_a_nul_is_rejected) {
    // A NUL truncates the path the moment it reaches a C API, so "safe.txt\0../evil"
    // would pass a naive check and then create something else entirely.
    std::string sneaky("safe.txt");
    sneaky.push_back('\0');
    sneaky += "../evil";
    DZ_CHECK(!is_safe_relative_path(sneaky));
}

DZ_TEST(an_over_long_path_is_rejected) {
    DZ_CHECK(!is_safe_relative_path(std::string(kMaxPathLength + 1, 'a')));
}

DZ_TEST(sanitising_an_unsafe_path_throws) {
    DZ_CHECK_EQUAL(sanitize_relative_path("fine/path.txt"), std::string("fine/path.txt"));
    DZ_CHECK_THROWS(sanitize_relative_path("../escape"));
}

DZ_TEST(resolving_output_paths_refuses_an_unsafe_entry) {
    std::vector<ManifestEntry> entries;

    ManifestEntry good;
    good.path = "photos/one.jpg";
    entries.push_back(good);

    std::vector<std::string> paths = resolve_output_paths(entries, "/tmp/out");
    DZ_CHECK_EQUAL(paths.size(), 1u);
    DZ_CHECK_EQUAL(paths[0], std::string("/tmp/out/photos/one.jpg"));

    // Checked again here, rather than relying on the parse-time check, because this
    // is the point where a path becomes a filesystem operation.
    ManifestEntry bad;
    bad.path = "../escape";
    entries.push_back(bad);
    DZ_CHECK_THROWS(resolve_output_paths(entries, "/tmp/out"));
}

DZ_TEST(usernames_are_restricted_to_safe_characters) {
    DZ_CHECK(is_valid_username("alice"));
    DZ_CHECK(is_valid_username("alice-2"));
    DZ_CHECK(is_valid_username("alice_smith"));
    DZ_CHECK(is_valid_username("a.b.c"));
    DZ_CHECK(is_valid_username("x"));

    DZ_CHECK(!is_valid_username(""));
    DZ_CHECK(!is_valid_username("Alice"));            // Uppercase would confuse matching.
    DZ_CHECK(!is_valid_username("alice smith"));      // A space in a shell argument.
    DZ_CHECK(!is_valid_username("alice/../bob"));     // Would escape if used as a path.
    DZ_CHECK(!is_valid_username("alice;rm -rf /"));
    DZ_CHECK(!is_valid_username(".hidden"));          // Leading dot.
    DZ_CHECK(!is_valid_username(".."));
    DZ_CHECK(!is_valid_username(std::string(kMaxUsernameLength + 1, 'a')));
}

DZ_TEST(path_helpers_behave_as_the_manifest_expects) {
    DZ_CHECK_EQUAL(base_name("/a/b/c.txt"), std::string("c.txt"));
    DZ_CHECK_EQUAL(base_name("c.txt"), std::string("c.txt"));
    // A trailing slash must not produce an empty name, or `drop-zone send photos/`
    // would have nothing to call the transfer.
    DZ_CHECK_EQUAL(base_name("/a/b/"), std::string("b"));
    DZ_CHECK_EQUAL(base_name("photos/"), std::string("photos"));

    DZ_CHECK_EQUAL(parent_path("/a/b/c.txt"), std::string("/a/b"));
    DZ_CHECK_EQUAL(parent_path("c.txt"), std::string("."));
    DZ_CHECK_EQUAL(parent_path("/c.txt"), std::string("/"));

    DZ_CHECK_EQUAL(join_path("/a", "b"), std::string("/a/b"));
    DZ_CHECK_EQUAL(join_path("/a/", "b"), std::string("/a/b"));
    DZ_CHECK_EQUAL(join_path("", "b"), std::string("b"));
    // An absolute right-hand side wins, matching how path joining behaves elsewhere.
    DZ_CHECK_EQUAL(join_path("/a", "/b"), std::string("/b"));
}

DZ_TEST(byte_and_rate_formatting_is_readable) {
    DZ_CHECK_EQUAL(format_bytes(0), std::string("0 B"));
    DZ_CHECK_EQUAL(format_bytes(512), std::string("512 B"));
    DZ_CHECK_EQUAL(format_bytes(1024), std::string("1.0 KiB"));
    DZ_CHECK_EQUAL(format_bytes(1536), std::string("1.5 KiB"));
    DZ_CHECK_EQUAL(format_bytes(1024ull * 1024 * 1024), std::string("1.0 GiB"));

    DZ_CHECK_EQUAL(format_rate(1024 * 1024, 1.0), std::string("1.0 MiB/s"));
    // A zero duration must not divide by zero.
    DZ_CHECK_EQUAL(format_rate(1000, 0.0), std::string("-"));
}
