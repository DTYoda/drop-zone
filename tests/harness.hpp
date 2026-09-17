// A very small test harness.
//
// Deliberately not a dependency. drop-zone's Homebrew formula should need a
// compiler and libcrypto and nothing else, and pulling in a test framework to
// check a few dozen assertions would put a build-time dependency in the way of
// that for no real gain.

#pragma once

#include <cstdio>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace dz::test {

struct Case {
    std::string name;
    std::function<void()> body;
};

/// Every registered case. A function rather than a variable so registration from a
/// static initialiser in another translation unit cannot run before it exists.
inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> body) {
        registry().push_back(Case{name, std::move(body)});
    }
};

/// Thrown by the check macros. Distinct from dz::Error so that a test asserting
/// that something throws cannot accidentally swallow a failed assertion.
class Failure : public std::exception {
public:
    explicit Failure(std::string message) : message_(std::move(message)) {}
    const char* what() const noexcept override { return message_.c_str(); }

private:
    std::string message_;
};

}  // namespace dz::test

/// Define a test case.
#define DZ_TEST(name)                                                          \
    static void name();                                                        \
    static const ::dz::test::Registrar registrar_##name(#name, name);          \
    static void name()

#define DZ_CHECK(condition)                                                            \
    do {                                                                               \
        if (!(condition)) {                                                            \
            throw ::dz::test::Failure(std::string(__FILE__) + ":" +                     \
                                      std::to_string(__LINE__) + ": expected " +        \
                                      #condition);                                      \
        }                                                                              \
    } while (false)

#define DZ_CHECK_EQUAL(actual, expected)                                                        \
    do {                                                                                        \
        auto dz_actual = (actual);                                                              \
        auto dz_expected = (expected);                                                          \
        if (!(dz_actual == dz_expected)) {                                                      \
            throw ::dz::test::Failure(std::string(__FILE__) + ":" + std::to_string(__LINE__) +   \
                                      ": " #actual " != " #expected);                            \
        }                                                                                       \
    } while (false)

/// Require that `expression` throws something derived from std::exception.
#define DZ_CHECK_THROWS(expression)                                                             \
    do {                                                                                        \
        bool dz_threw = false;                                                                  \
        try {                                                                                   \
            expression;                                                                         \
        } catch (const ::dz::test::Failure&) {                                                  \
            throw;                                                                              \
        } catch (const std::exception&) {                                                       \
            dz_threw = true;                                                                    \
        }                                                                                       \
        if (!dz_threw) {                                                                        \
            throw ::dz::test::Failure(std::string(__FILE__) + ":" + std::to_string(__LINE__) +   \
                                      ": expected " #expression " to throw");                    \
        }                                                                                       \
    } while (false)
