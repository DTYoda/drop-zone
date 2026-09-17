#include "dz/error.hpp"

#include <openssl/err.h>

#include <cstring>
#include <string>

namespace dz {

void fail(std::string_view message) { throw Error(std::string(message)); }

void fail_user(std::string_view message) { throw UserError(std::string(message)); }

void fail_errno(std::string_view what, int err) {
    // strerror_r rather than strerror: drop-zone fails from worker threads, and
    // strerror's buffer is shared.
    char buffer[256];
    const char* text;
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    text = strerror_r(err, buffer, sizeof(buffer));
#else
    text = (strerror_r(err, buffer, sizeof(buffer)) == 0) ? buffer : "unknown error";
#endif
    throw Error(std::string(what) + ": " + text);
}

void fail_openssl(std::string_view what) {
    std::string message(what);

    unsigned long code = ERR_get_error();
    if (code == 0) {
        message += ": libcrypto reported no reason";
    } else {
        char buffer[256];
        ERR_error_string_n(code, buffer, sizeof(buffer));
        message += ": ";
        message += buffer;
    }

    // Drain the rest of the queue so a later failure cannot inherit these
    // entries and report the wrong reason.
    clear_openssl_errors();

    throw Error(message);
}

void clear_openssl_errors() noexcept {
    while (ERR_get_error() != 0) {
    }
}

int check_syscall(int value, std::string_view what) {
    if (value < 0) fail_errno(what);
    return value;
}

}  // namespace dz
