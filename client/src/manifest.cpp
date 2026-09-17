#include "dz/client/manifest.hpp"

#include <dirent.h>
#include <sys/stat.h>

#include <algorithm>
#include <cstring>

#include "dz/error.hpp"
#include "dz/fileio.hpp"
#include "dz/log.hpp"

namespace dz::client {
namespace {

/// Walk `directory`, adding every regular file beneath it to `out`.
///
/// Uses lstat rather than the d_type from readdir because not every filesystem
/// fills d_type in, and a DT_UNKNOWN entry would otherwise be skipped silently.
void walk_directory(const std::string& directory, const std::string& prefix,
                    std::vector<LocalFile>& out) {
    DIR* handle = ::opendir(directory.c_str());
    if (handle == nullptr) fail_errno("cannot read directory '" + directory + "'");

    struct Guard {
        DIR* handle;
        ~Guard() { ::closedir(handle); }
    } guard{handle};

    // Collected and sorted rather than emitted in readdir order, so that two runs
    // over the same tree produce the same manifest -- which makes a transfer
    // reproducible and a failure easier to reason about.
    std::vector<std::string> names;

    while (dirent* entry = ::readdir(handle)) {
        if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        names.emplace_back(entry->d_name);
    }
    std::sort(names.begin(), names.end());

    for (const std::string& name : names) {
        std::string path = join_path(directory, name);
        std::string relative = prefix.empty() ? name : (prefix + "/" + name);

        struct stat info{};
        if (::lstat(path.c_str(), &info) != 0) fail_errno("cannot stat '" + path + "'");

        if (S_ISDIR(info.st_mode)) {
            walk_directory(path, relative, out);
            continue;
        }

        if (S_ISLNK(info.st_mode)) {
            // Not followed on purpose: a link inside a directory could point
            // anywhere the sending user can read, and a cycle would never
            // terminate.
            log::warn("skipping symbolic link '" + path + "'");
            continue;
        }

        if (!S_ISREG(info.st_mode)) {
            log::warn("skipping '" + path + "', which is not a regular file");
            continue;
        }

        LocalFile file;
        file.source_path = path;
        file.relative_path = relative;
        file.size = static_cast<std::uint64_t>(info.st_size);
        file.mode = static_cast<std::uint32_t>(info.st_mode) & 0777u;
        out.push_back(std::move(file));
    }
}

}  // namespace

Manifest build_manifest(const std::vector<std::string>& inputs) {
    Manifest manifest;

    for (const std::string& input : inputs) {
        std::string path = expand_user_path(input);

        struct stat info{};
        if (::lstat(path.c_str(), &info) != 0) {
            fail_user("cannot send '" + input + "': no such file or directory");
        }

        if (S_ISDIR(info.st_mode)) {
            // The directory's own name becomes the top-level prefix, so sending
            // `./photos` produces `photos/...` on the other side.
            std::string name = base_name(path);
            walk_directory(path, name, manifest.files);
            continue;
        }

        if (!S_ISREG(info.st_mode)) {
            fail_user("cannot send '" + input + "': only regular files and directories are sent");
        }

        LocalFile file;
        file.source_path = path;
        file.relative_path = base_name(path);
        file.size = static_cast<std::uint64_t>(info.st_size);
        file.mode = static_cast<std::uint32_t>(info.st_mode) & 0777u;
        manifest.files.push_back(std::move(file));
    }

    if (manifest.files.empty()) fail_user("nothing to send: no regular files were found");
    if (manifest.files.size() > kMaxManifestEntries) {
        fail_user("that is " + std::to_string(manifest.files.size()) + " files, more than the " +
                  std::to_string(kMaxManifestEntries) + " drop-zone will send in one transfer");
    }

    for (const LocalFile& file : manifest.files) {
        if (!is_safe_relative_path(file.relative_path)) {
            fail("refusing to send '" + file.source_path + "' under the unsafe relative path '" +
                 file.relative_path + "'");
        }
        manifest.total_bytes += file.size;
    }

    if (inputs.size() == 1) {
        manifest.display_name = base_name(expand_user_path(inputs.front()));
    } else {
        manifest.display_name = std::to_string(inputs.size()) + " items";
    }

    return manifest;
}

std::vector<ManifestEntry> to_wire_entries(const Manifest& manifest) {
    std::vector<ManifestEntry> entries;
    entries.reserve(manifest.files.size());

    for (const LocalFile& file : manifest.files) {
        ManifestEntry entry;
        entry.path = file.relative_path;
        entry.size = file.size;
        entry.mode = file.mode;
        entries.push_back(std::move(entry));
    }
    return entries;
}

void compute_digests(Manifest& manifest, std::vector<ManifestEntry>& entries) {
    for (std::size_t i = 0; i < manifest.files.size(); ++i) {
        const LocalFile& file = manifest.files[i];

        MappedFile mapped(file.source_path);
        mapped.advise_sequential();

        // Hashed in one call over the mapping: the kernel faults the pages in as
        // SHA-256 walks them, so this needs no staging buffer of its own.
        Sha256Digest digest = (mapped.size() > 0)
                                  ? sha256(mapped.data(), static_cast<std::size_t>(mapped.size()))
                                  : sha256("", 0);
        std::memcpy(entries[i].digest, digest.data(), digest.size());
    }
}

std::vector<std::string> resolve_output_paths(const std::vector<ManifestEntry>& entries,
                                             const std::string& output_directory) {
    std::vector<std::string> paths;
    paths.reserve(entries.size());

    for (const ManifestEntry& entry : entries) {
        // Already validated when the offer was parsed, but checked again here
        // because this is the point where a path becomes a filesystem operation,
        // and a check that happens somewhere else is a check that can be bypassed
        // by a later code change.
        if (!is_safe_relative_path(entry.path)) {
            fail("the sender offered an unsafe path: '" + entry.path + "'");
        }
        paths.push_back(join_path(output_directory, entry.path));
    }
    return paths;
}

}  // namespace dz::client
