// Turning what the user typed into a list of files to send.
//
// The prototype walked directories with readdir and sent each file's bytes with
// nothing in between, which meant the receiver had no way to know where one file
// ended and the next began, or what to call any of them. A manifest fixes that:
// the receiver learns every path, size and mode before a single byte of content
// arrives, so it can create the directories, reserve the space, and refuse the
// whole transfer if anything about it looks wrong.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "dz/protocol.hpp"

namespace dz::client {

/// One file to send: where it is locally, and what the receiver should call it.
struct LocalFile {
    /// Path on this machine, as it will be opened.
    std::string source_path;
    /// Path relative to the receiver's output directory.
    std::string relative_path;
    std::uint64_t size = 0;
    std::uint32_t mode = 0644;
};

struct Manifest {
    std::vector<LocalFile> files;
    std::uint64_t total_bytes = 0;
    /// What to show the user: a filename, a directory name, or "3 items".
    std::string display_name;
};

/// Expand the command line's inputs into a manifest.
///
/// A file contributes itself. A directory contributes everything beneath it,
/// with paths relative to the directory's own name so that sending `./photos`
/// creates `photos/` on the other side rather than scattering its contents.
/// Symbolic links are not followed: following them would let a link inside a
/// directory copy something the user never meant to send, and can produce an
/// unbounded walk through a cycle.
Manifest build_manifest(const std::vector<std::string>& inputs);

/// Fill in each entry's SHA-256. Costs a full read pass, which is why it only
/// happens when --verify asks for it.
void compute_digests(Manifest& manifest, std::vector<ManifestEntry>& entries);

/// Convert to the wire form.
std::vector<ManifestEntry> to_wire_entries(const Manifest& manifest);

/// Where each file the receiver has been offered should be written, having
/// checked that every path stays inside `output_directory`.
///
/// The check matters because the paths came from the network: a peer that could
/// get "../../.ssh/authorized_keys" accepted would have write access to anywhere
/// the receiving user can write.
std::vector<std::string> resolve_output_paths(const std::vector<ManifestEntry>& entries,
                                              const std::string& output_directory);

}  // namespace dz::client
