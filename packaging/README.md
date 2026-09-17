# Packaging drop-zone

Package managers install a **tagged source archive**, not a git branch. This
directory holds the client formula and the checklist for cutting that archive.

The client and the rendezvous daemon are separate packages. A laptop install
must never place `drop-zone-server` on the machine. The Homebrew formula and
the CMake flag `-DDZ_BUILD_SERVER=OFF` enforce that.

## What packagers need

These are the usual blockers for Homebrew, AUR, Nix, and Debian:

1. A DFSG-friendly license at the repo root (`LICENSE`, MIT).
2. Git tags that match `project(... VERSION ...)` in `CMakeLists.txt` (`v1.0.0`
   for version `1.0.0`).
3. An immutable tarball URL with a SHA-256. GitHub publishes
   `https://github.com/DTYoda/drop-zone/archive/refs/tags/v1.0.0.tar.gz` for
   every tag.
4. A build that uses only documented flags: CMake 3.16+, OpenSSL 1.1.1+,
   `-DDZ_NATIVE_ARCH=OFF` for bottles.

## Cutting a release

1. Set `project(drop-zone VERSION X.Y.Z)` in `CMakeLists.txt` and the version
   line in `packaging/man/drop-zone.1`.
2. Merge to `main`.
3. Tag and push:
   ```sh
   git tag -a vX.Y.Z -m "drop-zone X.Y.Z"
   git push origin vX.Y.Z
   ```
4. The `Release` GitHub Action creates a GitHub Release and prints the source
   tarball SHA-256. Or compute it locally:
   ```sh
   ./packaging/homebrew/fill-stable.sh vX.Y.Z
   ```
5. Paste the printed `url` and `sha256` into `packaging/homebrew/drop-zone.rb`,
   then copy that file to `Formula/drop-zone.rb` in
   [DTYoda/homebrew-tap](https://github.com/DTYoda/homebrew-tap).

## Homebrew

The client is on a personal tap:

```sh
brew tap DTYoda/tap
brew install drop-zone
```

The tap is [DTYoda/homebrew-tap](https://github.com/DTYoda/homebrew-tap)
(`Formula/drop-zone.rb`). Keep that file in lockstep with
`packaging/homebrew/drop-zone.rb` in this repo.

Homebrew-core is the next step: it needs a few clean tagged releases,
`brew audit --new`, and `brew test drop-zone`. See
https://docs.brew.sh/How-To-Open-a-Homebrew-Pull-Request.

Do not submit a formula whose `url` points at `branch: "main"`. Core and
BrewTestBot require a checksummed archive.

## Other managers

The same tagged tarball is the input for an AUR `PKGBUILD`, a Nix derivation,
and a Debian source package. Add those recipes after the first `v*` tag; they
are not required to start a Homebrew tap.
