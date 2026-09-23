# README images

PNG diagrams used by the top-level [README](../../README.md). Matching `.svg` sources
are kept beside them for edits; rasterize with:

```sh
rsvg-convert -w 1840 NAME.svg -o NAME.png
```

GitHub (and many Markdown previews) reject or sanitize inline SVGs as image
sources, so the README links the PNG exports.

| File | What it shows |
| --- | --- |
| [logo.png](logo.png) | Project mark (arrow into a notched zone) |
| [hero-banner.png](hero-banner.png) | README header: tagline and compact topology |
| [architecture.png](architecture.png) | Rendezvous introduction vs peer-to-peer transfer |
| [terminal-session.png](terminal-session.png) | Stylized sender/receiver terminals from a real transfer |
| [transport-ladder.png](transport-ladder.png) | TCP → UDP → relay fallback order |
| [trust-model.png](trust-model.png) | What the server learns vs what peers protect |
| [throughput.png](throughput.png) | Loopback AES-256-GCM numbers from PERFORMANCE.md |
