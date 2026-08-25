# ADR-048: Vision Decoder content-addressed releases v1

Status: R1 repository-only / no release installation / no systemd installation

The decoder Worker and the Pillow Probe are two independent immutable release
trees. The Worker release contains only the decoder package and its runtime ADR.
The Probe release contains the channel-neutral transport types, the Pillow Probe,
and the exact inactive policy document. A canonical manifest binds every source,
destination, mode, and SHA-256; its identity document determines the release
digest.

The service template is rendered only with two 64-hex release digests. After
rendering, its code, policy, and documentation paths all point to exact release
directories. Mutable repository paths, `current`, `latest`, `/usr/local`, and
the former mutable policy directory are rejected.

This stage does not build into `/opt`, install units, create a user, run
`daemon-reload`, create the marker, open a socket, inspect user media, call a
model, or connect a channel. A later work-only build must first produce and
verify both release trees and the rendered unit evidence.

