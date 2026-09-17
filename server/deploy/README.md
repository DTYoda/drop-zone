# drop-zone-server deployment files.
#
# drop-zone-server.service   systemd unit. Sandboxed: DynamicUser, no home, no
#                            writes, no core dumps. Point ExecStart at wherever
#                            the binary was installed.
# Dockerfile                 multi-stage build producing a debian image that
#                            contains only the daemon and libssl.
#
# The process itself also sets RLIMIT_CORE 0 and never opens a file for write.
# The unit and the image repeat that promise from the outside so a
# misconfiguration cannot put a session table on disk.
