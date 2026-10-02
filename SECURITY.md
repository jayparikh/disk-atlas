# Security and privacy

Disk Atlas is a local, single-user application. Do not expose its port through
a proxy, public tunnel or firewall rule. Local scan metadata is not encrypted.

The scanner does not read file contents, but paths and metadata can still be
sensitive. Do not include real inventories, exported reports, raw diagnostic
logs or personal screenshots in public reports.

For a security issue, use the repository's private vulnerability reporting
channel if the maintainer has enabled it. Do not publish credentials, personal
data or a detailed exploit in a public issue.

For an ordinary bug, prefer reproduction steps using `--demo` or a small
fictional fixture. Review any diagnostic text for private paths before sharing.
