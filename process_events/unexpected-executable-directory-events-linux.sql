-- Events version of unexpected-executable-directory
-- Designed for execution every minute (where the parent may still be around)
SELECT pe.pid,
    pe.path,
    REGEX_MATCH(pe.path, "(.*)/", 1) AS dirname,
    pe.mode,
    pe.cwd,
    pe.euid,
    pe.parent,
    pp.path AS parent_path,
    pp.name AS parent_name,
    pp.cmdline AS parent_cmd,
    pp.euid AS parent_euid,
    phash.sha256 AS parent_sha256,
    hash.sha256 AS sha256
FROM process_events pe
    LEFT JOIN processes p ON pe.pid = pe.pid
    LEFT JOIN processes pp ON pe.parent = p.pid
    LEFT JOIN hash ON pe.path = hash.path
    LEFT JOIN hash phash ON pp.path = hash.path
WHERE pe.time > (strftime("%s", "now") -15)
    AND dirname NOT LIKE "/home/%"
    AND dirname NOT LIKE "/nix/store/%/bin"
    AND dirname NOT LIKE "/nix/store/%/lib/%"
    AND dirname NOT LIKE "/nix/store/%/libexec"
    AND dirname NOT LIKE "/nix/store/%/libexec/%"
    AND dirname NOT LIKE "/nix/store/%/share/%"
    AND dirname NOT LIKE "/opt/%"
    AND dirname NOT LIKE "/tmp/go-build%"
    AND dirname NOT LIKE "/snap/%"
    AND dirname NOT LIKE "/usr/libexec/%"
    AND dirname NOT LIKE "/usr/local/%/bin/%"
    AND dirname NOT LIKE "/usr/local/%bin"
    AND dirname NOT LIKE "/usr/local/%libexec"
    and dirname NOT LIKE "/usr/local/Cellar/%"
    AND dirname NOT LIKE "/usr/lib/%"
    AND dirname NOT LIKE "/usr/lib64/%"
    AND dirname NOT LIKE "/tmp/%/bin"
    AND dirname NOT LIKE "/usr/local/go/pkg/tool/%"
    AND dirname NOT IN (
        "/bin",
        "/ko-app",
        "/sbin",
        "/usr/bin",
        "/usr/lib",
        "/usr/lib/bluetooth",
        "/usr/lib/cups/notifier",
        "/usr/lib/evolution-data-server",
        "/usr/lib/fwupd",
        "/usr/lib/ibus",
        "/usr/lib/libreoffice/program",
        "/usr/lib/polkit-1",
        "/usr/lib/slack",
        "/usr/lib/firefox",
        "/usr/lib/snapd",
        "/usr/lib/systemd",
        "/usr/lib/telepathy",
        "/usr/lib/udisks2",
        "/usr/lib/xorg",
        "/usr/lib/firefox",
        "/usr/lib64/firefox",
        "/usr/libexec",
        "/usr/libexec/ApplicationFirewall",
        "/usr/libexec/rosetta",
        "/usr/sbin",
        "/",
        "/app",
        "/usr/share/code"
    )
    AND NOT pe.path IN (
        "/usr/lib32/ld-linux.so.2"
    )
    AND NOT (
        dirname = ""
        AND p.name LIKE "runc%"
    )
    AND NOT (
        dirname = ""
        AND parent_name IN ("dockerd")
    )
    AND NOT (pe.euid = 65532)
GROUP BY pe.pid