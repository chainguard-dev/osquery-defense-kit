-- Events version of unexpected-executable-directory
-- Designed for execution every minute (where the parent may still be around)
SELECT p.pid,
    p.path AS fullpath,
    REPLACE(p.path, RTRIM(p.path, REPLACE(p.path, "/", "")), "") AS basename,
    REPLACE(p.path, CONCAT("/", REPLACE(p.path, RTRIM(p.path, REPLACE(p.path, "/", "")), "")) , "") AS dirname,
    p.cmdline,
    p.mode,
    p.cwd,
    p.euid,
    p.parent,
    p.syscall,
    pp.path AS parent_path,
    pp.name AS parent_name,
    pp.cmdline AS parent_cmdline,
    pp.euid AS parent_euid,
    hash.sha256 AS parent_sha256
FROM process_events p
    LEFT JOIN processes pp ON p.parent = pp.pid
    LEFT JOIN hash ON pp.path = hash.path
WHERE p.time > (strftime("%s", "now") -60)
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
        "/usr/share/code"
    )
    AND NOT (dirname="" AND name LIKE "runc%")

-- Don't spam alerts with repeated invocations of the same command-line
GROUP BY p.cmdline