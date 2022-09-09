SELECT p.pid,
    p.path,
    p.name,
    p.cmdline,
    p.euid,
    p.parent,
    pp.path AS parent_path,
    pp.name AS parent_name,
    pp.cmdline AS parent_cmdline,
    pp.euid AS parent_euid
FROM processes p
    JOIN processes pp ON p.parent = pp.pid
WHERE p.euid < pp.euid
    AND p.path NOT IN (
        '/usr/bin/fusermount',
        '/usr/bin/fusermount3',
        '/usr/bin/login',
        '/usr/bin/sudo',
        '/usr/bin/doas'
    )
    AND p.path NOT LIKE "/nix/store/%/bin/sudo"
    AND p.path NOT LIKE "/nix/store/%/bin/dhcpcd"
