SELECT pmm.pid,
    p.uid,
    p.gid,
    p.path AS proc_path,
    p.name AS proc_name,
    p.cmdline AS proc_cmd,
    pmm.path AS lib_path
FROM process_memory_map pmm
    JOIN processes p ON pmm.pid = p.pid
WHERE pmm.path LIKE "%libpcap%"
    AND euid = 0
    AND proc_path NOT LIKE "/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd"
    AND proc_path NOT LIKE "/nix/store/%-systemd-%/lib/systemd/systemd-journald"
    AND proc_path NOT LIKE "/nix/store/%-systemd-%/lib/systemd/systemd-logind"
    AND proc_path NOT LIKE "/nix/store/%-systemd-%/bin/udevadm"
    AND proc_path NOT LIKE "/System/Library/%"
    AND proc_path NOT IN (
        '/usr/libexec/UserEventAgent',
        '/usr/sbin/systemstats',
        '/usr/sbin/cupsd'
    )
    AND proc_cmd NOT IN (
        '/nix/var/nix/profiles/default/bin/nix-daemon',
        '/run/current-system/systemd/lib/systemd/systemd',
        '/usr/bin/python3 -s /usr/sbin/firewalld --nofork --nopid'
    )
GROUP BY pmm.pid