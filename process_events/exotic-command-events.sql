-- Ported from exotic-commands
-- Designed for execution every minute (where the parent may still be around)
SELECT p.pid,
    p.path,
    REPLACE(p.path, RTRIM(p.path, REPLACE(p.path, '/', '')), '') AS basename,
    -- On macOS there is often a trailing space
    TRIM(cmd) AS cmd,
    p.mode,
    p.cwd,
    p.euid,
    p.parent,
    p.syscall,
    pp.path AS parent_path,
    pp.name AS parent_name,
    pcmd AS parent_cmdline,
    pp.euid AS parent_euid,
    hash.sha256 AS parent_sha256
FROM uptime, process_events p
    LEFT JOIN processes pp ON p.parent = pp.pid
    LEFT JOIN hash ON pp.path = hash.path
WHERE p.time > (strftime('%s', 'now') -60)
    AND
    (
        basename IN (
            'bitspin',
            'bpftool',
            'csrutil',
            'incbit',
            'insmod',
            'kmod',
            'lushput',
            'mkfifo',
            'msfvenom',
            'nc',
            'socat'
        )
        OR cmd LIKE '%set visible of front window to false%'
        OR cmd LIKE '%chrome%--load-extension%'

        -- Known attack scripts
        OR basename LIKE '%pwn%'
        OR cmd LIKE '%attack%'
        -- Unusual behaviors
        OR cmd LIKE '%ufw disable%'
        OR cmd LIKE '%iptables -P % ACCEPT%'
        OR cmd LIKE '%iptables -F%'
        OR cmd LIKE '%chattr -ia%'
--        OR cmd LIKE '%base64 -d%'
        OR cmd LIKE '%touch%acmr%'
        OR cmd LIKE '%ld.so.preload%'
        OR cmd LIKE '%urllib.urlopen%'
        OR cmd LIKE '%nohup%tmp%'
        -- Crypto miners
        OR cmd LIKE '%c3pool%'
        OR cmd LIKE '%cryptonight%'
        OR cmd LIKE '%f2pool%'
        OR cmd LIKE '%hashrate%'
        OR cmd LIKE '%hashvault%'
        OR cmd LIKE '%minerd%'
        OR cmd LIKE '%monero%'
        OR cmd LIKE '%nanopool%'
        OR cmd LIKE '%nicehash%'
        OR cmd LIKE '%stratum%'
        OR basename LIKE '%xig%'
        OR basename LIKE '%xmr%'
        -- Random keywords
        OR cmd LIKE '%ransom%'
        -- Reverse shells
        OR cmd LIKE '%/dev/tcp/%'
        OR cmd LIKE '%/dev/udp/%'
        OR cmd LIKE '%fsockopen%'
        OR cmd LIKE '%openssl%quiet%'
        OR cmd LIKE '%pty.spawn%'
        OR cmd LIKE '%sh -i'
        OR cmd LIKE '%socat%'
        OR cmd LIKE '%SOCK_STREAM%'
        OR cmd LIKE '%Socket.fork%'
        OR cmd LIKE '%Socket.new%'
        OR cmd LIKE '%socket.socket%'
    )

    -- Things that could reasonably happen at boot.
    AND NOT (
        p.path IN ('/usr/bin/kmod', '/bin/kmod')
        AND parent_path='/usr/lib/systemd/systemd'
        AND parent_cmdline='/sbin/init'
    )
    AND NOT (
        p.path IN ('/usr/bin/kmod', '/bin/kmod')
        AND parent_name IN ('firewalld')
    )
    AND NOT (
        p.path IN ('/usr/bin/kmod', '/bin/kmod')
        AND uptime.total_seconds < 15
    )
    -- gpgtools
    AND NOT (
        p.path = '/usr/bin/mkfifo'
        AND cmd LIKE '%/org.gpgtools.log.%/fifo'
    )
    -- Dropbox
    AND NOT (
        parent_name = 'Dropbox'
        AND cmd LIKE 'csrutil status'
    )

    -- Docker, kube-proxy
    AND NOT (
        p.path IN ('/usr/bin/kmod', '/bin/kmod')
        AND parent_name IN ('dockerd', 'kube-proxy')
    )
    AND NOT cmd LIKE 'modprobe -va%'
    AND NOT cmd LIKE 'modprobe -ab%'
    AND NOT cmd LIKE '%modprobe overlay'
    AND NOT cmd LIKE '%modprobe aufs'
    AND NOT cmd IN (
        'lsmod'
    )