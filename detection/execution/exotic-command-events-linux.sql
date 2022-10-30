-- Pick out exotic processes based on their command-line (events-based)
--
-- references:
--   * https://themittenmac.com/what-does-apt-activity-look-like-on-macos/
--
-- false positives:
--   * possible, but none known
--
-- tags: transient process events
-- platform: linux
-- interval: 60
SELECT
  p.pid,
  p.path,
  REPLACE(
    p.path,
    RTRIM(p.path, REPLACE(p.path, '/', '')),
    ''
  ) AS basename,
  -- On macOS there is often a trailing space
  TRIM(p.cmdline) AS cmd,
  p.mode,
  p.cwd,
  p.euid,
  p.parent,
  p.syscall,
  hash.sha256,
  pp.path AS parent_path,
  pp.name AS parent_name,
  TRIM(p.cmdline) AS parent_cmd,
  pp.euid AS parent_euid,
  phash.sha256 AS parent_sha256
FROM
  uptime,
  process_events p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash AS phash ON pp.path = phash.path
WHERE
  p.time > (strftime('%s', 'now') -60)
  AND (
    basename IN (
      'bitspin',
      'bpftool',
      'heyoka',
      'nstx',
      'dnscat2',
      'tuns',
      'iodine',
      'rshell',
      'rsh',
      'incbit',
      'insmod',
      'kmod',
      'lushput',
      'mkfifo',
      'msfvenom',
      'nc',
      'socat'
    )
    -- Chrome Stealer
    OR cmd LIKE '%chrome%-load-extension%'
    -- Known attack scripts
    OR basename LIKE '%pwn%'
    OR basename LIKE '%attack%'
    -- Unusual behaviors
    OR cmd LIKE '%ufw disable%'
    OR cmd LIKE '%iptables -P % ACCEPT%'
    OR cmd LIKE '%iptables -F%'
    OR cmd LIKE '%chattr -ia%'
    OR cmd LIKE '%chmod 777 %'
    OR cmd LIKE '%touch%acmr%'
    OR cmd LIKE '%touch -r%'
    OR cmd LIKE '%ld.so.preload%'
    OR cmd LIKE '%urllib.urlopen%'
    OR cmd LIKE '%nohup%tmp%'
    OR cmd LIKE '%iptables stop'
    OR cmd LIKE '%systemctl stop firewalld%'
    OR cmd LIKE '%systemctl disable firewalld%'
    OR cmd LIKE '%pkill -f%'
    OR cmd LIKE '%rm -f%/tmp%'
    OR cmd LIKE '%rm -rf /boot%'
    OR cmd LIKE '%xargs kill -9%'
    OR cmd LIKE '%nohup /bin/bash%'
    OR cmd LIKE '%echo%|%base64 --decode %|%'
    OR cmd LIKE '%UserKnownHostsFile=/dev/null%'
    -- Crypto miners
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
    OR (cmd LIKE '%Socket.%' AND NOT cmd LIKE '%ipc-socket%')
  ) -- Things that could reasonably happen at boot.
  AND NOT (
    p.path IN ('/usr/bin/kmod', '/bin/kmod')
    AND parent_path = '/usr/lib/systemd/systemd'
    AND parent_cmd = '/sbin/init'
  )
  AND NOT (
    p.path IN ('/usr/bin/kmod', '/bin/kmod')
    AND parent_name IN (
      'firewalld',
      'mkinitramfs',
      'systemd',
      'dockerd',
      'kube-proxy'
    )
  )
  AND NOT (
    p.path IN ('/usr/bin/kmod', '/bin/kmod')
    AND uptime.total_seconds < 15
  )
  AND NOT (
    p.path = '/usr/bin/mkfifo'
    AND cmd LIKE '%/org.gpgtools.log.%/fifo'
  )
  AND NOT cmd LIKE '%modprobe -va%'
  AND NOT cmd LIKE 'modprobe -ab%'
  AND NOT cmd LIKE '%modprobe overlay'
  AND NOT cmd LIKE '%modprobe aufs'
  AND NOT cmd IN ('lsmod')
  -- Seen on Ubuntu
  AND NOT cmd LIKE 'rm -f /tmp/apt-key-gpghome.%/pubring.gpg'
  AND NOT cmd LIKE 'rm -f /var/tmp/mkinitramfs_%'
  AND NOT cmd LIKE 'rm -f -- /tmp/%'
