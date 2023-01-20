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
-- interval: 30
SELECT
  pe.path AS path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS child_name,
  TRIM(pe.cmdline) AS cmd,
  pe.pid AS pid,
  pe.euid AS euid,
  pe.parent AS parent_pid,
  TRIM(IIF(pp.cmdline != NULL, pp.cmdline, ppe.cmdline)) AS parent_cmd,
  TRIM(IIF(pp.path != NULL, pp.path, ppe.path)) AS parent_path,
  REGEX_MATCH (
    IIF(pp.path != NULL, pp.path, ppe.path),
    '.*/(.*)',
    1
  ) AS parent_name,
  TRIM(IIF(pp.path != NULL, hash.sha256, ehash.sha256)) AS parent_hash,
  TRIM(IIF(gp.cmdline != NULL, gp.cmdline, gpe.cmdline)) AS gparent_cmd,
  TRIM(IIF(gp.path != NULL, gp.path, gpe.path)) AS gparent_path,
  REGEX_MATCH (
    IIF(gp.path != NULL, gp.path, gpe.path),
    '.*/(.*)',
    1
  ) AS gparent_name,
  IIF(pp.parent != NULL, pp.parent, ppe.parent) AS gparent_pid
FROM
  process_events pe,
  uptime
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON pe.parent = pp.pid
  LEFT JOIN process_events ppe ON pe.parent = ppe.pid
  LEFT JOIN processes gp ON gp.pid = pp.parent
  LEFT JOIN process_events gpe ON ppe.parent = gpe.pid
  LEFT JOIN hash ON pp.path = hash.path
  LEFT JOIN hash ehash ON ppe.path = ehash.path
WHERE
  pe.time > (strftime('%s', 'now') -30)
  AND (
    child_name IN (
      'bitspin',
      'bpftool',
      'heyoka',
      'nstx',
      'dnscat2',
      'tuns',
      'iodine',
      'esxcli',
      'vim-cmd',
      'minerd',
      'cpuminer-multi',
      'cpuminer',
      'httpdns',
      'rshell',
      'rsh',
      'xmrig',
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
    OR child_name LIKE '%pwn%'
    OR child_name LIKE '%attack%'
    -- Unusual behaviors
    OR cmd LIKE '%ufw disable%'
    OR cmd LIKE '%powershell%'
    OR cmd LIKE '%iptables -P % ACCEPT%'
    OR cmd LIKE '%iptables -F%'
    OR cmd LIKE '%chattr -ia%'
    OR cmd LIKE '%chmod %777 %'
    OR (
      INSTR(cmd, 'history') > 0
      AND cmd LIKE '%history'
    )
    OR cmd LIKE '%touch%acmr%'
    OR cmd LIKE '%touch -r%'
    OR cmd LIKE '%ld.so.preload%'
    OR cmd LIKE '%urllib.urlopen%'
    OR cmd LIKE '%nohup%tmp%'
    OR cmd LIKE '%iptables stop'
    OR cmd LIKE '%systemctl stop firewalld%'
    OR cmd LIKE '%systemctl disable firewalld%'
    OR cmd LIKE '%pkill -f%'
    OR (
      cmd LIKE '%xargs kill -9%'
      AND pe.euid = 0
    )
    OR cmd LIKE '%rm -rf /boot%'
    OR cmd LIKE '%nohup /bin/bash%'
    OR cmd LIKE '%echo%|%base64 --decode %|%'
    OR cmd LIKE '%UserKnownHostsFile=/dev/null%'
    -- Crypto miners
    OR cmd LIKE '%monero%'
    OR cmd LIKE '%nanopool%'
    OR cmd LIKE '%nicehash%'
    OR cmd LIKE '%stratum%'
    -- Random keywords
    OR cmd LIKE '%ransom%'
    -- Reverse shells
    OR cmd LIKE '%/dev/tcp/%'
    OR cmd LIKE '%/dev/udp/%'
    OR cmd LIKE '%fsockopen%'
    OR cmd LIKE '%openssl%quiet%'
    OR cmd LIKE '%pty.spawn%'
    OR (
      cmd LIKE '%sh -i'
      AND NOT parent_name IN ('sh', 'java')
    )
    OR cmd LIKE '%socat%'
    OR cmd LIKE '%SOCK_STREAM%'
    OR INSTR(cmd, 'Socket.') > 0
    OR (
      cmd LIKE '%tail -f /dev/null%'
      AND p.cgroup_path NOT LIKE '/system.slice/docker-%'
    )
  ) -- Things that could reasonably happen at boot.
  AND NOT (
    pe.path IN ('/usr/bin/kmod', '/bin/kmod')
    AND parent_path = '/usr/lib/systemd/systemd'
    AND parent_cmd = '/sbin/init'
  )
  AND NOT (
    pe.path IN ('/usr/bin/kmod', '/bin/kmod')
    AND parent_name IN (
      'firewalld',
      'mkinitramfs',
      'systemd',
      'dockerd',
      'kube-proxy'
    )
  )
  AND NOT (
    pe.path IN ('/usr/bin/kmod', '/bin/kmod')
    AND uptime.total_seconds < 15
  )
  AND NOT (
    pe.path = '/usr/bin/mkfifo'
    AND cmd LIKE '%/org.gpgtools.log.%/fifo'
  )
  AND NOT cmd LIKE '%modprobe -va%'
  AND NOT cmd LIKE 'modprobe -ab%'
  AND NOT cmd LIKE '%modprobe overlay'
  AND NOT cmd LIKE '%modprobe aufs'
  AND NOT cmd LIKE 'modprobe --all%'
  AND NOT cmd LIKE 'modinfo -k%'
  -- Invalid command from someones tmux environment
  AND NOT cmd LIKE 'pkill -f cut -c3%'
  AND NOT cmd LIKE 'dirname %history'
  AND NOT cmd LIKE 'tail /%history'
  AND NOT cmd LIKE '%/usr/bin/cmake%Socket.h'
  AND NOT cmd LIKE '%/usr/bin/cmake%Socket.cpp'
  AND NOT cmd LIKE 'find . -executable -type f -name %grep -l GNU Libtool%touch -r%'
  AND NOT child_name IN ('cc1', 'compile', 'cmake', 'cc1plus')
