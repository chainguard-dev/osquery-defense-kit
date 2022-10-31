-- Pick out exotic processes based on their command-line (events-based)
--
-- references:
--   * https://themittenmac.com/what-does-apt-activity-look-like-on-macos/
--
-- false positives:
--   * possible, but none known
--
-- tags: transient process events
-- platform: darwin
-- interval: 45
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
  p.time > (strftime('%s', 'now') -45)
  AND (
    basename IN (
      'bitspin',
      'bpftool',
      'csrutil',
      'heyoka',
      'nstx',
      'dnscat2',
      'tuns',
      'iodine',
      'rshell',
      'rsh',
      'incbit',
      'kmod',
      'lushput',
      'mkfifo',
      'msfvenom',
      'nc',
      'socat'
    ) -- Chrome Stealer
    OR cmd LIKE '%set visible of front window to false%'
    OR cmd LIKE '%chrome%-load-extension%' -- Known attack scripts
    OR basename LIKE '%pwn%'
    OR basename LIKE '%attack%' -- Unusual behaviors
    OR cmd LIKE '%chattr -ia%'
    OR cmd LIKE '%chmod 777 %'
    OR cmd LIKE '%touch%acmr%'
    OR cmd LIKE '%touch -r%'
    OR cmd LIKE '%ld.so.preload%'
    OR cmd LIKE '%urllib.urlopen%'
    OR cmd LIKE '%nohup%tmp%'
    OR cmd LIKE '%killall Terminal%'
    OR cmd LIKE '%iptables stop'
    OR cmd LIKE '%pkill -f%'
    OR cmd LIKE '%rm -f /var/tmp%'
    OR cmd LIKE '%rm -rf /boot%'
    OR cmd LIKE '%rm -f /tmp%'
    OR cmd LIKE '%xargs kill -9%'
    OR cmd LIKE '%nohup /bin/bash%'
    OR cmd LIKE '%echo%|%base64 --decode %|%'
    OR cmd LIKE '%launchctl list%'
    OR (
      cmd LIKE '%UserKnownHostsFile=/dev/null%'
      AND NOT parent_name = 'limactl'
    ) -- Random keywords
    OR cmd LIKE '%ransom%' -- Reverse shells
    OR cmd LIKE '%fsockopen%'
    OR cmd LIKE '%openssl%quiet%'
    OR cmd LIKE '%pty.spawn%'
    OR (
      cmd LIKE '%sh -i'
      AND NOT parent_name = 'sh'
    )
    OR cmd LIKE '%socat%'
    OR cmd LIKE '%SOCK_STREAM%'
    OR (
      cmd LIKE '%Socket.%'
      AND NOT basename IN ('compile', 'sed', 'mv')
      AND NOT cmd LIKE "%sys/socket.h%"
    )
  ) -- Things that could reasonably happen at boot.
  AND NOT (
    p.path = '/usr/bin/mkfifo'
    AND cmd LIKE '%/org.gpgtools.log.%/fifo'
  )
  AND NOT (
    cmd LIKE '%csrutil status'
    AND parent_name IN ('Dropbox')
  ) -- The source of these commands is still a mystery to me.
  AND NOT (
    cmd IN (
      '/usr/bin/csrutil status',
      '/usr/bin/csrutil report',
      '/bin/launchctl list',
      '/bin/launchctl list homebrew.mxcl.yabai',
      '/bin/launchctl asuser 0 /bin/launchctl list'
    )
    AND p.parent = -1
  )
  AND NOT cmd LIKE '/bin/rm -f /tmp/periodic.%'
  AND NOT cmd LIKE 'rm -f /tmp/locate%/_updatedb%'
  AND NOT cmd LIKE 'rm -f /tmp/locate%/mklocate%/_mklocatedb%'
  AND NOT cmd LIKE 'touch -r /tmp/KSInstallAction.%'
