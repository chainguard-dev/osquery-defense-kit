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
  ppp.path AS gparent_path,
  ppp.name AS gparent_name,
  TRIM(p.cmdline) AS parent_cmd,
  pp.euid AS parent_euid,
  phash.sha256 AS parent_sha256,
  gphash.sha256 AS gparent_sha256
FROM
  uptime,
  process_events p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN processes ppp ON pp.parent = ppp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash AS phash ON pp.path = phash.path
  LEFT JOIN hash AS gphash ON ppp.path = gphash.path
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
    OR (
      p.euid = 0
      AND (
        cmd LIKE '%pkill -f%'
        OR cmd LIKE '%xargs kill -9%'
      )
    )
    OR cmd LIKE '%rm -f /var/tmp%'
    OR cmd LIKE '%rm -f /tmp%'
    OR cmd LIKE '%nohup /bin/bash%'
    OR cmd LIKE '%history'
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
      AND NOT parent_name IN ('sh', 'java')
    )
    OR cmd LIKE '%socat%'
    OR cmd LIKE '%SOCK_STREAM%'
    OR (
      cmd LIKE '%Socket.%'
      AND NOT basename IN ('compile', 'sed', 'mv', 'cover')
      AND NOT cmd LIKE "%sys/socket.h%"
      AND NOT cmd LIKE "%websocket%"
      AND NOT cmd LIKE "%socket.go%"
      AND NOT cmd LIKE "%socket.cpython%"
    )
  ) -- Things that could reasonably happen at boot.
  AND NOT (
    p.path = '/usr/bin/mkfifo'
    AND cmd LIKE '%/org.gpgtools.log.%/fifo'
  )
  AND NOT (
    cmd LIKE '%csrutil status'
    AND parent_name IN ('Dropbox')
  )
  AND NOT (
    cmd IN (
      '/bin/launchctl asuser 0 /bin/launchctl list',
      '/bin/launchctl list',
      '/bin/launchctl list com.logi.optionsplus.update',
      '/bin/launchctl list homebrew.mxcl.yabai',
      'launchctl list com.parallels.desktop.launchdaemon',
      'launchctl list us.zoom.ZoomDaemon',
      '/Library/Apple/System/Library/StagedFrameworks/Safari/SafariShared.framework/XPCServices/com.apple.Safari.History.xpc/Contents/MacOS/com.apple.Safari.History',
      'sudo launchctl list us.zoom.ZoomDaemon',
      '/usr/bin/csrutil report',
      '/usr/bin/csrutil status',
      'xpcproxy com.apple.Safari.History'
    )
    -- The source of these commands is still a mystery to me.
    OR p.parent = -1
  )
  AND NOT cmd LIKE '/bin/rm -f /tmp/periodic.%'
  AND NOT cmd LIKE 'rm -f /tmp/locate%/_updatedb%'
  AND NOT cmd LIKE 'rm -f /tmp/locate%/mklocate%/_mklocatedb%'
  AND NOT cmd LIKE 'rm -f /tmp/insttmp_%'
  AND NOT cmd LIKE '/bin/cp %history%sessions/%'
  AND NOT cmd LIKE 'touch -r /tmp/KSInstallAction.%'
  AND NOT cmd LIKE '%find /Applications/LogiTuneInstaller.app -type d -exec chmod 777 {}%'
  AND NOT cmd LIKE '/bin/rm -f /tmp/com.adobe.%.updater/%'
  AND NOT cmd LIKE 'dirname %history'
