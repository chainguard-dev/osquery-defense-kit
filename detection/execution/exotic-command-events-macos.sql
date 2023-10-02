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
-- interval: 180
SELECT -- Child
  pe.path AS p0_path,
  pe.time AS p0_time,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  pe.euid AS p0_euid,
  s.authority AS p0_authority,
  -- Parent
  pe.parent AS p1_pid,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  pe_sig1.authority AS p1_authority,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  TRIM(
    COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)
  ) AS p2_cmd,
  COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path) AS p2_path,
  COALESCE(
    p1_p2_hash.path,
    pe1_p2_hash.path,
    pe1_pe2_hash.path
  ) AS p2_hash,
  REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS p2_name,
  COALESCE(
    p1_p2_sig.authority,
    pe1_p2_sig.authority,
    pe1_pe2_sig.authority
  ) AS p2_authority,
  -- Exception key
  REGEX_MATCH (pe.path, '.*/(.*)', 1) || ',' || MIN(pe.euid, 500) || ',' || REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) || ',' || REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS exception_key
FROM
  process_events pe,
  uptime
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN signature s ON pe.path = s.path -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path
  LEFT JOIN signature pe_sig1 ON pe1.path = pe_sig1.path -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
  LEFT JOIN signature p1_p2_sig ON p1_p2.path = p1_p2_sig.path
  LEFT JOIN signature pe1_p2_sig ON pe1_p2.path = pe1_p2_sig.path
  LEFT JOIN signature pe1_pe2_sig ON pe1_pe2.path = pe1_pe2_sig.path
WHERE
  pe.time > (strftime('%s', 'now') -180)
  AND pe.status = 0
  AND pe.cmdline != ''
  AND pe.cmdline IS NOT NULL
  AND (
    p0_name IN (
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
    OR p0_cmd LIKE '%set visible of front window to false%'
    OR p0_cmd LIKE '%chrome%-load-extension%' -- Known attack scripts
    OR p0_name LIKE '%pwn%'
    OR p0_name LIKE '%attack%' -- Unusual behaviors
    OR p0_cmd LIKE '%chattr -i%'
    OR p0_cmd LIKE '%dd if=/dev/%'
    OR p0_cmd LIKE '%cat /dev/null >%'
    OR p0_cmd LIKE '%truncate -s0 %'
    OR p0_cmd LIKE '%touch%acmr%'
    OR p0_cmd LIKE '%touch -r%'
    OR p0_cmd LIKE '%ld.so.preload%'
    OR p0_cmd LIKE '%urllib.urlopen%'
    OR p0_cmd LIKE '%nohup%tmp%'
    OR p0_cmd LIKE '%killall Terminal%'
    OR (
      pe.euid = 0
      AND (
        p0_cmd LIKE '%pkill -f%'
        OR p0_cmd LIKE '%xargs kill -9%'
      )
    )
    OR p0_cmd LIKE '%rm -f /var/tmp%'
    OR p0_cmd LIKE '%rm -f /tmp%'
    OR p0_cmd LIKE '%nohup /bin/bash%'
    OR (
      INSTR(p0_cmd, 'history') > 0
      AND p0_cmd LIKE '%history'
      AND p0_cmd NOT LIKE '% history'
    )
    OR p0_cmd LIKE '%echo%|%base64 --decode %|%'
    OR p0_cmd LIKE '%echo%|%base64 -d %|%'
    OR p0_cmd LIKE '%launchctl bootout%'
    OR p0_cmd LIKE '%chflags uchg%'
    OR (
      p0_cmd LIKE '%UserKnownHostsFile=/dev/null%'
      AND NOT p1_name = 'limactl'
    ) -- Random keywords
    OR p0_cmd LIKE '%ransom%' -- Reverse shells
    OR p0_cmd LIKE '%fsockopen%'
    OR p0_cmd LIKE '%openssl%quiet%'
    OR p0_cmd LIKE '%pty.spawn%'
    OR (
      p0_cmd LIKE '%sh -i'
      AND NOT p1_name IN ('sh', 'java')
      AND NOT p1_cmd LIKE "%pipenv shell"
    )
    OR p0_cmd LIKE 'socat %'
    OR p0_cmd LIKE '%SOCK_STREAM%'
    OR INSTR(p0_cmd, 'Socket.') > 0
  ) -- Things that could reasonably happen at boot.
  AND NOT (
    pe.path = '/usr/bin/mkfifo'
    AND (
      p0_cmd LIKE '%/org.gpgtools.log.%/fifo'
      OR p0_cmd LIKE '%/var/%/gitstatus.POWERLEVEL9K.%'
      OR p0_cmd LIKE '%/var/%/p10k.worker.%'
    )
  )
  AND NOT (
    p0_cmd LIKE '%csrutil status'
    AND p1_name IN ('Dropbox')
  )
  AND NOT (
    p0_cmd IN (
      '/bin/launchctl bootout gui/501 /Library/LaunchAgents/com.logi.optionsplus.plist',
      '/bin/launchctl bootout system/com.docker.socket',
      '/bin/rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress',
      'git history',
      'dd if=/dev/urandom bs=15 count=1 status=none',
      'launchctl bootout gui/501/com.grammarly.ProjectLlama.UninstallAgent',
      'helm history',
      '/Library/Apple/System/Library/StagedFrameworks/Safari/SafariShared.framework/XPCServices/com.apple.Safari.History.xpc/Contents/MacOS/com.apple.Safari.History',
      'nc -h',
      'nc',
      'nc -uv 8.8.8.8 53',
      'nc localhost 8080 -vz',
      'nix profile history',
      'dd if=/dev/stdin conv=unblock cbs=79',
      'rm -f /tmp/mysql.sock',
      'sh -c launchctl bootout system "/Library/LaunchDaemons/com.ecamm.EcammAudioXPCHelper.plist"',
      '/usr/bin/csrutil report',
      '/usr/bin/csrutil status',
      '/usr/bin/pkill -F /private/var/run/lima/shared_socket_vmnet.pid',
      '/usr/bin/sudo /bin/rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress',
      '/usr/bin/xattr -d com.apple.writer_bundle_identifier /Applications/Safari.app',
      'xpcproxy com.apple.Safari.History'
    ) -- The source of these commands is still a mystery to me.
    OR pe.parent = -1
  )
  AND NOT p0_cmd LIKE 'launchctl bootout gui/501 /Users/%/Library/LaunchAgents/com.elgato.StreamDeck.plist'
  AND NOT p0_cmd LIKE '-history%'
  AND NOT p0_cmd LIKE 'dirname %history'
  AND NOT p0_cmd LIKE '/bin/rm -f /tmp/periodic.%'
  AND NOT p0_cmd LIKE '/bin/rm -f /tmp/nix-shell.%'
  AND NOT p0_cmd LIKE 'touch -r . /private/tmp/nix-build%'
  AND NOT p0_cmd LIKE '%GNU Libtool%touch -r%'
  AND NOT p0_cmd LIKE 'rm -f /tmp/locate%/_updatedb%'
  AND NOT p0_cmd LIKE 'rm -f /tmp/locate%/mklocate%/_mklocatedb%'
  AND NOT p0_cmd LIKE 'rm -f /tmp/insttmp_%'
  AND NOT p0_cmd LIKE '%nc localhost%'
  AND NOT p0_cmd LIKE '/bin/cp %history%sessions/%'
  AND NOT p0_cmd LIKE '%ssh %/lima/%'
  AND NOT p0_cmd LIKE 'touch -r /tmp/KSInstallAction.%'
  AND NOT p0_cmd LIKE '%find /Applications/LogiTuneInstaller.app -type d -exec chmod 777 {}%'
  AND NOT p0_cmd LIKE '/bin/rm -f /tmp/com.adobe.%.updater/%'
  AND NOT p0_name IN ('cc1', 'compile', 'yara')
  AND NOT exception_key IN (
    'dd,500,zsh,login',
    'yara,500,bash,fish',
    'ssh,500,limactl.ventura,launchd',
    'git,500,zsh,login',
    'bat,500,zsh,login',
    'git,500,zsh,goland',
    'sh,0,Ecamm Live,launchd',
    'cat,500,zsh,login'
  )
