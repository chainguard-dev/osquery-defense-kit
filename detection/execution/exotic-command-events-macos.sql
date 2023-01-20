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
  pe.path AS path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS name,
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
  IIF(pp.parent != NULL, pp.parent, ppe.parent) AS gparent_pid,
  IIF(
    signature.identifier != NULL,
    signature.identifier,
    esignature.identifier
  ) AS parent_identifier,
  IIF(
    signature.authority != NULL,
    signature.authority,
    esignature.authority
  ) AS parent_authority
FROM
  process_events pe
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON pe.parent = pp.pid
  LEFT JOIN process_events ppe ON pe.parent = ppe.pid
  LEFT JOIN processes gp ON gp.pid = pp.parent
  LEFT JOIN process_events gpe ON ppe.parent = gpe.pid
  LEFT JOIN hash ON pp.path = hash.path
  LEFT JOIN hash ehash ON ppe.path = ehash.path
  LEFT JOIN signature ON pp.path = signature.path
  LEFT JOIN signature esignature ON ppe.path = esignature.path
WHERE
  pe.time > (strftime('%s', 'now') -45)
  AND pe.status = 0
  AND (
    name IN (
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
    OR name LIKE '%pwn%'
    OR name LIKE '%attack%' -- Unusual behaviors
    OR cmd LIKE '%powershell%'
    OR cmd LIKE '%chattr -ia%'
    OR cmd LIKE '%chmod%777 %'
    OR cmd LIKE '%touch%acmr%'
    OR cmd LIKE '%touch -r%'
    OR cmd LIKE '%ld.so.preload%'
    OR cmd LIKE '%urllib.urlopen%'
    OR cmd LIKE '%nohup%tmp%'
    OR cmd LIKE '%killall Terminal%'
    OR cmd LIKE '%iptables stop'
    OR (
      pe.euid = 0
      AND (
        cmd LIKE '%pkill -f%'
        OR cmd LIKE '%xargs kill -9%'
      )
    )
    OR cmd LIKE '%rm -f /var/tmp%'
    OR cmd LIKE '%rm -f /tmp%'
    OR cmd LIKE '%nohup /bin/bash%'
    OR (
      INSTR(cmd, 'history') > 0
      AND cmd LIKE '%history'
    )
    OR cmd LIKE '%echo%|%base64 --decode %|%'
    OR cmd LIKE '%launchctl load%'
    OR cmd LIKE '%launchctl bootout%'
    OR cmd LIKE '%chflags uchg%'
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
      AND NOT parent_cmd LIKE "%pipenv shell"
    )
    OR cmd LIKE '%socat%'
    OR cmd LIKE '%SOCK_STREAM%'
    OR INSTR(cmd, 'Socket.') > 0
  ) -- Things that could reasonably happen at boot.
  AND NOT (
    pe.path = '/usr/bin/mkfifo'
    AND cmd LIKE '%/org.gpgtools.log.%/fifo'
  )
  AND NOT (
    cmd LIKE '%csrutil status'
    AND parent_name IN ('Dropbox')
  )
  AND NOT (
    cmd IN (
      'launchctl load /Library/LaunchDaemons/us.zoom.ZoomDaemon.plist',
      'sudo launchctl load /Library/LaunchDaemons/us.zoom.ZoomDaemon.plist',
      '/bin/launchctl load -wF /Library/LaunchAgents/com.adobe.GC.AGM.plist',
      '/bin/rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress',
      'git history',
      '/usr/bin/pkill -F /private/var/run/lima/shared_socket_vmnet.pid',
      '/Library/Apple/System/Library/StagedFrameworks/Safari/SafariShared.framework/XPCServices/com.apple.Safari.History.xpc/Contents/MacOS/com.apple.Safari.History',
      '/usr/bin/csrutil report',
      '/usr/bin/csrutil status',
      'xpcproxy com.apple.Safari.History'
    )
    -- The source of these commands is still a mystery to me.
    OR pe.parent = -1
  )
  AND NOT cmd LIKE '/bin/launchctl load -wF /Users/%/Library/PreferencePanes/../LaunchAgents/com.adobe.GC.Invoker-1.0.plist'
  AND NOT cmd LIKE '/bin/launchctl load -w /Users/%/Library/LaunchAgents/keybase.%.plist'
  AND NOT cmd LIKE '-history%'
  AND NOT cmd LIKE '/bin/rm -f /tmp/periodic.%'
  AND NOT cmd LIKE 'rm -f /tmp/locate%/_updatedb%'
  AND NOT cmd LIKE 'rm -f /tmp/locate%/mklocate%/_mklocatedb%'
  AND NOT cmd LIKE 'rm -f /tmp/insttmp_%'
  AND NOT cmd LIKE '/bin/cp %history%sessions/%'
  AND NOT cmd LIKE 'touch -r /tmp/KSInstallAction.%'
  AND NOT cmd LIKE '%find /Applications/LogiTuneInstaller.app -type d -exec chmod 777 {}%'
  AND NOT cmd LIKE '/bin/rm -f /tmp/com.adobe.%.updater/%'
  AND NOT cmd LIKE '%history'
  AND NOT name IN ('cc1', 'compile')
