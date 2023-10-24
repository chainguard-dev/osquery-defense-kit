-- Slow query to find root programs with an open socket and few shared libraries
--
-- false positives:
--   * some minimalist daemons
--
-- references:
--   * https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game
--
-- tags: persistent process state seldom
-- platform: macos
SELECT
  p.uid,
  p.euid,
  pos.protocol,
  pos.pid,
  pos.remote_address,
  pos.local_address,
  pos.local_port,
  pos.remote_port,
  p.name,
  p.start_time,
  p.parent,
  p.cgroup_path,
  p.path,
  pos.state,
  GROUP_CONCAT(DISTINCT pmm.path) AS libs,
  COUNT(DISTINCT pmm.path) AS lib_count,
  -- Normally we would use signatures for exceptions, but it was triggering
  -- an unusual performance issue in osquery.
  CONCAT (MIN(p.euid, 500), ',', p.name, ',', p.path) AS exception_key
FROM
  processes p
  -- For some reason, joining this table increases the runtime by 30X
  -- LEFT JOIN signature s ON p.path = s.path
  JOIN process_memory_map pmm ON p.pid = pmm.pid
  JOIN process_open_sockets pos ON p.pid = pos.pid
WHERE
  p.pid IN (
    SELECT
      processes.pid
    FROM
      processes
      JOIN process_open_sockets ON processes.pid = process_open_sockets.pid
      AND family != 1
    WHERE
      processes.path NOT LIKE '/System/%'
      -- TODO: consider whitelisting /Applications/%.app/Contents/MacOS/%
      AND processes.path NOT LIKE '/Library/Apple/%'
      AND processes.path NOT LIKE '/usr/libexec/%'
      AND processes.path NOT LIKE '/usr/sbin/%'
      AND processes.path NOT LIKE '/sbin/%'
      AND processes.path NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%'
      AND processes.path NOT LIKE '/usr/bin/%'
      AND processes.path NOT LIKE '/nix/store/%/bin/nix'
      AND processes.path NOT LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
      AND processes.path NOT LIKE '/usr/local/kolide-k2/bin/launcher-updates/%/Kolide.app/Contents/MacOS/launcher'
      AND processes.start_time < (strftime('%s', 'now') -600)
    GROUP BY
      processes.path
  )
  AND pmm.path LIKE "%.dylib"
  AND exception_key NOT IN (
    '500,Bitwarden,/Applications/Bitwarden.app/Contents/MacOS/Bitwarden',
    '500,Evernote,/Applications/Evernote.app/Contents/MacOS/Evernote',
    '500,Skitch,/Applications/Skitch.app/Contents/MacOS/Skitch',
    '500,monday.com,/Applications/monday.com.app/Contents/MacOS/monday.com',
    '500,J8RPQ294UB.com.skitch.SkitchHelper,/Applications/Skitch.app/Contents/Library/LoginItems/J8RPQ294UB.com.skitch.SkitchHelper.app/Contents/MacOS/J8RPQ294UB.com.skitch.SkitchHelper',
    '500,Revolt,/Applications/Revolt.app/Contents/MacOS/Revolt',
    '500,Revolt Helper,/Applications/Revolt.app/Contents/Frameworks/Revolt Helper.app/Contents/MacOS/Revolt Helper',
    '500,Revolt Helper (GPU),/Applications/Revolt.app/Contents/Frameworks/Revolt Helper (GPU).app/Contents/MacOS/Revolt Helper (GPU)',
    '500,Slack,/Applications/Slack.app/Contents/MacOS/Slack',
    '500,Slack Helper (GPU),/Applications/Slack.app/Contents/Frameworks/Slack Helper (GPU).app/Contents/MacOS/Slack Helper (GPU)',
    '500,Slack Helper (Renderer),/Applications/Slack.app/Contents/Frameworks/Slack Helper (Renderer).app/Contents/MacOS/Slack Helper (Renderer)',
    '500,Snagit 2020,/Applications/Snagit 2020.app/Contents/MacOS/Snagit 2020',
    '500,SnagitHelper2020,/Applications/Snagit 2020.app/Contents/Library/LoginItems/SnagitHelper2020.app/Contents/MacOS/SnagitHelper2020',
    '500,Todoist,/Applications/Todoist.app/Contents/MacOS/Todoist',
    '500,WhatsApp Helper (GPU),/Applications/WhatsApp.app/Contents/Frameworks/WhatsApp Helper (GPU).app/Contents/MacOS/WhatsApp Helper (GPU)'
  )
  AND exception_key NOT LIKE '500,MacVim,/%/MacVim.app/Contents/MacOS/MacVim'
  AND exception_key NOT LIKE '500,PrinterProxy,/Users/%/Library/Printers/Brother %.app/Contents/MacOS/PrinterProxy'
  AND exception_key NOT LIKE '500,Steam Helper,/Users/%/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/Frameworks/Steam Helper.app/Contents/MacOS/Steam Helper'
GROUP BY
  pos.pid
HAVING
  lib_count IN (1, 2)
  AND libs NOT LIKE '/Applications/%/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/libffmpeg.dylib,/usr/lib/libobjc-trampolines.dylib'
  AND libs NOT LIKE '/usr/lib/libobjc-trampolines.dylib,/Applications/%.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/libffmpeg.dylib'
