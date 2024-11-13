-- Alert on programs running that are unusually old
--
-- false positive:
--   * legimitely ancient programs. For instance, printer drivers.
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/006/ (Indicator Removal on Host: Timestomp)
--
-- tags: transient process state
SELECT
  p.path,
  p.cmdline,
  p.cwd,
  p.pid,
  p.name,
  f.mtime,
  f.ctime,
  p.cgroup_path,
  ((strftime('%s', 'now') - f.ctime) / 86400) AS ctime_age_days,
  ((strftime('%s', 'now') - f.mtime) / 86400) AS mtime_age_days,
  ((strftime('%s', 'now') - f.btime) / 86400) AS btime_age_days,
  h.sha256,
  f.uid,
  m.data,
  f.gid
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN hash h ON p.path = h.path
  LEFT JOIN magic m ON p.path = m.path
WHERE
  (
    ctime_age_days > 1050
    OR mtime_age_days > 1050
  )
  -- Jan 1st, 1980 (the source of many false positives)
  AND f.mtime > 315561600
  AND f.path NOT LIKE '/home/%/idea-IU-223.8214.52/%'
  AND f.directory NOT LIKE '/Applications/%.app/Contents/MacOS'
  AND f.directory NOT LIKE '/Applications/%.app/Contents/Frameworks/%/Resources'
  AND f.directory NOT LIKE '/opt/homebrew/Cellar/%/bin'
  AND f.path NOT IN (
    '/Applications/Gitter.app/Contents/Library/LoginItems/GitterHelperApp.app/Contents/MacOS/GitterHelperApp',
    '/Applications/Pandora.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/crashpad_handler',
    '/Applications/Skitch.app/Contents/Library/LoginItems/J8RPQ294UB.com.skitch.SkitchHelper.app/Contents/MacOS/J8RPQ294UB.com.skitch.SkitchHelper',
    '/Library/Application Support/Logitech/com.logitech.vc.LogiVCCoreService/LogiVCCoreService.app/Contents/MacOS/LogiVCCoreService',
    '/Library/Printers/Brother/Utilities/BrStatusMonitor.app/Contents/MacOS/BrStatusMonitor',
    '/Library/Application Support/Razer/RzUpdater.app/Contents/MacOS/RzUpdater',
    '/Library/Application Support/LogiFacecam.bundle/Contents/MacOS/LogiFacecamService',
    '/Library/Printers/Brother/Utilities/Server/LOGINserver.app/Contents/MacOS/LOGINserver',
    '/Library/Printers/Brother/Filter/rastertobrother2300.bundle/Contents/MacOS/rastertobrother2300',
    '/Applications/Vimari.app/Contents/PlugIns/Vimari Extension.appex/Contents/MacOS/Vimari Extension',
    '/Library/Printers/Brother/Utilities/Server/NETserver.app/Contents/MacOS/NETserver',
    '/Library/Printers/Brother/Utilities/Server/USBAppControl.app/Contents/MacOS/USBAppControl',
    '/Library/Application Support/EPSON/Scanner/ScannerMonitor/Epson Scanner Monitor.app/Contents/MacOS/Epson Scanner Monitor',
    '/Library/Printers/Brother/Utilities/Server/USBserver.app/Contents/MacOS/USBserver',
    '/Library/Printers/Brother/Utilities/Server/WorkflowAppControl.app/Contents/MacOS/WorkflowAppControl',
    '/snap/brackets/138/opt/brackets/Brackets',
    '/snap/brackets/138/opt/brackets/Brackets-node',
    '/usr/bin/i3blocks',
    '/usr/bin/sshfs',
    '/usr/bin/mono-sgen',
    '/usr/bin/xclip',
    '/usr/bin/xsel',
    '/usr/bin/pavucontrol',
    '/usr/bin/espeak',
    '/usr/bin/unpigz',
    '/usr/bin/xsettingsd',
    '/usr/bin/xss-lock',
    '/usr/bin/i3lock',
    '/usr/bin/xbindkeys',
    '/usr/local/bin/dive'
  )
  AND p.name NOT IN (
    'buildkitd',
    'Flycut',
    'kail',
    'Vimari Extension',
    'Android File Transfer Agent',
    'BluejeansHelper',
    'J8RPQ294UB.com.skitch.SkitchHelper',
    'Pandora',
    'Pandora Helper',
    'dlv'
  )
  AND f.path NOT LIKE '/private/var/folders/%/T/AppTranslocation/%/d/Skitch.app/Contents/MacOS/Skitch'
  AND p.cgroup_path NOT LIKE '/user.slice/user-%.slice/user@%.service/user.slice/podman-%'
  AND p.cgroup_path NOT LIKE '/system.slice/docker-%'
  AND p.cgroup_path NOT LIKE '/user.slice/user-%.slice/user@%.service/user.slice/nerdctl-%'
GROUP BY
  p.pid,
  p.path
