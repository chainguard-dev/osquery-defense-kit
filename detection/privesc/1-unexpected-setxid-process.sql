-- Processes running that originate from setuid/setgid programs
--
-- false-positives:
--   * an unlisted setuid binary
--
-- references:
--   * https://attack.mitre.org/techniques/T1548/001/ (Setuid and Setgid)
--
-- tags: persistent state process escalation
-- platform: posix
SELECT
  p.pid,
  p.name,
  p.path,
  p.cmdline,
  f.ctime,
  p.cwd,
  p.uid,
  f.mode,
  hash.sha256
FROM
  processes p
  JOIN file f ON p.path = f.path
  JOIN hash ON p.path = hash.path
WHERE
  f.mode NOT LIKE '0%'
  AND f.path NOT IN (
    '/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service',
    '/Applications/VMware Fusion.app/Contents/Library/vmware-vmx',
    '/bin/ps',
    '/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/Helpers/launcher',
    '/Library/Application Support/org.pqrs/Karabiner-Elements/bin/karabiner_session_monitor',
    '/Library/DropboxHelperTools/Dropbox_u501/dbkextd',
    '/opt/1Password/1Password-BrowserSupport',
    '/opt/1Password/1Password-KeyringHelper',
    '/opt/Blockbench/chrome-sandbox',
    '/opt/google/chrome/chrome-sandbox',
    '/opt/IRCCloud/chrome-sandbox',
    '/opt/zoom/cef/chrome-sandbox',
    '/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent',
    '/usr/bin/bwrap',
    '/usr/bin/crontab',
    '/usr/bin/doas',
    '/usr/bin/fusermount',
    '/usr/bin/fusermount3',
    '/usr/bin/keybase-redirector',
    '/usr/bin/login',
    '/usr/bin/mount',
    '/usr/bin/newgrp',
    '/usr/bin/op',
    '/usr/bin/passwd',
    '/usr/bin/schroot',
    '/usr/bin/ssh-agent',
    '/usr/bin/su',
    '/usr/bin/sudo',
    '/usr/bin/top',
    '/usr/lib/electron/chrome-sandbox',
    '/usr/lib/electron22/chrome-sandbox',
    '/usr/lib/opt/1Password/1Password-BrowserSupport',
    '/usr/lib/polkit-1/polkit-agent-helper-1',
    '/usr/lib/slack/chrome-sandbox',
    '/usr/lib/xf86-video-intel-backlight-helper',
    '/usr/lib/Xorg.wrap',
    '/usr/sbin/traceroute'
  )
  AND f.filename != 'chrome-sandbox'
  AND f.path NOT LIKE '/Library/Application Support/Google/GoogleUpdater/1%/GoogleUpdater.app/Contents/Helpers/launcher'
  AND f.path NOT LIKE '/opt/homebrew/Cellar/dnsmasq/%/sbin/dnsmasq'
  AND f.path NOT LIKE '/opt/homebrew/Cellar/socket_vmnet/%/bin/socket_vmnet'
  AND f.path NOT LIKE '/Users/%/homebrew/Cellar/socket_vmnet/%/bin/socket_vmnet'
  AND f.path NOT LIKE '/snap/snapd/%/usr/lib/snapd/snap-confine'
