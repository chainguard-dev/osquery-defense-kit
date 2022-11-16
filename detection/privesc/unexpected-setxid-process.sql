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
    '/bin/ps',
    '/Library/Application Support/org.pqrs/Karabiner-Elements/bin/karabiner_session_monitor',
    '/Library/DropboxHelperTools/Dropbox_u501/dbkextd',
    '/opt/1Password/1Password-BrowserSupport',
    '/opt/1Password/1Password-KeyringHelper',
    '/usr/bin/keybase-redirector',
    '/usr/bin/doas',
    '/usr/bin/fusermount',
    '/usr/bin/fusermount3',
    '/usr/bin/login',
    '/usr/bin/mount',
    '/usr/bin/ssh-agent',
    '/usr/bin/su',
    '/usr/bin/sudo',
    '/usr/bin/top',
    '/usr/lib/xf86-video-intel-backlight-helper',
    '/usr/lib/Xorg.wrap',
    '/usr/sbin/traceroute'
  );
