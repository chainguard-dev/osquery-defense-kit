-- Processes running that originate from setuid/setgid programs
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
  f.mode NOT LIKE "0%"
  AND f.path NOT IN (
    "/bin/ps",
    "/Library/DropboxHelperTools/Dropbox_u501/dbkextd",
    "/opt/1Password/1Password-BrowserSupport",
    "/opt/1Password/1Password-KeyringHelper",
    "/usr/bin/doas",
    "/usr/bin/mount",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/usr/bin/login",
    "/usr/bin/ssh-agent",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/top",
    "/usr/lib/Xorg.wrap"
  );
