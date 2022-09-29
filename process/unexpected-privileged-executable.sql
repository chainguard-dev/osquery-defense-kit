SELECT
  p.pid,
  p.name,
  p.path,
  p.cmdline,
  p.cwd,
  p.uid,
  f.mode
FROM
  processes p
  JOIN file f ON p.path = f.path
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
    "/usr/bin/top"
  );
