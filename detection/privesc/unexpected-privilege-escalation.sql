-- Find processes that run with a lower effective UID than their parent (state-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1548/001/ (Setuid and Setgid)
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- related:
--   * unexpected-privilege-escalation-events.sql
--
-- tags: transient rapid state process escalation
-- platform: posix
SELECT
  p.pid AS child_pid,
  p.path AS child_path,
  p.name AS child_name,
  p.cmdline AS child_cmdline,
  p.euid AS child_euid,
  p.state AS child_state,
  file.mode AS child_mode,
  hash.sha256 AS child_hash,
  p.parent AS parent_pid,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  pfile.mode AS parent_mode,
  hash.sha256 AS parent_hash
FROM
  processes p
  JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN file AS pfile ON pp.path = pfile.path
  LEFT JOIN hash AS phash ON pp.path = phash.path
WHERE
  p.euid < pp.euid
  AND p.path NOT IN (
    '/usr/bin/fusermount',
    '/usr/bin/fusermount3',
    '/usr/bin/login',
    '/usr/bin/sudo',
    '/usr/bin/doas',
    '/bin/ps',
    '/usr/bin/top'
  )
  AND p.path NOT LIKE '/nix/store/%/bin/sudo'
  AND p.path NOT LIKE '/nix/store/%/bin/dhcpcd'
  AND NOT (
    p.name = 'polkit-agent-he'
    AND parent_path = '/usr/bin/gnome-shell'
  )
  AND NOT (
    p.name = 'fusermount3'
    AND parent_path = '/usr/lib/xdg-document-portal'
  )
  AND NOT (
    p.path = '/usr/bin/pkexec'
    AND parent_path = '/usr/bin/update-notifier'
  )
  AND NOT (
    p.path = '/usr/libexec/xdg-permission-store'
    AND parent_path = '/usr/lib/systemd/systemd'
  )
