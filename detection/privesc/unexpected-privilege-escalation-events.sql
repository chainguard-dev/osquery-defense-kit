-- Find processes that run with a lower effective UID than their parent (event-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1548/001/ (Setuid and Setgid)
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- related:
--   * unexpected-privilege-escalation.sql
--
-- tags: events process escalation
-- platform: posix
-- interval: 30
SELECT
  p.pid AS child_pid,
  p.path AS child_path,
  REGEX_MATCH (RTRIM(file.path, '/'), '.*/(.*?)$', 1) AS child_name,
  p.cmdline AS child_cmdline,
  p.euid AS child_euid,
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
  process_events p
  JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN file AS pfile ON pp.path = pfile.path
  LEFT JOIN hash AS phash ON pp.path = phash.path
WHERE
  p.time > (strftime('%s', 'now') -30)
  AND p.euid < pp.euid
  AND p.path NOT IN (
    '/bin/ps',
    '/usr/bin/doas',
    '/usr/bin/fusermount',
    '/usr/bin/fusermount3',
    '/usr/bin/login',
    '/usr/bin/sudo',
    '/usr/bin/top',
    '/usr/lib/snapd/snap-confine',
    '/usr/lib/snapd/snap-update-ns',
    '/usr/lib/systemd/systemd',
    '/usr/lib/Xorg.wrap',
    '/usr/lib/xorg/Xorg.wrap'
  )
  AND p.path NOT LIKE '/nix/store/%/bin/sudo'
  AND p.path NOT LIKE '/nix/store/%/bin/dhcpcd'
  AND p.path NOT LIKE '/snap/snapd/%/usr/lib/snapd/snap-confine'
  AND NOT (
    child_name = 'polkit-agent-helper-1'
    AND parent_path = '/usr/bin/gnome-shell'
  )
  AND NOT (
    child_name = 'fusermount3'
    AND parent_path = '/usr/lib/xdg-document-portal'
  )
  AND NOT (
    child_name IN ('dash', 'pkexec')
    AND parent_path = '/usr/bin/update-notifier'
  )
