-- A program where the parent PID is not on disk
--
-- Reveals boopkit if a child is spawned
-- TODO: Make mount namespace aware
--
-- false positives:
--   * none observed
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/004/ (Indicator Removal on Host: File Deletion)
--
-- false positives:
--   * none observed
--
-- tags: persistent daemon
SELECT
  p.name AS child_name,
  p.pid AS child_pid,
  p.path AS child_path,
  p.cmdline AS child_cmd,
  p.euid AS child_euid,
  p.gid AS child_gid,
  hash.path,
  p.on_disk AS child_on_disk,
  pp.pid AS parent_pid,
  pp.name AS parent_name,
  pp.path AS parent_path,
  pp.cmdline AS cmd,
  pp.on_disk AS parent_on_disk,
  pp.uid AS parent_uid,
  pp.gid AS parent_gid
FROM
  processes p
  JOIN processes pp ON pp.pid = p.parent
  LEFT JOIN hash ON p.path = hash.path
WHERE
  parent_on_disk != 1
  AND child_on_disk = 1
  AND NOT child_pid IN (1, 2)
  AND NOT parent_pid IN (1, 2) -- launchd, kthreadd
  AND NOT parent_path IN (
    '/opt/google/chrome/chrome',
    '/usr/lib/systemd/systemd',
    '/usr/bin/dockerd',
    '/usr/bin/gnome-shell'
  ) -- long-running launchers
  AND NOT parent_name IN (
    'lightdm',
    'nvim',
    'gnome-shell',
    'slack',
    'kube-proxy',
    'kubelet'
  ) -- These alerts were unfortunately useless - lots of spam on macOS
  AND NOT (
    parent_path = ''
    AND p.uid > 500
  )
  AND parent_path NOT LIKE '/app/extra/%'
  AND parent_path NOT LIKE '/opt/homebrew/Cellar/%'
  AND NOT (
    parent_name LIKE 'kworker/%+events_unbound'
    AND child_name IN ('modprobe')
  )
