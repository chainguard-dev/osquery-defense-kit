-- Find processes that run with a lower effective UID than their parent (state-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1548/001/ (Setuid and Setgid)
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- related:
--   * unexpected-privilege-escalation-events.sql
--
-- tags: transient state process escalation
-- platform: linux
SELECT
  p0.uid AS p0_uid,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.pid IN (
    SELECT
      pid
    FROM
      processes
    WHERE
      euid < uid
      AND NOT path IN (
        '/bin/ps',
        '/opt/1Password/1password',
        '/usr/bin/doas',
        '/usr/bin/fusermount',
        '/usr/bin/fusermount3',
        '/usr/bin/login',
        '/usr/bin/su',
        '/usr/bin/sudo',
        '/usr/bin/top',
        '/usr/libexec/Xorg',
        '/usr/lib/xorg/Xorg'
      ) -- doas may be in the process of being upgraded
      AND NOT path LIKE '/nix/store/%/bin/sudo'
      AND NOT path LIKE '/nix/store/%/bin/dhcpcd'
      AND NOT path LIKE '/snap/snapd/%/usr/lib/snapd/snap-confine'
      AND NOT name IN ('doas', 'sudo')
  )
  AND NOT (
    p0.cmdline LIKE '%pacman%'
    AND p1.cmdline LIKE 'yay%'
  )
  AND NOT (
    p0.name = 'polkit-agent-he'
    AND p1.path = '/usr/bin/gnome-shell'
  )
  AND NOT (
    p0.name = 'fusermount3'
    AND p1.path = '/usr/lib/xdg-document-portal'
  )
  AND NOT (
    p0.path = '/usr/bin/pkexec'
    AND p1.path = '/usr/bin/update-notifier'
  )
  AND NOT (
    p0.path = '/usr/libexec/xdg-permission-store'
    AND p1.path = '/usr/lib/systemd/systemd'
  )
