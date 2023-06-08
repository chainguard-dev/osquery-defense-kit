-- Find processes that run with a lower effective UID than their parent (event-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1548/001/ (Setuid and Setgid)
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- related:
--   * unexpected-privilege-escalation.sql
--
-- False positives:
--   * On some hosts this ocassionally gets the parenting relationship confused
--
-- tags: events process escalation disabled
-- platform: linux
-- interval: 600
SELECT
  file.mode AS p0_binary_mode,
  -- Child
  pe.path AS p0_path,
  pe.time AS p0_time,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.uid AS p0_uid,
  pe.euid AS p0_euid,
  pe.pid AS p0_pid,
  p.cgroup_path AS p0_cgroup,
  -- Parent
  pe.parent AS p1_pid,
  p1.cgroup_path AS p1_cgroup,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p1.euid, pe1.euid) AS p1_euid,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  COALESCE(p1_p2.cgroup_path, pe1_p2.cgroup_path) AS p2_cgroup,
  TRIM(
    COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)
  ) AS p2_cmd,
  COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path) AS p2_path,
  COALESCE(
    p1_p2_hash.path,
    pe1_p2_hash.path,
    pe1_pe2_hash.path
  ) AS p2_hash,
  REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS p2_name
FROM
  process_events pe
  LEFT JOIN file ON pe.path = file.path
  LEFT JOIN processes p ON pe.pid = pe.pid -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
WHERE
  pe.pid IN (
    SELECT
      pid
    FROM
      process_events
    WHERE
      time > (strftime('%s', 'now') -600)
      AND syscall = "execve"
      AND euid < 500
      AND (
        uid = 0
        OR euid < uid
      )
  )
  AND pe.time > (strftime('%s', 'now') -600)
  AND pe.syscall = "execve"
  AND pe.euid < 500
  AND (
    pe.euid < pe.uid
    OR pe.euid < p1_euid
    OR pe.euid < pe1.euid
  )
  AND pe.path NOT IN (
    '/bin/ps',
    '/opt/1Password/1Password-KeyringHelper',
    '/usr/bin/doas',
    '/usr/bin/su',
    '/usr/bin/fusermount',
    '/usr/bin/fusermount3',
    '/usr/bin/gpg',
    '/usr/bin/gpgconf',
    '/usr/bin/gpgsm',
    '/usr/bin/i3lock',
    '/usr/bin/login',
    '/usr/bin/nvidia-modprobe',
    '/usr/bin/sudo',
    '/usr/bin/top',
    '/usr/bin/unix_chkpwd',
    '/usr/lib/slack/chrome-sandbox',
    '/usr/lib/snapd/snap-confine',
    '/usr/lib/snapd/snap-update-ns',
    '/usr/lib/systemd/systemd',
    '/usr/lib/Xorg.wrap',
    '/usr/lib/xorg/Xorg.wrap'
  )
  AND pe.path NOT LIKE '/nix/store/%/bin/sudo'
  AND pe.path NOT LIKE '/nix/store/%/bin/dhcpcd'
  AND pe.path NOT LIKE '/snap/snapd/%/usr/lib/snapd/snap-confine'
  AND pe.path NOT LIKE '/snap/snapd/%/usr/lib/snapd/snap-update-ns'
  AND NOT p1_cmd IN (
    '/usr/lib/systemd/systemd --user',
    '/bin/sh -c /usr/bin/pkexec /usr/share/apport/apport-gtk'
  )
  AND NOT p0_cmd = '/usr/bin/pkexec /usr/lib/update-notifier/package-system-locked'
  AND NOT (
    p0_name = 'polkit-agent-helper-1'
    AND p1_path IN (
      '/usr/bin/gnome-shell',
      '/usr/lib/gvfsd',
      '/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1'
    )
  )
  AND NOT (
    p0_name = 'fusermount3'
    AND p1_path = '/usr/lib/xdg-document-portal'
  )
  AND NOT (
    p0_name IN ('dash', 'pkexec')
    AND p1_path = '/usr/bin/update-notifier'
  ) -- A bizarro persistent false-positive from an Arch linux host
  AND NOT (
    p.cgroup_path = "/init.scope"
    AND p1.cgroup_path != "/init.scope"
  )
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
  AND NOT p1.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY
  pe.pid
