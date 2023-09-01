-- Find programs which spawn root children without propagating environment variables
--
-- references:
--   * https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
--
-- tags: persistent state daemon process
-- interval: 600
-- platform: linux
SELECT
  COUNT(key) AS count,
  p.pid,
  p.path,
  p.name,
  p.on_disk,
  p.cgroup_path,
  hash.sha256,
  p.parent,
  p.cmdline,
  p.cwd,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmd
  -- Processes is 20X faster to scan than process_envs
FROM
  processes p
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN process_envs pe ON p.pid = pe.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
WHERE
  p.euid = 0
  -- This time should match the interval
  AND p.start_time > (strftime('%s', 'now') - 601)
  -- Filter out transient processes that may not have an envs entry by the time we poll for it
  AND p.start_time < (strftime('%s', 'now') - 1)
  AND p.parent NOT IN (0, 2)
  AND NOT p.path IS NULL
  AND p.name NOT IN (
    '1Password-Keyri',
    'abrt-handle-eve',
    'applydeltarpm',
    'bwrap',
    'crond',
    'cupsd',
    'dhcpcd',
    'dnf',
    'fprintd',
    'gdm-session-wor',
    'gdm-x-session',
    'gpg-agent',
    'modprobe',
    'nginx',
    'osqueryi',
    'realmd',
    'dbus-daemon',
    'sedispatch',
    'ssh',
    'sshd',
    'sudo',
    'systemd',
    'systemd-udevd',
    'systemd-userdbd',
    'systemd-userwor',
    '(udev-worker)',
    'Xorg',
    'zfs',
    'zypak-sandbox'
  )
  AND NOT pp.name IN (
    'systemd-userdbd',
    'crond',
    'systemd',
    'systemd-udevd',
    '(udev-worker)'
  )
  AND NOT (
    p.name LIKE 'systemd-%'
    AND p.parent = 1
  )
  AND NOT p.cgroup_path IN ('/system.slice/cronie.service')
  AND NOT pp.cmdline LIKE 'bwrap %'
  AND NOT p.cmdline LIKE '%--type=zygote%'
  AND NOT p.cmdline LIKE '%--disable-seccomp-filter-sandbox%'
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
  AND NOT (
    p.name = 'sh'
    AND p.cgroup_path = '/system.slice/znapzend.service'
  )
GROUP BY
  p.pid
HAVING
  count == 0;
