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
  AND p.start_time > (strftime('%s', 'now') - 601) -- Filter out transient processes that may not have an envs entry by the time we poll for it
  AND p.start_time < (strftime('%s', 'now') - 1)
  AND p.parent NOT IN (0, 2)
  AND NOT p.path IS NULL
  AND p.name NOT IN (
    'applydeltarpm',
    'bwrap',
    'cupsd',
    'dhcpcd',
    'modprobe',
    'dnf',
    'gdm-session-wor',
    'gpg-agent',
    'nginx',
    'sshd',
    'zypak-sandbox'
  )
  AND NOT (
    p.name LIKE 'systemd-%'
    AND p.parent = 1
  )
  AND NOT pp.cmdline LIKE 'bwrap %'
  AND NOT p.cmdline LIKE '%--type=zygote%'
  AND NOT p.cmdline LIKE '%--disable-seccomp-filter-sandbox%'
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY
  p.pid
HAVING
  count == 0;
