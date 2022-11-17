-- Find programs which have cleared their environment
--
-- references:
--   * https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
--
-- tags: persistent state daemon process
-- platform: linux
-- interval: 600
SELECT
  COUNT(key) AS count,
  p.pid,
  p.path,
  p.name,
  p.on_disk,
  hash.sha256,
  p.parent,
  p.cmdline,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmd -- Processes is 20X faster to scan than process_envs
FROM
  processes p
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN process_envs pe ON p.pid = pe.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
WHERE -- This time should match the interval
  p.start_time > (strftime('%s', 'now') - 605) -- Filter out transient processes that may not have an envs entry by the time we poll for it
  AND p.start_time < (strftime('%s', 'now') - 5) -- This pattern is common with kthreadd processes
  AND p.parent NOT IN (0, 2)
  AND NOT p.path IS NULL
  AND p.name NOT IN (
    'gpg-agent',
    'bwrap',
    'spotify',
    'chrome',
    'jcef_helper',
    'slack',
    'gnome-boxes-sea',
    'gnome-contacts-',
    'gnome-clocks',
    'systemd-userwor',
    'nginx',
    'gnome-terminal-',
    'sshd',
    'zoom.real',
    'teams',
    'zoom',
    'zypak-sandbox'
  )
  AND p.path NOT IN (
    '/usr/bin/gpg-agent',
    '/usr/bin/bwrap',
    '/usr/lib/slack/slack',
    '/usr/sbin/nginx',
    '/usr/libexec/gnome-terminal-server',
    '/usr/lib/systemd/systemd-userdbd',
    '/opt/google/chrome/chrome',
    '/opt/spotify/spotify'
  )
  AND NOT pp.name IN ('yum', 'chrome', 'zoom.real', 'ZoomLauncher')
  AND NOT pp.cmdline LIKE 'bwrap %'
  AND NOT p.cmdline LIKE '%--type=zygote%'
  AND NOT p.cmdline LIKE '%--disable-seccomp-filter-sandbox%'
  AND NOT p.cmdline LIKE '%--enable-crashpad%'
GROUP BY
  p.pid
HAVING
  count == 0;
