-- Catch DNS traffic going to machines other than the host-configured DNS server (state-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/004/ (C2: Application Layer Protocol: DNS)
--
-- tags: transient state net often dns
--
-- NOTE: This only supports IPv4 traffic due to an osquery bug with 'dns_resolvers'
SELECT
  s.family,
  protocol,
  s.local_port,
  s.remote_port,
  s.local_address,
  s.remote_address,
  p.name,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  s.pid,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  hash.sha256,
  GROUP_CONCAT(
    (
      SELECT DISTINCT
        address
      FROM
        dns_resolvers
      WHERE
        type = 'nameserver'
        AND address != ''
    ),
    ','
  ) AS sys_resolvers,
  CONCAT (p.name, ',', remote_address, ',', remote_port) AS exception_key
FROM
  process_open_sockets s
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
WHERE
  remote_port IN (53, 5353)
  AND remote_address NOT LIKE '%:%'
  AND s.remote_address NOT LIKE '172.1%'
  AND s.remote_address NOT LIKE '172.2%'
  AND s.remote_address NOT LIKE '172.30.%'
  AND s.remote_address NOT LIKE '172.31.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '127.%'
  AND remote_address NOT IN (
    SELECT DISTINCT
      address
    FROM
      dns_resolvers
    WHERE
      type = 'nameserver'
      and address != ''
  )
  -- systemd-resolve sometimes shows up this way
  -- If we could narrow this down using 'sys_resolvers' I would, but it is misuse of GROUP_CONCAT
  AND NOT (
    s.pid = -1
    AND s.remote_port = 53
    and s.protocol = 17
    and p.parent = ''
  )
  -- Some applications hard-code a safe DNS resolver, or allow the user to configure one
  AND s.remote_address NOT IN (
    '1.1.1.1', -- Cloudflare
    '1.1.1.2', -- Cloudflare
    '8.8.8.8', -- Google
    '8.8.4.4', -- Google (backup)
    '208.67.222.222', -- OpenDNS
    '75.75.75.75', -- Comcast
    '68.105.28.13' -- Cox
  )
  -- Other exceptions
  AND exception_key NOT IN (
    'coredns,0.0.0.0,53',
    'nessusd,50.16.123.71,53',
    'Arc Helper,1.0.0.1,53',
    'syncthing,46.162.192.181,53'
  )
  -- Local DNS servers and custom clients go here
  AND p.path NOT IN (
    '/usr/lib/systemd/systemd-resolved',
    '/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper',
    '/Applications/Spotify.app/Contents/Frameworks/Spotify Helper.app/Contents/MacOS/Spotify Helper'
  )
  AND p.path NOT LIKE '/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/%/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper'
  -- Workaround for the GROUP_CONCAT subselect adding a blank ent
  -- Workaround for the GROUP_CONCAT subselect adding a blank ent
GROUP BY
  s.remote_address,
  s.remote_port
HAVING
  remote_address != ''
