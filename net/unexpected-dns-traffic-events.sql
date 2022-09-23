-- Catch DNS traffic going to machines other than the host-configured DNS server
-- NOTE: This only supports IPv4 traffic due to an osquery bug with "dns_resolvers"

-- The non-event version is unexpected-dns-traffic.sql
SELECT
  protocol,
  s.remote_port,
  s.remote_address,
  p.name,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  s.pid,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  hash.sha256,
  CONCAT(
    p.name,
    ",",
    remote_address,
    ",",
    remote_port
  ) AS exception_key
FROM socket_events s
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
WHERE s.time > (strftime("%s", "now") -120)
  AND remote_port IN (53, 5353)
  AND remote_address NOT LIKE "%:%"
  AND s.remote_address NOT LIKE "172.1%"
  AND s.remote_address NOT LIKE "172.2%"
  AND s.remote_address NOT LIKE "172.30.%"
  AND s.remote_address NOT LIKE "172.31.%"
  AND s.remote_address NOT LIKE "10.%"
  AND s.remote_address NOT LIKE "192.168.%"
  AND s.remote_address NOT LIKE "127.%"
  AND remote_address NOT IN (
    SELECT DISTINCT address
    FROM dns_resolvers
    WHERE type = "nameserver"
      and address != ""
  )

  -- systemd-resolve sometimes shows up this way
  -- If we could narrow this down using "sys_resolvers" I would, but it is misuse of GROUP_CONCAT
  AND NOT (s.pid = -1 AND s.remote_port=53 and p.parent="")

  -- Some applications hard-code a safe DNS resolver, or allow the user to configure one
  AND s.remote_address NOT IN (
    "1.1.1.1", -- Cloudflare
    "8.8.8.8",  -- Google
    "8.8.4.4",  -- Google (backup)
    "208.67.222.222", -- OpenDNS
    "75.75.75.75" -- Comcast
  )

  -- Exceptions that specifically talk to one server
  AND exception_key NOT IN (
    "nessusd,50.16.123.71,53",
    "coredns,0.0.0.0,53"
  )

  -- Local DNS servers and custom clients go here
  AND p.path NOT IN (
    "/usr/lib/systemd/systemd-resolved"
  )
  AND p.path NOT LIKE "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/%/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"



-- Workaround for the GROUP_CONCAT subselect adding a blank ent
GROUP BY s.remote_address,
  s.remote_port
HAVING remote_address != ""