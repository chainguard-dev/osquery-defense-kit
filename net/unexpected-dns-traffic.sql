-- Catch DNS traffic going to machines other than the host-configured DNS server
-- NOTE: This only supports IPv4 traffic due to an osquery bug with 'dns_resolvers'
SELECT
  s.family, protocol, s.local_port, s.remote_port, s.local_address,
  s.remote_address, p.name, p.path, p.cmdline AS child_cmd, p.cwd, s.pid, s.net_namespace,
  p.parent AS parent_pid, pp.cmdline AS parent_cmd, hash.sha256,
  CONCAT(p.name, ',', remote_address, ',', remote_port, ',', protocol) AS exception_key
FROM process_open_sockets s
LEFT JOIN processes p ON s.pid = p.pid
LEFT JOIN processes pp ON p.parent = pp.pid
LEFT JOIN hash ON p.path = hash.path
WHERE remote_port IN (53,5353)
AND remote_address NOT LIKE "%:%"
AND remote_address NOT IN (
    SELECT address FROM dns_resolvers WHERE type='nameserver' and address != ''
)
AND NOT child_cmd = '/usr/lib/systemd/systemd-resolved' -- misconfiguration?
AND exception_key NOT IN (
    'systemd-resolve,192.168.50.1,53,17'
)
