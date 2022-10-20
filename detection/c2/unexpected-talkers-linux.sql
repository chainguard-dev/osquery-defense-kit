-- Unexpected programs communicating over non-HTTPS protocols (state-based)
--
-- This query is a bit awkward and hobbled due to the lack of osquery support
-- for looking up binary signatures in Linux.
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/ (C&C, Application Layer Protocol)
--
-- tags: transient state net rapid
-- platform: linux
SELECT s.remote_address,
  p.name,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  pp.path AS parent_path,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  s.state,
  hash.sha256,
  -- This intentionally avoids file.path, as it won't join across mount namespaces
  CONCAT (
    MIN(s.remote_port, 32768),
    ',',
    s.protocol,
    ',',
    MIN(p.euid, 500),
    ',',
    REPLACE(
      REGEX_MATCH(p.path, '(/.*?)/', 1),
      '/nix',
      '/usr'
    ),
    '/',
    REGEX_MATCH(p.path, '.*/(.*?)$', 1),
    ',',
    MIN(f.uid, 500),
    'u,',
    MIN(f.gid, 500),
    'g,',
    p.name
  ) AS exception_key
FROM process_open_sockets s
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN hash ON p.path = hash.path
WHERE protocol > 0
  AND s.remote_port > 0
  -- See unexpected-https-client
  AND NOT (
    s.remote_port = 443
    AND protocol IN (6, 17)
  )
  -- See unexpected-dns-traffic
  AND NOT (
    s.remote_port = 53
    AND protocol IN (6, 17)
  )
  AND s.remote_address NOT IN (
    '127.0.0.1',
    '::ffff:127.0.0.1',
    '::1',
    '::',
    '0.0.0.0'
  )
  AND s.remote_address NOT LIKE 'fe80:%'
  AND s.remote_address NOT LIKE '127.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '172.1%'
  AND s.remote_address NOT LIKE '172.2%'
  AND s.remote_address NOT LIKE '172.30.%'
  AND s.remote_address NOT LIKE '172.31.%'
  AND s.remote_address NOT LIKE '::ffff:172.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '::ffff:10.%'
  AND s.remote_address NOT LIKE 'fc00:%'
  AND p.path != ''
  AND NOT exception_key IN (
    '123,17,500,/usr/chronyd,0u,0g,chronyd',
    '22000,6,500,/usr/syncthing,0u,0g,syncthing',
    '4070,6,500,/opt/spotify,0u,0g,spotify',
    '5228,6,500,/opt/chrome,0u,0g,chrome',
    '80,6,0,/usr/.tailscaled-wrapped,0u,0g,.tailscaled-wra'
    '80,6,0,/usr/tailscaled,0u,0g,tailscaled',
    '80,6,500,/opt/chrome,0u,0g,chrome',
    '80,6,500,/usr/firefox,0u,0g,firefox',
    '8000,6,500,/opt/chrome,0u,0g,chrome',
    '8000,6,500,/usr/firefox,0u,0g,firefox',
    '8080,6,500,/opt/chrome,0u,0g,chrome',
    '8080,6,500,/usr/firefox,0u,0g,firefox',
    '8443,6,500,/opt/chrome,0u,0g,chrome',
    '8443,6,500,/usr/firefox,0u,0g,firefox',
  )
  AND NOT (
    p.name = 'syncthing'
    AND f.filename = 'syncthing'
    AND s.remote_port > 1024
    AND s.protocol = 6
    AND p.euid > 500
  )
GROUP BY p.cmdline