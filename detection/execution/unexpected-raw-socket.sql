-- Find unexpected use of raw sockets in executables, sometimes used for C&C communications
--
-- false positives:
--   * operating-system network managers
--
-- tags: transient process state
-- platform: posix
SELECT
  pop.pid,
  p.path,
  p.cmdline,
  p.name,
  hash.sha256
FROM
  process_open_sockets pop
  JOIN processes p ON pop.pid = p.pid
  JOIN hash ON p.path = hash.path
WHERE
  family = 17 -- PF_PACKET
  AND name NOT IN (
    'wpa_supplicant',
    'NetworkManager',
    'dhcpcd',
    'tcpdump'
  )
