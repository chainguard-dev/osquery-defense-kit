SELECT
  pop.pid,
  p.path,
  p.cmdline
FROM
  process_open_sockets pop
  JOIN processes p ON pop.pid = p.pid
WHERE
  family = 2 -- PF_INET
  AND protocol = 1 -- ICMP
  AND p.name NOT IN ('ping')
