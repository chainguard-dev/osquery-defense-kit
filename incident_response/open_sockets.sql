-- Retrieves all the open sockets per process in the target system.
--
-- tags: postmortem
-- platform: posix
SELECT DISTINCT
  pid,
  family,
  protocol,
  local_address,
  local_port,
  remote_address,
  remote_port,
  path
FROM
  process_open_sockets
WHERE
  path <> ''
  or remote_address <> '';
