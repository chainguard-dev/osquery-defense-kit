-- Retrieves the current status of IP/IPv6 forwarding.
--
-- tags: postmortem
-- platform: posix
SELECT
  *
FROM
  system_controls
WHERE
  oid = '4.30.41.1'
UNION
SELECT
  *
FROM
  system_controls
WHERE
  oid = '4.2.0.1';
