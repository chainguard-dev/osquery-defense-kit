-- Retrieves all the entries in the target system /etc/hosts file.
--
-- tags: postmortem
-- platform: posix
SELECT
  *
FROM
  etc_hosts;
