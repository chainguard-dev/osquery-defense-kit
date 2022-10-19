-- Retrieves setuid-enabled executables in well-known paths
--
-- platform: posix
-- tags: postmortem
SELECT
  *
FROM
  suid_bin;
