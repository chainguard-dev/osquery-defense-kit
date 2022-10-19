-- Retrieves all the environment variables per process in the target system.
-- tags: postmortem
-- platform: posix
SELECT
  *
FROM
  process_envs;
