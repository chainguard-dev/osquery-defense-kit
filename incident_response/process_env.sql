-- Retrieves all the environment variables per process in the target system.
--
-- interval: 86400
-- platform: posix
-- value: Insight into the process data: Where was it started from, was it preloaded...
-- version: 1.4.5
select
  *
from
  process_envs;
