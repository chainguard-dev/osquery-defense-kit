-- Retrieves all the jobs scheduled in crontab in the target system.
--
-- interval: 3600
-- platform: posix
-- value: Identify malware that uses this persistence mechanism to launch at a given interval
-- version: 1.4.5
select
  *
from
  crontab;
