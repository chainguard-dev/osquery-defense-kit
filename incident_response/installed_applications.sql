-- Retrieves all the currently installed applications in the target OSX system.
--
-- interval: 3600
-- platform: darwin
-- value: Identify malware, adware, or vulnerable packages that are installed as an application.
-- version: 1.4.5
select
  *
from
  apps;
