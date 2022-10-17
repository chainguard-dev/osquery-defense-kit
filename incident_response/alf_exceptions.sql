-- Retrieves the exceptions for the Application Layer Firewall in OSX.
--
-- interval: 3600
-- platform: darwin
-- value: Verify firewall settings are as restrictive as you need. Identify unwanted firewall holes made by malware or humans
-- version: 1.4.5
select
  *
from
  alf_exceptions;
