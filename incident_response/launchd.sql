-- Retrieves all the daemons that will run in the start of the target OSX system.
--
-- interval: 3600
-- platform: darwin
-- value: Identify malware that uses this persistence mechanism to launch at system boot
-- version: 1.4.5

select * from launchd;
