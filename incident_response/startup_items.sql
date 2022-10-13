-- Retrieve all the items that will load when the target OSX system starts.
--
-- interval: 86400
-- platform: darwin
-- value: Identify malware that uses this persistence mechanism to launch at a given interval
-- version: 1.4.5

select * from startup_items;
