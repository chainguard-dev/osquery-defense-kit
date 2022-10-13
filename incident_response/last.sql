-- Retrieves the list of the latest logins with PID, username and timestamp.
--
-- interval: 3600
-- platform: posix
-- value: Useful for intrusion detection and incident response. Verify assumptions of what accounts should be accessing what systems and identify machines accessed during a compromise.
-- version: 1.4.5

select * from last;
