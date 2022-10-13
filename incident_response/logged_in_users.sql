-- Retrieves the list of all the currently logged in users in the target system.
--
-- interval: 3600
-- platform: posix
-- value: Useful for intrusion detection and incident response. Verify assumptions of what accounts should be accessing what systems and identify machines accessed during a compromise.
-- version: 1.4.5

select liu.*, p.name, p.cmdline, p.cwd, p.root from logged_in_users liu, processes p where liu.pid = p.pid;
