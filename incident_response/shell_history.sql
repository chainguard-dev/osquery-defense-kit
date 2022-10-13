-- Retrieves the command history, per user, by parsing the shell history files.
--
-- interval: 86400
-- platform: posix
-- value: Identify actions taken. Useful for compromised hosts.
-- version: 1.4.5

select * from users join shell_history using (uid);
