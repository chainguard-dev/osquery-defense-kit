-- Retrieves all the files in the target system that are setuid enabled.
--
-- platform: posix
-- value: Detect backdoor binaries (attacker may drop a copy of /bin/sh). Find potential elevation points / vulnerabilities in the standard build.
-- version: 1.4.5

select * from suid_bin;
