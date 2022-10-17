-- Retrieves all the open files per process in the target system.
--
-- interval: 86400
-- platform: posix
-- value: Identify processes accessing sensitive files they shouldn't
-- version: 1.4.5
select distinct
  pid,
  path
from
  process_open_files
where
  path not like '/private/var/folders%'
  and path not like '/System/Library/%'
  and path not in ('/dev/null', '/dev/urandom', '/dev/random');
