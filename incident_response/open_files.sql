-- Retrieves all the open files per process in the target system.
--
-- tags: postmortem
-- platform: posix
SELECT DISTINCT
  pof.pid,
  pof.path,
  p.name,
  p.cmdline
FROM
  process_open_files pof
  LEFT JOIN processes p ON pof.pid = p.pid
WHERE
  pof.path NOT LIKE '/private/var/folders%'
  AND pof.path NOT LIKE '/System/Library/%'
  AND pof.path NOT IN ('/dev/null', '/dev/urandom', '/dev/random');
