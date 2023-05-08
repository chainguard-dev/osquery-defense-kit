-- Retrieves the memory map per process
-- platform: posix
-- tags: postmortem
SELECT
  pid,
  permissions,
offset
,
  inode,
  path,
  pseudo
FROM
  process_memory_map
WHERE
  path != ""
GROUP BY
  pid,
  permissions,
offset
,
  inode,
  path,
  pseudo;
