-- Return the list of open files by process
--
-- tags: postmortem
-- platform: posix
SELECT
  p.path AS p_path,
  p.name AS p_name,
  p.start_time AS p_time,
  p.euid AS p_euid,
  p.uid AS p_uid,
  p.cmdline AS p_cmdline,
  pof.*
FROM
  process_open_files AS pof
  LEFT JOIN processes p ON pof.pid = p.pid;
