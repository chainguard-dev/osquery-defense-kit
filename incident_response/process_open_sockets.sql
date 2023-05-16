-- Return the list of open sockets per process
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
  pos.*
FROM
  process_open_sockets AS pos
  LEFT JOIN processes p ON pos.pid = p.pid;
