-- Return the list of open pipes per process
--
-- tags: postmortem
-- platform: linux
SELECT
  p.path AS p_path,
  p.name AS p_name,
  p.start_time AS p_time,
  p.euid AS p_euid,
  p.uid AS p_uid,
  p.cmdline AS p_cmdline,
  pop.*
FROM
  process_open_pipes AS pop
  LEFT JOIN processes p ON pop.pid = p.pid;
