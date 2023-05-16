-- Return shared memory info
--
-- tags: postmortem
-- platform: linux
SELECT
  shm.*,
  p.path AS p_path,
  p.name AS p_name,
  p.start_time AS p_time,
  p.euid AS p_euid,
  p.uid AS p_uid,
  p.cmdline AS p_cmdline
FROM
  shared_memory AS shm
  LEFT JOIN processes p ON shm.pid = p.pid;
