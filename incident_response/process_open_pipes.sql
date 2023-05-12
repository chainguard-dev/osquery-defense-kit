-- Return the list of open pipes per process
--
-- tags: postmortem
-- platform: linux
SELECT
  p.path AS p_path,
  p.name AS p_name,
  pop.*
FROM
  process_open_pipes AS pop
  LEFT JOIN processes p ON pop.pid = p.pid;
