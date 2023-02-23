-- Retrieves all the listening ports in the target system.
--
-- tags: postmortem
-- platform: posix
SELECT
  lp.*, p.name AS p_name, p.path AS p_path, p.euid AS p_euid
FROM
  listening_ports AS lp
  LEFT JOIN processes p ON lp.pid = p.pid;
