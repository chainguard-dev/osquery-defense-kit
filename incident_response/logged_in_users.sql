-- Retrieves the list of all the currently logged in users in the target system.
--
-- tags: postmortem
-- platform: posix
SELECT
  liu.*,
  p.name,
  p.cmdline,
  p.cwd,
  p.root
FROM
  logged_in_users liu,
  processes p
WHERE
  liu.pid = p.pid;
