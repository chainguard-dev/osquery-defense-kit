-- Retrieves the command history, per user, by parsing the shell history files.
--
-- tags: postmortem
-- platform: posix
SELECT
  *
FROM
  users
  JOIN shell_history USING (uid);
