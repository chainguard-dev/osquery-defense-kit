-- Retrieves the ssh keys per user
--
-- tags: postmortem
SELECT
  *
FROM
  users
  JOIN user_ssh_keys USING (uid);
