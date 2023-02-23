-- Retrieves the ssh configs per user
--
-- tags: postmortem
SELECT
  *
FROM
  users
  JOIN ssh_configs USING (uid);
