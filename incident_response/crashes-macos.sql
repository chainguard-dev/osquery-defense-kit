-- Retrieves crash log info per user
--
-- tags: postmortem
SELECT
  *
FROM
  users
  JOIN crashes USING (uid);
