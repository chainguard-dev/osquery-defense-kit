-- Retrieves all the currently installed authorized keys on a system
--
-- tags: postmortem
-- platform: posix
SELECT
  authorized_keys.*
FROM
  users
  JOIN authorized_keys ON users.uid = authorized_keys.uid;
