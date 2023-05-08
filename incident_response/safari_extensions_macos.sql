-- Return the list of installed Safari extensions
--
-- tags: postmortem
-- platform: darwin
SELECT
  safari_extensions.*
FROM
  users
  JOIN safari_extensions ON users.uid = safari_extensions.uid;
