-- Retrieves chrome extensions that execute on a broad set of URLs.
-- tags: postmortem
-- platform: posix
SELECT
  chrome_extensions.*
FROM
  users
  JOIN chrome_extensions ON users.uid = chrome_extensions.uid
