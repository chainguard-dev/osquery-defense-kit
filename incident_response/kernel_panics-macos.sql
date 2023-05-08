-- Retrieves entries from the macOS kernel panic logs
--
-- tags: postmortem
-- platform: darwin
SELECT
  *
FROM
  kernel_panics;
