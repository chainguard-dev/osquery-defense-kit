-- Returns a list of file information from /dev (non-hidden only)
--
-- tags: postmortem
-- platform: posix
SELECT
  file.*,
  magic.data
FROM
  file
  JOIN magic ON file.path = magic.path
WHERE
  file.path LIKE "/dev/%%";
