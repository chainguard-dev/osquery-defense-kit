-- Returns a list of file information from /etc (non-hidden only)
--
-- tags: postmortem
-- platform: posix
SELECT
  *
FROM
  file
  JOIN hash ON file.path = hash.path
WHERE
  file.path LIKE "/etc/%%";
