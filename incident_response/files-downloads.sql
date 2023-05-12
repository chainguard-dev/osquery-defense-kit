-- Returns a list of file information from Downloads directories
--
-- tags: postmortem
-- platform: posix
SELECT
  file.*,
  magic.data,
  hash.sha256
FROM
  file
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN hash ON file.path = hash.path
WHERE
  file.path LIKE "/home/%/Downloads/%"
  OR file.path LIKE "/Users/%/Downloads/%"
