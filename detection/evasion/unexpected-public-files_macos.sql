-- Find unexpected files in ~/Public
--
-- references:
--   * https://www.elastic.co/security-labs/inital-research-of-jokerspy
--
-- false positives:
--   * Files dropped in via File Sharing
--
-- tags: persistent state filesystem seldom
-- platform: darwin
SELECT
  file.path,
  file.type,
  file.size,
  file.mtime,
  file.uid,
  file.btime,
  file.mode,
  file.ctime,
  file.gid,
  hash.sha256,
  magic.data,
  RTRIM(
    COALESCE(
      REGEX_MATCH (file.directory, '(/.*?/.*?/.*?/)', 1),
      file.directory
    ),
    "/"
  ) AS top3_dir
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    file.directory LIKE '/Users/%/Public'
    OR file.directory LIKE '/Users/%/Public/%%'
    OR file.directory LIKE '/Users/%/Public/.%'
  )
  AND NOT (
    file.type = 'directory'
    OR file.path LIKE '%/../%'
    OR file.path LIKE '%/./%'
    OR file.path LIKE '/Users/%/Public/Drop Box/.localized'
  )
