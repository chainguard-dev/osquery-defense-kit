-- Find unexpected in unexpected places under /Users
--
-- references:
--   * https://www.elastic.co/security-labs/inital-research-of-jokerspy
--   * https://www.elastic.co/security-labs/DPRK-strikes-using-a-new-variant-of-rustbucket
--
-- false positives:
--   * none known
--
-- tags: persistent seldom
-- platform: darwin
SELECT
  f.path,
  f.directory,
  f.uid,
  f.gid,
  f.mode,
  f.mtime,
  f.atime,
  f.btime,
  f.ctime,
  f.size,
  hash.sha256,
  REPLACE(f.directory, u.directory, '~') AS homedir,
  RTRIM(
    COALESCE(
      REGEX_MATCH (
        REPLACE(f.directory, u.directory, '~'),
        '(.*?/.*?/.*?/)',
        1
      ),
      REPLACE(f.directory, u.directory, '~')
    ),
    "/"
  ) AS top2_homedir,
  magic.data,
  signature.authority,
  signature.identifier
FROM
  file f
  LEFT JOIN hash on f.path = hash.path
  LEFT JOIN users u ON f.uid = u.uid
  LEFT JOIN magic ON f.path = magic.path
  LEFT JOIN signature ON f.path = signature.path
WHERE -- Optimization: don't join things until we have a whittled down list of files
  f.path IN (
    SELECT DISTINCT
      path
    FROM
      file
    WHERE
      (
        file.path LIKE '/Users/Shared/%%'
        OR file.path LIKE '/Users/%/Library/%%'
        OR file.path LIKE '/Users/%/Public/%%'
        OR file.path LIKE '/Users/%/Photos/%%'
        OR file.path LIKE '/Users/Shared/.%/%%'
        OR file.path LIKE '/Users/%/Library/.%/%%'
        OR file.path LIKE '/Users/%/Public/.%/%%'
        OR file.path LIKE '/Users/%/Photos/.%/%%'
        OR file.path LIKE '/Users/%/.%/%%'
      ) -- Prevent weird recursion
      AND NOT file.path LIKE '%/../%'
      AND NOT file.path LIKE '%/./%' -- Exclude very temporary files
      AND NOT file.directory LIKE '/Users/%/Library/Mobile Documents/com~apple~shoebox/%'
      AND NOT file.directory LIKE '/Users/%/Library/Containers/%'
      AND NOT file.directory LIKE '/Users/%/.Trash'
      AND NOT file.directory LIKE '/Users/%/Library/Daemon Containers/%/Data/Downloads'
      AND NOT file.directory LIKE '/Users/Shared/LGHUB/depots/%'
      AND NOT file.directory LIKE '/Users/Shared/LogiOptionsPlus/depots/%'
      AND NOT file.directory LIKE '/Users/%/Library/Application Support/AutoFirma/certutil'
      AND NOT file.directory LIKE '/Users/%/Library/Caches/chainctl'
      AND NOT file.directory IN (
        '/Users/Shared/LogiOptionsPlus/cache',
        '/Users/Shared/logitune',
        '/Users/Shared/Red Giant/Uninstall'
      )
      AND NOT (strftime('%s', 'now') - ctime) < 60 -- Only executable files
      AND file.type = 'regular'
      AND file.size > 32
      AND (
        file.mode LIKE '%7%'
        or file.mode LIKE '%5%'
        or file.mode LIKE '%1%'
      )
  )
  AND (
    magic.data IS NULL
    OR magic.data LIKE "%executable%"
    OR magic.data LIKE "%shared library%"
  ) -- Filter out downloaded Linux binaries
  AND NOT (
    magic.data IS NOT NULL
    AND magic.data LIKE "ELF %LSB %"
  )
  AND NOT (
    magic.data IS NOT NULL
    AND magic.data LIKE "0420 Alliant virtual executable%"
  )
  AND NOT top2_homedir IN (
    '~/Library/Application Support',
    '/Users/Shared/LGHUB/cache',
    '~/Library/Printers',
    '~/Library/QuickLook',
    '~/Library/pnpm',
    '/Users/Shared/Red Giant/Uninstall',
    '~/Library/Thunderbird',
    '~/Library/helm',
    '~/Library/Services',
    '~/.terraform.d',
    '~/.iterm2',
    '/Users/Shared/LogiOptionsPlus/cache',
    '~/Library/Screen Savers',
    '~/Library/Python',
    '~/Library/Caches',
    '~/.magefile',
    '~/.nvm'
  )
  AND NOT homedir IN (
    '~/.bin',
    '~/.fzf',
    '~/Library/Dropbox/DropboxMacUpdate.app/Contents/MacOS'
  )
GROUP BY
  f.path
