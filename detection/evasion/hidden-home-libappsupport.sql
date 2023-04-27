-- Find unexpected hidden files in a users Application Support directory
--
-- references:
--   * https://objective-see.org/blog/blog_0x73.html
--
-- false positives:
--   * programs with unusual self-updaters
--
-- tags: persistent state filesystem
-- platform: darwin
SELECT
  file.path,
  file.filename,
  file.type,
  file.mode,
  file.size,
  file.mtime,
  file.uid,
  file.ctime,
  REPLACE(file.path, u.directory, '~') AS homepath,
  REPLACE(file.directory, u.directory, '~') AS homedir,
  file.gid,
  hash.sha256,
  magic.data,
  signature.identifier,
  signature.authority
FROM
  file
  JOIN hash ON file.path = hash.path
  JOIN users u ON file.uid = u.uid
  JOIN magic ON file.path = magic.path
  JOIN signature ON file.path = signature.path
WHERE
  file.path IN (
    SELECT
      path
    FROM
      file
    WHERE
      (
        path LIKE '/Users/%/Library/Application Support/%/.%'
        OR path LIKE '/Users/%/Library/Application Support/.%'
      )
      AND NOT file.filename IN ('.', '..', '.updaterId', '.DS_Store')
      AND size > 0
  )
  AND NOT homedir IN (
    '~/Library/Application Support/Adobe',
    '~/Library/Application Support/Beeper',
    '~/Library/Application Support/com.tinyapp.TablePlus',
    '~/Library/Application Support/Jabra Direct',
    '~/Library/Application Support/discord',
    '~/Library/Application Support/Keybase',
    '~/Library/Application Support/com.intelliscapesolutions.caffeine',
    '~/Library/Application Support/com.psiexams.psi-bridge-secure-browser',
    '~/Library/Application Support/GitHub Desktop',
    '~/Library/Application Support/Loom',
    '~/Library/Application Support/ZaloApp',
    '~/Library/Application Support/ZaloPC',
    '~/Library/Application Support/com.bohemiancoding.sketch3',
    '~/Library/Application Support/DropboxElectron',
    '~/Library/Application Support/Docker Desktop',
    '~/Library/Application Support/Slack',
    '~/Library/Application Support/Code',
    '~/Library/Application Support/lghub',
    '~/Library/Application Support/com.operasoftware.Opera',
    '~/Library/Application Support/com.apple.spotlight',
    '~/Library/Application Support/Lens'
  )
  AND NOT homepath IN (
    '~/Library/Application Support/.Shadowland5.5',
    '~/Library/Application Support/.com.contextsformac.Contexts.plist',
    '~/Library/Application Support/.settings'
  )
  AND NOT homepath LIKE '~/Library/Application Support/.syssettings%'
GROUP BY
  file.path
