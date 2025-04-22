-- Find unexpected hidden files in a users Library directory
--
-- references:
--   * https://www.sentinelone.com/blog/xcsset-malware-update-macos-threat-actors-prepare-for-life-without-python/
--
-- false positives:
--   * programs which create new Library directories
--
-- tags: persistent state filesystem
-- platform: darwin
SELECT
  file.path,
  file.type,
  file.size,
  file.mtime,
  file.uid,
  file.ctime,
  REPLACE(file.directory, u.directory, '~') AS homedir,
  file.gid,
  hash.sha256,
  magic.data,
  signature.identifier,
  signature.authority
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN users u ON file.uid = u.uid
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN signature ON file.path = signature.path
WHERE
  (
    file.path LIKE '/Users/%/Library/%%/.%/%%'
    OR file.path LIKE '/Users/%/Library/.%/%%'
    OR file.path LIKE '/Users/%/Library/%%/.%/.%'
  )
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%'
  AND NOT homedir IN (
    '~/Library/Accessibility/.com.apple.RTTTranscripts_SUPPORT/_EXTERNAL_DATA',
    '~/Library/Application Support/.keymapp',
    '~/Library/Caches/.adobe/c2pa_cache',
    '~/Library/Caches/.sigstore/gitsign',
    '~/Library/com.apple.groupkitd/.syncedGroupStore_SUPPORT/_EXTERNAL_DATA',
    '~/Library/com.apple.groupkitd/.syncedGroupStore_SUPPORT/_EXTERNAL_DATA/',
    '~/Library/Finance/.finance_cloud_SUPPORT/_EXTERNAL_DATA',
    '~/Library/Finance/.finance_dropbox_SUPPORT/_EXTERNAL_DATA',
    '~/Library/Finance/.finance_local_SUPPORT/_EXTERNAL_DATA',
    '~/Library/Group Containers/.SiriTodayViewExtension',
    '~/Library/Group Containers/.SiriTodayViewExtension/Library',
    '~/Library/GroupContainersAlias/.SiriTodayViewExtension',
    '~/Library/GroupContainersAlias/.SiriTodayViewExtension/Library',
    '~/Library/HomeKit/.core-cloudkit-shared_SUPPORT/_EXTERNAL_DATA',
    '~/Library/HomeKit/.core-cloudkit_SUPPORT/_EXTERNAL_DATA',
    '~/Library/pnpm/.tools/pnpm',
    '~/Library/Preferences/.wrangler',
    '~/Library/Preferences/.wrangler/config',
    '~/Library/Saved Searches/.DockTags',
    '~/Library/Stickers/.stickers_SUPPORT/_EXTERNAL_DATA'
  )
  AND NOT homedir LIKE '~/Library/.icedove/%'
  AND NOT homedir LIKE '~/Library/%/.%_SUPPORT/_EXTERNAL_DATA'
  AND NOT homedir LIKe '~/Library/Caches/.git%'
  AND NOT homedir LIKE '~/Library/Mobile Documents/.Trash%'
  -- ugh
  AND NOT file.path LIKE '/Library/Application Scripts/.%-%-%-%-%/.%'
  AND NOT homedir LIKE '~/Library/Application Scripts/.%-%-%-%-%'
  AND NOT homedir LIKE '~/Library/Application Scripts/.%-%-%-%-%/.%'
