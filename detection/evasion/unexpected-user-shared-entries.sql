-- Find unexpected files in /Users/Shared
--
-- references:
--   * https://www.elastic.co/security-labs/inital-research-of-jokerspy
--
-- false positives:
--   * programs which create Shared files
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
    file.path LIKE '/Users/Shared/%%'
    OR file.path LIKE '/Users/Shared/.%'
    OR file.path LIKE '/Users/Shared/.%/%%'
    OR file.path LIKE '/Users/Shared/%/.%'
  )
  AND NOT (
    file.type = 'directory'
    OR file.size = 0
    OR file.path LIKE '%/../%'
    OR file.path LIKE '%/./%'
    OR file.path IN (
      '/Users/Shared/.4oaLkgIGnA',
      '/Users/Shared/.BetaEnrollmentData.plist',
      '/Users/Shared/.betamigrated',
      '/Users/Shared/.com.intego.reporting.plist',
      '/Users/Shared/.DS_Store',
      '/Users/Shared/.ks.intego_metrics_2.plist',
      '/Users/Shared/.localized',
      '/Users/Shared/.NSVolumeHeap',
      '/Users/Shared/.SeedEnrollment.plist',
      '/Users/Shared/.userfonts.cachedb',
      '/Users/Shared/CleanMyMac X/.licence',
      '/Users/Shared/LogiTuneInstallerStarted.txt',
      '/Users/Shared/Plugin Loading.log'
    )
    OR top3_dir IN (
      '/Users/Shared/.logishrd',
      '/Users/Shared/Adobe',
      '/Users/Shared/AdobeGCData',
      '/Users/Shared/AdobeGCInfo',
      '/Users/Shared/AdobeInstalledCodecsTier2',
      '/Users/Shared/Audiority',
      '/Users/Shared/Canon_Inc_IC',
      '/Users/Shared/CleanMyMac X Menu',
      '/Users/Shared/CleanMyMac X',
      '/Users/Shared/CleanMyMac_5',
      '/Users/Shared/Electronic Arts',
      '/Users/Shared/LGHUB',
      '/Users/Shared/logi',
      '/Users/Shared/LogioptionsPlus',
      '/Users/Shared/LogiOptionsPlus',
      '/Users/Shared/logitune',
      '/Users/Shared/macenhance',
      '/Users/Shared/Maxon',
      '/Users/Shared/Media Cache Files',
      '/Users/Shared/Media Cache Files/',
      '/Users/Shared/Parallels',
      '/Users/Shared/Pixologic',
      '/Users/Shared/PPN',
      '/Users/Shared/Previously Relocated Items',
      '/Users/Shared/Red Giant',
      '/Users/Shared/Relocated Items',
      '/Users/Shared/TechSmith',
      '/Users/Shared/UnrealEngine',
      '/Users/Shared/ZBrushData2024'
    )
    OR file.path LIKE '/Users/Shared/Epic Games/%'
    OR file.path LIKE "/Users/Shared/Previously Relocated Items %/%"
    OR (
      file.path LIKE "%.plist"
      AND magic.data = 'XML 1.0 document, ASCII text'
    )
  )
