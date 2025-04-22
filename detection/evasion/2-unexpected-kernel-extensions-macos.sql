-- Find unexpected 3rd-party kernel extensions
--
-- false positives:
--   * none known
--
-- platform: darwin
-- tags: persistent seldom kernel
SELECT
  k.linked_against,
  k.name,
  k.path,
  k.size,
  k.version,
  hash.sha256,
  k.path || ',' || k.name || ',' || k.version || ',' || k.linked_against AS exception_key
FROM
  kernel_extensions AS k
  LEFT JOIN hash ON k.path = hash.path
WHERE
  k.path NOT LIKE '/System/Library/Extensions/%'
  AND NOT (
    idx = 0
    AND name = '__kernel__'
  )
  AND exception_key NOT IN (
    '/Library/StagedExtensions/Library/Extensions/CalDigitUSBHubSupport.kext,com.CalDigit.USBHubSupport,1,<3>',
    '/Library/StagedExtensions/Library/Filesystems/kbfuse.fs/Contents/Extensions/13/kbfuse.kext,com.github.kbfuse.filesystems.kbfuse,2113.21,<1 3 4 5 7>',
    '/Library/StagedExtensions/Library/Filesystems/macfuse.fs/Contents/Extensions/14/macfuse.kext,io.macfuse.filesystems.macfuse,2128.20,<1 3 4 5 7>'
  )
  AND exception_key NOT LIKE '/Library/StagedExtensions/Library/Extensions/UAD2System.kext,com.uaudio.driver.UAD2System,%'
  AND exception_key NOT LIKE '/Library/StagedExtensions/Library/Extensions/ufsd_ExtFS.kext,com.paragon-software.filesystems.extfs,%'
  AND exception_key NOT LIKE '/Library/StagedExtensions/Library/Extensions/ufsd_NTFS.kext,com.paragon-software.filesystems.ntfs,%'
  AND exception_key NOT LIKE '/Library/StagedExtensions/Library/Filesystems/macfuse.fs/Contents/Extensions/%/macfuse.kext,io.macfuse.filesystems.macfuse,%'
  AND exception_key NOT LIKE '/usr/appleinternal/standalone/platform,com.apple.sptm,24.%'
  AND exception_key NOT LIKE '/usr/appleinternal/standalone/platform,com.apple.txm,24.%'
