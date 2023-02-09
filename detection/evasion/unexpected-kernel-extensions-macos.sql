-- Find unexpected 3rd-party kernel extensions
--
-- false positives:
--   * none known
--
-- platform: darwin
-- tags: persistent seldom kernel
SELECT
  linked_against, name, path, size, version,
  path || ',' || name || ',' || version || ',' || linked_against AS exception_key
FROM
  kernel_extensions
WHERE
  path NOT LIKE '/System/Library/Extensions/%'
  AND NOT (
    idx = 0
    AND name = '__kernel__'
  )
  AND exception_key NOT IN ('/Library/StagedExtensions/Library/Extensions/CalDigitUSBHubSupport.kext,com.CalDigit.USBHubSupport,1,<3>')
