-- Detect weird mounts, like mounting the EFI partition
--
-- references:
--   * https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/
--
-- platform: linux
-- tags: transient filesystem state
SELECT
  *
FROM
  mounts
WHERE
  device = '/dev/disk0s1'
  AND type = 'msdos';
