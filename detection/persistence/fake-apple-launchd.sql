-- Find launchd entries which purport to be by Apple, but point to binaries that are not signed by Apple.
--
-- references:
--   * https://attack.mitre.org/techniques/T1543/004/ (Create or Modify System Process: Launch Daemon)
--   * https://posts.specterops.io/hunting-for-bad-apples-part-1-22ef2b44c0aa
--
-- false positives:
--   * none have been observed
--
-- platform: darwin
-- tags: persistent launchd state
SELECT
  *
FROM
  launchd
  LEFT JOIN file ON launchd.path = file.path
  LEFT JOIN signature ON launchd.program_arguments = signature.path
WHERE
  launchd.name LIKE 'com.apple.%'
  -- Optimization, assumes SIP
  AND file.directory NOT IN (
    '/System/Library/LaunchAgents',
    '/System/Library/LaunchDaemons',
    '/Library/Apple/System/Library/LaunchDaemons',
    '/Library/Apple/System/Library/LaunchAgents'
  )
  AND launchd.run_at_load = 1
  AND signature.authority != 'Software Signing'
