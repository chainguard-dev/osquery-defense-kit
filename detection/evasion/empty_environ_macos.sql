-- Find programs which have cleared their environment
--
-- references:
--   * https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
--
-- tags: persistent state daemon process
-- platform: darwin
-- interval: 600
SELECT COUNT(key) AS count,
  p.pid,
  p.path,
  p.on_disk,
  p.parent,
  p.cmdline,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmd,
  signature.identifier,
  signature.authority,
  hash.sha256,
  CONCAT(
    MIN(p.euid, 500),
    ',',
    p.name,
    ',',
    signature.identifier,
    ',',
    signature.authority
  ) AS exception_key -- Processes is 20X faster to scan than process_envs
FROM processes p
  LEFT JOIN process_envs pe ON p.pid = pe.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN signature ON p.path = signature.path
WHERE -- This time should match the interval
  p.start_time > (strftime('%s', 'now') - 605) -- Filter out transient processes that may not have an envs entry by the time we poll for it
  AND p.start_time < (strftime('%s', 'now') - 5)
  AND p.path NOT LIKE '/System/Library/%'
  -- This condition happens a fair bit on macOS, particularly electron apps
  AND NOT (
    p.path LIKE '/Applications/%.app/Contents/%/Contents/MacOS/%'
    AND signature.authority = 'Apple Mac OS Application Signing'
  )
  AND NOT (
    signature.identifier LIKE 'com.apple.%'
    AND signature.authority = 'Software Signing'
  )
  AND NOT exception_key IN (
    '500,chrome_crashpad_handler,chrome_crashpad_handler,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '500,com.docker.cli,com.docker,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '500,CraftWidgetExtension,com.lukilabs.lukiapp.CraftWidget,Apple Mac OS Application Signing',
    '500,Obsidian Helper (Renderer),md.obsidian.helper.Renderer,Developer ID Application: Dynalist Inc. (6JSW4SJWN9)',
    '500,Pages,com.apple.iWork.Pages,Apple Mac OS Application Signing',
    '500,SafariLaunchAgent,SafariLaunchAgent-55554944882a849c6a6839b4b0e7c551bbc81898,Software Signing',
    '500,TwitterNotificationServiceExtension,maccatalyst.com.atebits.Tweetie2.NotificationServiceExtension,Apple Mac OS Application Signing'
  )
  AND NOT exception_key LIKE '500,Google Chrome%,Developer ID Application: Google LLC (EQHXZ8M8AV)'
  AND NOT exception_key LIKE '500,Brave Browser %,com.brave.Browser.%,Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)'

  -- Electron apps
  AND NOT (
    p.path LIKE '/Applications/%Helper%'
    AND (
      exception_key LIKE '500,%Helper%,Renderer,Developer ID Application: % (%)'
      OR exception_key LIKE '500,%Helper%,helper,Developer ID Application: % (%)'
    )
  )
GROUP BY p.pid
HAVING count == 0;