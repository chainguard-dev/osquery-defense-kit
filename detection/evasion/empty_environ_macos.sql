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
  p.start_time > (strftime('%s', 'now') - 600)
  -- Filter out transient processes that may not have an envs entry by the time we poll for it
  AND p.start_time < (strftime('%s', 'now') - 1)
  AND p.path NOT LIKE '/System/Library/%'
  AND NOT (
    signature.identifier LIKE 'com.apple.%'
    AND signature.authority = 'Software Signing'
  )
  AND NOT exception_key IN (
    '500,Brave Browser Helper (Renderer),com.brave.Browser.helper.renderer,Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)',
    '500,Google Chrome Helper (Alerts),com.google.Chrome.framework.AlertNotificationService,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '500,Google Chrome Helper,com.google.Chrome.helper,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '500,Google Chrome Helper (Renderer),com.google.Chrome.helper.renderer,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '500,Pages,com.apple.iWork.Pages,Apple Mac OS Application Signing',
    '500,SafariLaunchAgent,SafariLaunchAgent-55554944882a849c6a6839b4b0e7c551bbc81898,Software Signing'
  )
GROUP BY p.pid
HAVING count == 0;