-- Processes that do not exist on disk
--
-- false positives:
--   * Self-updating programs that remain running
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/004/ (Indicator Removal on Host: File Deletion)
--
-- platform: darwin
-- tags: persistent process state
SELECT
  p.pid,
  p.path,
  p.name,
  p.parent,
  p.state,
  p.cwd,
  p.gid,
  p.uid,
  p.euid,
  p.cmdline AS cmd,
  p.cwd,
  p.on_disk,
  p.state,
  pp.on_disk AS parent_on_disk,
  pp.path AS parent_path,
  pp.cmdline AS parent_cmd,
  pp.cwd AS parent_cwd,
  hash.sha256 AS parent_sha256
FROM
  processes p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON pp.path = hash.path
WHERE
  p.on_disk != 1 -- false positives from recently spawned processes
  AND (strftime('%s', 'now') - p.start_time) > 15
  AND p.pid > 0
  AND p.parent != 2 -- kthreadd
  AND p.state != 'Z' -- The kernel no longer has enough tracking information for this alert to be useful
  AND NOT (
    p.parent = 1
    AND p.path = ''
  )
  AND NOT (
    p.gid = 20
    AND (
      -- NOTE: p.path is typically empty when on_disk != 1, so don't depend on it.
      cmd LIKE '/Library/Apple/System/%'
      OR cmd LIKE '/Applications/%/Contents/%'
      OR cmd LIKE '/Library/Apple/System/%'
      OR cmd LIKE '/Library/Application Support/Logitech.localized/%'
      OR cmd LIKE '/Library/Developer/CommandLineTools/%'
      OR p.path IN (
        '/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper'
      )
      OR cmd LIKE '/opt/homebrew/Cellar/%'
      OR p.path LIKE '/opt/homebrew/Cellar/%/bin/%'
      OR p.path LIKE '/private/var/folders/zz/%/T/PKInstallSandboxTrash/%.sandboxTrash/%'
      OR cmd LIKE '/opt/homebrew/opt/%'
      OR cmd LIKE '/private/var/folders/%/Visual Studio Code.app/Contents/%'
      OR cmd LIKE '/Users/%/homebrew/opt/mysql/bin/%' -- Sometimes cmd is empty also :(
      OR parent_cmd LIKE '/Applications/Google Chrome.app/%'
    )
  )
  AND NOT (
    p.name = ''
    AND parent_cmd = '/Applications/Firefox Developer Edition.app/Contents/MacOS/firefox -foreground'
  )
