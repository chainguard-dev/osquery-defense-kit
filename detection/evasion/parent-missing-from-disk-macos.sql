-- A program where the parent PID is not on disk
--
-- Reveals boopkit if a child is spawned
-- TODO: Make mount namespace aware
--
-- false positives:
--   * none observed
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/004/ (Indicator Removal on Host: File Deletion)
--
-- false positives:
--   * none observed
--
-- tags: persistent daemon
SELECT
  s.authority AS p0_auth,
  s.identifier AS p0_id,
  DATETIME(f.ctime, 'unixepoch') AS p0_changed,
  DATETIME(f.mtime, 'unixepoch') AS p0_modified,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.pid IN (
    SELECT
      p.pid
    FROM
      processes p
      -- NOTE: This is an expensive join on macOS
      JOIN processes pp ON p.parent = pp.pid
    WHERE
      p.parent NOT IN (0, 1, 2)
      AND p.path != ""
      -- macOS Optimization
      AND p.path NOT LIKE '/System/%'
      AND p.path NOT LIKE '/usr/libexec/%'
      AND p.path NOT LIKE '/usr/bin/%'
      AND p.path NOT LIKE '/sbin/%'
      -- Exceptions
      AND pp.path NOT LIKE '/opt/homebrew/Cellar/%'
      AND pp.path NOT LIKE '%google-cloud-sdk/.install/.backup%'
      AND pp.path NOT LIKE '/private/var/folders/%/T/PKInstallSandboxTrash/%.sandboxTrash/%'
      AND pp.path NOT IN (
        "",
        "/sbin/launchd",
        "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)",
        "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper"
      )
      AND pp.on_disk != 1
  );
