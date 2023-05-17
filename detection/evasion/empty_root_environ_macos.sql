-- Find programs which spawn root children without propagating environment variables
--
-- references:
--   * https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
--
-- tags: persistent state daemon process seldom disabled
-- platform: darwin
-- interval: 600
SELECT
  COUNT(key) AS count,
  p.pid,
  p.path,
  p.name,
  p.euid,
  p.on_disk,
  p.parent,
  p.cmdline,
  p.cwd,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmd,
  signature.identifier,
  signature.authority,
  hash.sha256,
  CONCAT (
    MIN(p.euid, 500),
    ',',
    p.name,
    ',',
    signature.identifier,
    ',',
    signature.authority
  ) AS exception_key
FROM
  processes p
  LEFT JOIN process_envs pe ON p.pid = pe.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN signature ON p.path = signature.path
WHERE
  p.pid IN (
    SELECT
      pid
    FROM
      processes
    WHERE
      euid = 0
      AND start_time > (strftime('%s', 'now') - 601)
      AND start_time < (strftime('%s', 'now') - 1)
      AND path NOT LIKE '/System/Library/%'
      AND path NOT LIKE '/opt/homebrew/Cellar/%'
  )
  AND signature.authority NOT IN (
    'Software Signing',
    'Apple Mac OS Application Signing',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: GitHub (VEKTX9H2N7)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    'Developer ID Application: Node.js Foundation (HX7739G8FX)',
    'Developer ID Application: Keybase, Inc. (99229SGT5K)',
    'Developer ID Application: Kolide Inc (YZ3EM74M78)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Mozilla Corporation (43AQ936H96)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Opal Camera Inc (97Z3HJWCRT)',
    'Developer ID Application: Parallels International GmbH (4C6364ACXT)',
    'Developer ID Application: Yubico Limited (LQA3CS5MM7)'
  )
GROUP BY
  p.pid
HAVING
  count == 0;
