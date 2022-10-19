-- Unexpected launchd scripts that use the 'program' field
--
-- references:
--   * https://attack.mitre.org/techniques/T1543/004/ (Create or Modify System Process: Launch Daemon)
--
-- false positives:
--   * Software by new vendors which have not yet been added to the allow list
--
-- tags: persistent filesystem state
-- platform: darwin
SELECT
  l.label,
  l.name,
  l.path,
  l.program,
  l.program_arguments,
  l.keep_alive,
  signature.authority AS program_authority,
  signature.identifier AS program_identifier,
  hash.sha256
FROM
  launchd l
  LEFT JOIN signature ON l.program = signature.path
  LEFT JOIN hash ON l.path = hash.path
WHERE
  (
    run_at_load = 1
    OR keep_alive = 1
  )
  AND l.path NOT LIKE '/System/%'
  AND program IS NOT NULL
  AND program_authority NOT IN (
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    'Developer ID Application: Valve Corporation (MXGJJ98X76)',
    'Developer ID Application: Wireshark Foundation, Inc. (7Z6EMTD2C6)'
  )
  AND program NOT IN ('/usr/local/MacGPG2/libexec/shutdown-gpg-agent')
