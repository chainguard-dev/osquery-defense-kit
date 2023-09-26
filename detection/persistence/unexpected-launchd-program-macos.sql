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
    'Developer ID Application: Canonical Group Limited (X4QN7LTP59)',
    'Developer ID Application: Creative Labs Pte. Ltd. (5Q3552844F)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Jonathan Bullard (Z2SG5H3HC8)',
    'Developer ID Application: Ilya Parniuk (ACC5R6RH47)',
    'Developer ID Application: Fortinet, Inc (AH4XFXJ7DK)',
    'Developer ID Application: Hercules Labs Inc. (B8PC799ZGU)',
    'Developer ID Application: Kandji, Inc. (P3FGV63VK7)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Louis Pontoise (QXD7GW8FHY)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    'Developer ID Application: Valve Corporation (MXGJJ98X76)',
    'Developer ID Application: Wireshark Foundation, Inc. (7Z6EMTD2C6)',
    'Software Signing'
  )
  AND program NOT IN ('/usr/local/MacGPG2/libexec/shutdown-gpg-agent')
  AND NOT (
    l.path = '/Library/LaunchDaemons/com.docker.socket.plist'
    AND program_authority = 'Software Signing'
    AND program_identifier IN ('com.apple.ln', 'com.apple.link')
    AND program_arguments LIKE '/bin/ln -s -f /Users/%/run/docker.sock /var/run/docker.sock'
  )
GROUP BY
  l.path
