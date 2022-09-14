-- Launchd entries that specify command-lines
-- WARNING: I think this might some how be filtering out entries like Grammarly for unknown reasons
SELECT l.label,
    l.name,
    l.path,
    TRIM(REGEX_SPLIT(l.program_arguments, ' -', 0)) AS program_path,
    l.program_arguments,
    l.keep_alive,
    signature.authority AS program_authority,
    hash.sha256
FROM launchd l
    LEFT JOIN signature ON program_path = signature.path
    LEFT JOIN hash ON program_path = hash.path
WHERE (
        run_at_load = 1
        OR keep_alive = 1
    )
    AND (
        program IS NULL
        OR program = ""
    )
    AND l.path NOT LIKE "/System/%"
    AND program_authority NOT IN (
        'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
        'Developer ID Application: Foxit Corporation (8GN47HTP75)',
        'Developer ID Application: Google LLC (EQHXZ8M8AV)',
        'Developer ID Application: Keybase, Inc. (99229SGT5K)',
        'Developer ID Application: Kolide Inc (YZ3EM74M78)',
        'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
        'Developer ID Application: MacPaw Inc. (S8EX82NJP6)',
        'Developer ID Application: Mersive Technologies (63B5A5WDNG)',
        'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
        'Developer ID Application: Proton Technologies AG (6UN54H93QT)',
        'Software Signing',
        'yabai-cert'

    )
    AND program_arguments NOT IN ('/opt/homebrew/opt/skhd/bin/skhd')
    AND program_arguments NOT LIKE '/Users/%/Library/Application Support/com.grammarly.ProjectLlama/Scripts/post-uninstall.sh'

