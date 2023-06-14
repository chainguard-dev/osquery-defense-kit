-- Look for sketchy mounted disk images, inspired by Shlayer
--
-- references:
--   * https://attack.mitre.org/techniques/T1566/001/ (Phishing: Spearphishing Attachment)
--   * https://attack.mitre.org/techniques/T1204/002/ (User Execution: Malicious File)
--   * https://www.crowdstrike.com/blog/how-crowdstrike-uncovered-a-new-macos-browser-hijacking-campaign/
--
-- tags: transient volume filesystem
-- platform: darwin
SELECT
  RTRIM(file.path, '/') AS f,
  file.bsd_flags AS f_flags,
  file.gid AS f_gid,
  file.mode AS f_mode,
  file.size AS f_size,
  file.type AS f_type,
  REGEX_MATCH (file.filename, '.*\.(.*?)$', 1) AS f_ext,
  file.uid AS f_uid,
  hash.sha256 AS f_sha256,
  magic.data AS f_data,
  mdfind.path AS probable_source,
  mdhash.sha256 AS probable_source_sha256,
  ea.value AS probable_url,
  REGEX_MATCH (file.path, '/Volumes/(.*?)/', 1) AS vol_name,
  signature.authority AS s_auth,
  signature.identifier AS s_id
FROM
  file
  LEFT JOIN mdfind ON mdfind.query = "kMDItemFSName == '*" || REGEX_MATCH (file.path, '/Volumes/(\w+)', 1) || "*.dmg'"
  LEFT JOIN extended_attributes ea ON mdfind.path = ea.path
  AND ea.key = 'where_from'
  LEFT JOIN hash on file.path = hash.path
  LEFT JOIN hash mdhash ON mdfind.path = mdhash.path
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN signature ON file.path = signature.path
WHERE
  file.path IN (
    SELECT
      file.path
    FROM
      block_devices
      JOIN mounts ON mounts.device = block_devices.name
      JOIN file ON file.directory = mounts.path
      OR file.directory LIKE mounts.path || "/%.app/Contents/MacOS/"
      OR file.directory LIKE mounts.path || "/%.app/Contents/Resources/"
      OR file.directory LIKE mounts.path || "/%/%.app/Contents/MacOS/"
      OR file.directory LIKE mounts.path || "/%/%.app/Contents/Resources/"
    WHERE
      model = 'Disk Image'
      AND parent != ""
      AND mounts.path LIKE "/Volumes/%"
      -- osquery will traverse symlinks, this prevents following symlinks to /Applications (poorly)
      AND file.path NOT LIKE "/Volumes/%/Applications/%"
  )
  AND (
    --   Rule 0. App binaries that are hidden, like WnBJLaF/1302.app/Contents/MacOS/1302 (1302.app)
    (
      file.directory LIKE '/Volumes/%/Contents/MacOS'
      AND file.bsd_flags = "HIDDEN"
    ) --   Rule 1. App binaries that are a thin shell script wrapper for another resource (Player_009.app, 1302.app)
    OR (
      file.directory LIKE '/Volumes/%/Contents/MacOS'
      AND file.mode LIKE "%7%"
      AND file.type != 'directory'
      AND magic.data LIKE '%script%'
      AND signature.identifier != 'net.snowflake.snowsql'
      AND signature.authority NOT IN (
        'Developer ID Application: Allen Bai (97DN42T837)',
        'Developer ID Application: Galvanix (5BRAQAFB8B)'
      )
    ) -- Rule 2. App binaries that have mixed-caps names such as LYwjtu0sc3XqkNVbQe_gM4YiRpmgUpRIew or yWnBJLaF (AdobeFlashPlayer_567.app)
    OR (
      file.mode LIKE "%7%"
      AND file.type != 'directory'
      AND REGEX_MATCH (file.filename, '([a-z]+[A-Z][A-Z]+[a-z]+)', 1) != ""
      AND magic.data LIKE "%executable%"
      -- Some people do weird things!
      AND signature.authority NOT IN (
        'Software Signing',
        'Developer ID Application: Atlassian Pty Ltd (UPXU4CQZ5P)',
        'Developer ID Application: MacroMates Ltd. (45TL96F76G)',
        'Developer ID Application: Logitech Inc. (QED4VVPZWA)'
      )
    ) -- Rule 3. App binaries with a numerical name, such as 2829030009 (Player_009.app)
    OR (
      file.mode LIKE "%7%"
      AND file.type != 'directory'
      AND REGEX_MATCH (file.filename, '^(\d)+$', 1) != ""
    ) --   4. App resources that are Mach-O binaries, such as 2829030009, or enc (Player_009.app, AdobeFlashPlayer_567.app)
    OR (
      file.directory LIKE '/Volumes/%/Resources'
      AND magic.data LIKE '%executable%'
      AND f_ext NOT IN ('py', 'sh', 'metallib')
    ) --   5. Volumes with a name containing suspicious names: Player, Flash, Update
    OR (
      (
        vol_name LIKE "Install%"
        OR vol_name LIKE "%Player"
        OR vol_name LIKE "%Flash%"
        OR vol_name LIKE "%Update"
      )
      AND file.directory LIKE "/Volumes/%/Contents/MacOS"
      AND signature.authority NOT IN (
        "Developer ID Application: Logitech Inc. (QED4VVPZWA)",
        "Developer ID Application: VideoLAN (75GAHG3SZQ)"
      )
    ) --   6. Volumes containing a hidden top-level folder or binary, such as yWnBJLaF (1302.app)
    OR (
      file.bsd_flags = "HIDDEN"
      AND (
        file.mode LIKE "%7%"
        OR file.mode LIKE "%5%"
        OR file.mode LIKE "%1%"
      )
      AND file.filename NOT IN (
        '.Trashes',
        '.background',
        '.VolumeIcon.icns',
        '.TemporaryItems'
      )
      -- Brother Printer Utilities
      AND f != '/Volumes/brotherwdswML_nonPanel/MacResources'
      AND file.filename NOT LIKE '%.previous'
      AND file.filename NOT LIKE '%.interrupted'
      AND signature.authority != 'Developer ID Application: Google LLC (EQHXZ8M8AV)'
      AND file.filename NOT LIKE '%.backup'
    ) --   7. Volumes containing a top-level symlink to something other than /Applications, such as yWnBJLaF (1302.app)
    OR (
      file.symlink = 1
      AND magic.data != 'symbolic link to /Applications'
      AND magic.data != 'symbolic link to /Applications/'
      AND magic.data != 'symbolic link to .'
      -- emacs
      AND magic.data != 'symbolic link to bin-x86%'
      AND magic.data NOT LIKE 'symbolic link to /Users/%/My Drive'
      AND magic.data NOT LIKE 'symbolic link to /Library/Application Support/Apple/Safari/SafariForWebKitDevelopment'
    )
  )
GROUP BY
  file.path;
