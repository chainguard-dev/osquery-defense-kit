-- Look for sketchy mounted disk images, inspired by Shlayer
--
-- references:
--   * https://attack.mitre.org/techniques/T1566/001/ (Phishing: Spearphishing Attachment)
--   * https://attack.mitre.org/techniques/T1204/002/ (User Execution: Malicious File)
--   * https://www.crowdstrike.com/blog/how-crowdstrike-uncovered-a-new-macos-browser-hijacking-campaign/
--
-- tags: volume filesystem
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
  signature.identifier AS s_id,
  yara.*
FROM
  file
  JOIN yara ON file.path = yara.path
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
      OR file.directory LIKE mounts.path || "/%/%.app/Contents/Library/LaunchServices"
      OR file.directory LIKE mounts.path || "/%/%.app/Contents/Resources/"
    WHERE
      model = 'Disk Image'
      AND parent != ""
      AND mounts.path LIKE "/Volumes/%"
      -- osquery will traverse symlinks, this prevents following symlinks to /Applications (poorly)
      AND file.path NOT LIKE "/Volumes/%/Applications/%"
      AND (
        file.mode LIKE "%7%"
        OR file.mode LIKE "%5%"
        OR file.mode LIKE "%1%"
      )
      AND file.type = "regular"
  )
  AND magic.data LIKE "%Executable%"
  AND yara.sigrule = '    
    rule stealer {
    strings:
        $data_stealers = "data_stealers" ascii
        $library_keychains = "/Library/Keychains" ascii
        $cookies_sqlite = "cookies.sqlite" ascii
        $moz_cookies = "moz_cookies" ascii
        $operagx = "OperaGX" ascii
        $brave_software = "BraveSoftware" ascii
        $osascript = "osascript" ascii
        $find_generic_password = "find-generic-password" ascii

    condition:
        2 of them
}'
  AND yara.count > 0
GROUP BY
  file.path
