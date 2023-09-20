-- Recently downloaded UPX file
SELECT
  file.path,
  file.size,
  file.btime,
  file.ctime,
  file.mtime,
  magic.data,
  hash.sha256
FROM
  file
  JOIN yara ON file.path = yara.path
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN hash ON file.path = hash.path
WHERE
  -- Only scan recent downloads
  (
    file.path LIKE '/home/%/Downloads/%'
    OR file.path LIKE '/Users/%/Downloads/%'
    OR file.path LIKE '/Volumes/%'
    OR file.path LIKE '/tmp/%'
    OR file.path LIKE '/var/tmp/%'
  )
  AND (
    file.btime > (strftime('%s', 'now') -432000)
    OR file.ctime > (strftime('%s', 'now') -432000)
    OR file.mtime > (strftime('%s', 'now') -432000)
  )
  AND yara.sigrule = '    
    rule upx {
    strings:
        $upx_sig = "UPX!"

    condition:
        $upx_sig in (0..1024)
    }'
  AND yara.count > 0