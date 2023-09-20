-- Recently downloaded Stealer
SELECT
  file.path,
  file.size,
  file.btime,
  file.ctime,
  file.mtime,
  magic.data,
  hash.sha256,
  yara.*
FROM
  file
  JOIN yara ON file.path = yara.path
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN hash ON file.path = hash.path
WHERE
  -- Only scan recent downloads
  (
    file.path LIKE '/home/%/Downloads/%'
    OR file.path LIKE '/home/%/Downloads/%/%'
    OR file.path LIKE '/Users/%/Downloads/%'
    OR file.path LIKE '/Users/%/Downloads/%/%'
    OR file.path LIKE '/tmp/%'
    OR file.path LIKE '/var/tmp/%'
  )
  AND (
    file.btime > (strftime('%s', 'now') -432000)
    OR file.ctime > (strftime('%s', 'now') -432000)
    OR file.mtime > (strftime('%s', 'now') -432000)
  )
  AND yara.sigrule = '    
    rule stealer {
    strings:
        $ds = "data_stealers" ascii
        $lk = "/Library/Keychains" ascii
        $cs = "cookies.sqlite" ascii
        $mc = "moz_cookies" ascii
        $og = "OperaGX" ascii
        $bs = "BraveSoftware" ascii
        $os = "osascript" ascii
        $fgp = "find-generic-password" ascii

    condition:
        2 of them
}'
  AND yara.count > 0