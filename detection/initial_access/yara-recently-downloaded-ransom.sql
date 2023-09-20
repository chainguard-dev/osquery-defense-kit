-- Recently downloaded UPX file
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
    OR file.path LIKE '/tmp/%'
    OR file.path LIKE '/var/tmp/%'
  )
  AND (
    file.btime > (strftime('%s', 'now') -432000)
    OR file.ctime > (strftime('%s', 'now') -432000)
    OR file.mtime > (strftime('%s', 'now') -432000)
  )
  AND yara.sigrule = '    
    rule ransomware {
    strings:
        $unfortunately = "unfortunately" ascii
        $crypted = "crypted" ascii
        $leaked = "leaked" ascii
        $recover = "recover your" ascii
        $leaks = "of leaks" ascii
        $decrypt = "will decrypt" ascii
        
        $onion = ".onion/" ascii    
        $tor = "TOR Browser" ascii

        $esxcli = "esxcli" ascii
    condition:
        filesize < 10MB and 2 of them
}'
  AND yara.count > 0