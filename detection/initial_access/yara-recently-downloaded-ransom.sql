-- tags: volume filesystem seldom
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
  file.path IN (
    SELECT
      path
    FROM
      file
    WHERE
      (
        file.path LIKE '/home/%/Downloads/%'
        OR file.path LIKE '/home/%/Downloads/%/%'
        OR file.path LIKE '/Users/%/Downloads/%'
        OR file.path LIKE '/Users/%/Downloads/%/%'
        OR file.path LIKE '/tmp/%'
        OR file.path LIKE '/var/tmp/%'
      )
      AND file.type = "regular"
      AND file.size > 2000
      AND file.size < 400000
      AND (
        file.btime > (strftime('%s', 'now') -43200)
        OR file.ctime > (strftime('%s', 'now') -43200)
        OR file.mtime > (strftime('%s', 'now') -43200)
      )
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
        filesize < 10MB and 3 of them
}'
  AND yara.count > 0
  AND file.path NOT LIKE "%.csv"
  AND file.path NOT LIKE "%.txt"
  AND file.path NOT LIKE "%.md"
  AND file.path NOT LIKE "%.xls"
