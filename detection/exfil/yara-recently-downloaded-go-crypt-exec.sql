-- Recently downloaded cryptexec program
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
    OR file.path LIKE '/Volumes/%'
    OR file.path LIKE '/tmp/%'
    OR file.path LIKE '/var/tmp/%'
  )
  AND (
    file.btime > (strftime('%s', 'now') -432000)
    OR file.ctime > (strftime('%s', 'now') -432000)
    OR file.mtime > (strftime('%s', 'now') -432000)
  )
  AND NOT file.path LIKE '%.csv'
  AND yara.sigrule = '    
    rule cryptexec {
    strings:
        $s_cbc = "crypto/cipher.newCBC" ascii
        $s_aes = "crypto/aes.newCipher"
        $s_run = "os/exec.(*Cmd).Run" ascii
        $s_exec = "os/exec.Command" ascii
        $not_analysis = "Dynamic Section"
    condition:
        3 of ($s*) and none of ($not*)
}'
  AND yara.count > 0
  AND file.path NOT LIKE '/Users/%/Downloads/chainctl%'
  AND file.filename NOT IN ('grype', 'chainctl', 'elastic-agent')
