-- Find unexpected executables in temp directories, often used by malware droppers
--
-- false positives:
--   * developers building code out of /tmp
--
-- tags: persistent
-- platform: posix
SELECT
  file.path,
  uid,
  gid,
  mode,
  file.mtime,
  file.size,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash on file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    -- Recursive queries don't seem to work well with hidden directories :(
    file.path LIKE '/tmp/%%'
    OR file.path LIKE '/tmp/.%/%%'
    OR file.path LIKE '/tmp/%/%%'
    OR file.path LIKE '/tmp/%/%/.%'
    OR file.path LIKE '/tmp/%/.%/%%'
  )
  AND file.type = 'regular'
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%'
  AND (
    file.mode LIKE '%7%'
    or file.mode LIKE '%5%'
    or file.mode LIKE '%1%'
  )
  AND NOT (
    uid > 500
    AND (
      file.path LIKE '%/go-build%'
      OR file.path LIKE '/tmp/checkout/%'
      OR file.path LIKE '/tmp/com.apple.installer%'
      OR file.path LIKE '/tmp/flow/%.npmzS_cacachezStmpzSgit-clone%'
      OR file.path LIKE '/tmp/%/site-packages/markupsafe/_speedups.cpython-%'
      OR file.path LIKE '/tmp/go.%.sum'
      OR file.path LIKE '/tmp/guile-%/guile-%'
      OR file.path LIKE '/tmp/terraformer/%'
      OR file.path LIKE '/tmp/tmp.%'
      OR file.path LIKE '%/bin/%-gen'
      OR file.path LIKE '%/bin/%'
      OR file.path LIKE '%/CCLBS/%'
      OR file.path LIKE '%/ko/%'
      OR file.path LIKE '%/pdf-tools/%'
      OR file.path LIKE '%/tmp/epdf%'
      OR -- These regular expressions can be narrowed down
      (
        file.size < 8000
        AND file.path LIKE '/tmp/%.sh'
        AND file.uid > 500
      )
      OR (
        file.size < 8000
        AND file.path LIKE '/tmp/%.py'
        AND file.uid > 500
      )
    )
  ) -- Nix
  AND NOT (
    file.directory LIKE '/tmp/tmp%'
    AND gid = 0
    AND uid > 300
    AND uid < 350
  ) -- Babel
  AND NOT (
    file.directory LIKE '/tmp/babel-%/sh-script-%'
    AND gid > 900
    AND uid = 1000
    AND size < 1024
  ) -- Random Testdata
  AND NOT (
    gid > 900
    AND uid = 1000
    AND (
      file.directory LIKE '/tmp/%/test'
      OR file.directory LIKE '/tmp/%/testdata'
    )
  ) -- Don't alert if the file is only on disk for a moment
  AND NOT (
    file.directory LIKE '/tmp/%'
    AND (strftime('%s', 'now') - ctime) < 30
  ) -- macOS updates
  AND NOT file.directory LIKE '/tmp/msu-target-%' -- I don't know man. I don't work here.
  AND NOT (
    file.path LIKE('/tmp/%compressed')
    AND size < 4000
    AND uid > 500
  ) -- Executables too small to even hold '#!/bin/sh\nuid'
  AND NOT (
    file.type = 'regular'
    AND size < 10
  )
