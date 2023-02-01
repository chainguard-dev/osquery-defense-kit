-- Find unexpected executables in temp directories, often used by malware droppers
--
-- false positives:
--   * developers building code out of /tmp
--
-- tags: persistent
-- platform: darwin
SELECT
  file.path,
  uid,
  gid,
  mode,
  REGEX_MATCH (RTRIM(file.path, '/'), '.*\.(.*?)$', 1) AS extension,
  file.btime,
  file.ctime,
  file.mtime,
  file.size,
  hash.sha256,
  magic.data,
  signature.identifier,
  signature.authority
FROM
  file
  LEFT JOIN hash on file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN signature ON file.path = signature.path
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
      OR file.path LIKE '/tmp/src/%'
      OR file.path LIKE '/tmp/terraformer/%'
      OR file.path LIKE '/tmp/tmp.%'
      OR file.path LIKE '/tmp/%/etc/network/if-up.d/%'
      OR file.path LIKE '/tmp/%/bin/busybox'
      OR file.path LIKE '%/bin/%-gen'
      OR file.path LIKE '/tmp/%-%/Photoshop Installer.app/Contents/%'
      OR file.path LIKE '%/CCLBS/%'
      OR file.path LIKE '/tmp/%/target/debug/build/%'
      OR file.path LIKE '%/ko/%'
      OR file.path LIKE '%/pdf-tools/%'
      OR file.path LIKE '%/tmp/epdf%'
      OR -- These regular expressions can be narrowed down
      (
        file.size < 50000
        AND file.uid > 500
        AND extension IN (
          'adoc',
          'bat',
          'java',
          'js',
          'json',
          'nib',
          'log',
          'strings',
          'perl',
          'pl',
          'py',
          'script',
          'sh',
          'txt',
          'yaml',
          'yml'
        )
        AND magic.data NOT LIKE "%Mach-O%"
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
  AND NOT file.directory LIKE '/tmp/UpdateBrain-%/AssetData/com.apple.MobileSoftwareUpdate.UpdateBrainService.xpc/Contents/MacOS'
  -- terraform
  AND NOT (
    uid > 500
    AND file.path LIKE '/tmp/terraform_%/terraform'
  )
  AND NOT (
    file.path LIKE '/tmp/%compressed'
    AND size < 4000
    AND uid > 500
  ) -- Executables too small to even hold '#!/bin/sh\nuid'
  AND NOT (
    file.type = 'regular'
    AND size < 10
  ) -- Common shell scripts
  AND NOT (
    file.filename IN ("configure", "mkinstalldirs")
    AND magic.data = "POSIX shell script, ASCII text executable"
  )
  AND NOT (
    magic.data IS NOT NULL
    AND (
      magic.data IN ('JSON data', 'ASCII text')
      OR magic.data LIKE 'ELF %-bit %SB executable%'
      OR magic.data LIKE 'symbolic link to l%.so.%'
      OR magic.data LIKE 'ELF %-bit LSB shared object%'
      OR magic.data LIKE 'libtool library file,%'
    )
  )
