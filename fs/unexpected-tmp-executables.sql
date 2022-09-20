SELECT file.path, uid, gid, mode, file.mtime, file.size, hash.sha256, magic.data
FROM file
LEFT JOIN hash on file.path = hash.path
LEFT JOIN magic ON file.path = magic.path
WHERE (
    file.path LIKE "/tmp/%%"
    OR file.path LIKE "/var/tmp/%%"
)
AND file.type = "regular"
AND (file.mode LIKE "%7%" or file.mode LIKE "%5%" or file.mode LIKE "%1%")
AND NOT (
    uid > 500 AND (
        file.path LIKE "%go-build%" OR
        file.path LIKE "%/bin/%-gen" OR
        file.path LIKE "%/bin/%" OR
        file.path LIKE "%/ko/%" OR
        file.path LIKE "%/CCLBS/%" OR
        file.path LIKE "%/tmp/epdf%" OR
        file.path LIKE "%/pdf-tools/%" OR
        file.path LIKE "/tmp/terraformer/%" OR
        file.path LIKE "/tmp/checkout/%" OR
        file.path LIKE "/tmp/guile-%/guile-%" OR
        file.path LIKE "/tmp/com.apple.installer%" OR
        (file.size < 4000 AND file.path LIKE "/tmp/%.sh") OR
        (file.size < 4000 AND file.path LIKE "/tmp/tmp.%")
    )
)
-- Nix
AND NOT (file.directory LIKE "/tmp/tmp%" AND gid=0 AND uid> 300 AND uid< 350)
-- Don't alert if it's only on disk for a moment
AND NOT (file.directory LIKE "/tmp/%" AND (strftime('%s', 'now') - ctime) < 60)
-- macOS updates
AND NOT file.directory LIKE "/tmp/msu-target-%"
