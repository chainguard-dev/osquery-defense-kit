SELECT file.path, uid, gid, mode, strftime('%s', 'now') - ctime AS mtime_age, magic.*, hash.sha256
FROM file
JOIN magic ON file.path = magic.path
JOIN hash on file.path = hash.path
WHERE (file.path LIKE "/tmp/%%" OR file.path LIKE "/var/tmp/%%")
AND file.type = "regular"
AND (file.mode LIKE "%7%" or file.mode LIKE "%5%" or file.mode LIKE "%1%")
AND file.path NOT LIKE "%go-build%"
AND file.path NOT LIKE "%/bin/%-gen"
AND file.path NOT LIKE "%/bin/%"
AND file.path NOT LIKE "%/ko/%"
AND file.path NOT LIKE "%/CCLBS/%"
AND file.path NOT LIKE "%/tmp/epdf%"
AND file.path NOT LIKE "%/pdf-tools/%"
AND file.path NOT LIKE "/tmp/%.sh"
AND file.path NOT LIKE "/tmp/terraformer/%"
AND file.path NOT LIKE "/tmp/checkout/%"
AND file.path NOT LIKE "/tmp/guile-%/guile-%"
AND file.path NOT LIKE "/tmp/com.apple.installer%"
-- Nix
AND NOT (file.directory LIKE "/tmp/tmp%" AND gid=0 AND uid> 300 AND uid< 350)
-- Don't alert if it's only on disk for a moment
AND NOT (file.directory LIKE "/tmp/%" AND mtime_age < 60)