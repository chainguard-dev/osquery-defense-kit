SELECT * FROM file WHERE
(path LIKE "/tmp/%%" OR path LIKE "/var/tmp/%%")
AND type = "regular"
AND mode LIKE "07%"
AND path NOT LIKE "%go-build%"
AND path NOT LIKE "%/bin/%-gen"
AND path NOT LIKE "%/bin/%"
AND path NOT LIKE "%/ko/%"
AND path NOT LIKE "%/CCLBS/%"
AND PATH NOT LIKE "%/tmp/epdf%"
AND PATH NOT LIKE "%/pdf-tools/%"
AND PATH NOT LIKE "/tmp/%.sh"
AND PATH NOT LIKE "/tmp/terraformer/%"
