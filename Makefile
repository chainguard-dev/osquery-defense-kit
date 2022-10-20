out/osqtool:
	mkdir -p out
	GOBIN=$(CURDIR)/out go install github.com/chainguard-dev/osqtool/cmd/osqtool@latest

out/odk-detection.sql: out/osqtool
	./out/osqtool --verify pack detection/ > out/odk-detection.conf

out/odk-policy.sql: out/osqtool
	./out/osqtool --verify pack policy/ > out/odk-policy.conf

out/odk-incident_response.sql: out/osqtool
	./out/osqtool --verify pack incident_response/ > out/odk-incident_response.conf

packs: out/odk-detection.sql out/odk-policy.sql out/odk-incident_response.sql

out/odk-packs.zip: packs
	cd out && zip odk-packs.zip *.conf

.PHONY: reformat
reformat:
	find . -type f -name "*.sql" | perl -ne 'chomp; system("cp $$_ /tmp/fix.sql && npx sql-formatter -l sqlite /tmp/fix.sql > $$_");'

all: out/odk-packs.zip
