out/osqtool:
	mkdir -p out
	GOBIN=$(CURDIR)/out go install github.com/chainguard-dev/osqtool/cmd/osqtool@latest

out/odk-detection.conf: out/osqtool
	./out/osqtool --max-results=0 --verify pack detection/ > out/odk-detection.conf

out/odk-policy.conf: out/osqtool
	./out/osqtool --max-results=0 --verify pack policy/ > out/odk-policy.conf

out/odk-incident-response.conf: out/osqtool
	./out/osqtool --max-results=40960 --max-query-duration=8s --max-total-daily-duration=90m --verify pack incident_response/ > out/odk-incident-response.conf

# An alternative rules file for configurations where the "wireless_networks" table is forbidden for querying
out/odk-incident-response-no-wifi.conf: out/osqtool
	./out/osqtool --max-results=40960 --max-query-duration=8s --max-total-daily-duration=90m --verify --exclude wireless_networks_macos pack incident_response/ > out/odk-incident-response-no-wifi.conf

packs: out/odk-detection.conf out/odk-policy.conf out/odk-incident-response.conf out/odk-incident-response-no-wifi.conf

out/odk-packs.zip: packs
	cd out && zip odk-packs.zip *.conf

.PHONY: reformat
reformat:
	find . -type f -name "*.sql" | perl -ne 'chomp; system("cp $$_ /tmp/fix.sql && npx sql-formatter -l sqlite /tmp/fix.sql > $$_");'

all: out/odk-packs.zip
