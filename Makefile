ARCH ?= $(shell uname -m)
COLLECT_DIR ?= "./out/$(shell hostname -s)-$(shell date +%Y-%m-%-d-%H-%M-%S)"
SUDO ?= "sudo"

out/osqtool-$(ARCH):
	mkdir -p out
	GOBIN=$(CURDIR)/out go install github.com/chainguard-dev/osqtool/cmd/osqtool@latest
	mv out/osqtool out/osqtool-$(ARCH)

out/odk-detection.conf: out/osqtool-$(ARCH) $(wildcard detection/*.sql)
	./out/osqtool-$(ARCH) --verify pack detection/ > out/.odk-detection.conf
	mv out/.odk-detection.conf out/odk-detection.conf

out/odk-policy.conf: out/osqtool-$(ARCH)  $(wildcard policy/*.sql)
	./out/osqtool-$(ARCH) --verify pack policy/ > out/.odk-policy.conf
	mv out/.odk-policy.conf out/odk-policy.conf

out/odk-incident-response.conf: out/osqtool-$(ARCH)  $(wildcard incident_response/*.sql)
	./out/osqtool-$(ARCH) --verify pack incident_response/ > out/.odk-incident_response.conf
	mv out/.odk-incident_response.conf out/odk-incident_response.conf

# An alternative rules file for configurations where the "wireless_networks" table is forbidden for querying
out/odk-incident-response-no-wifi.conf: out/osqtool-$(ARCH)
	./out/osqtool --max-results=150000 --max-query-duration=8s --max-total-daily-duration=90m --verify --exclude wireless_networks_macos pack incident_response/ > out/odk-incident-response-no-wifi.conf

packs: out/odk-detection.conf out/odk-policy.conf out/odk-incident-response.conf out/odk-incident-response-no-wifi.conf

out/odk-packs.zip: packs
	cd out && zip odk-packs.zip *.conf

.PHONY: reformat
reformat:
	find . -type f -name "*.sql" | perl -ne 'chomp; system("cp $$_ /tmp/fix.sql && npx sql-formatter -l sqlite /tmp/fix.sql > $$_");'

.PHONY: reformat-updates
reformat-updates:
	git status -s | awk '{ print $$2 }' | grep ".sql" | perl -ne 'chomp; system("cp $$_ /tmp/fix.sql && npx sql-formatter -l sqlite /tmp/fix.sql > $$_");'

.PHONY: collection
collection: ./out/osqtool-$(ARCH)
	mkdir -p $(COLLECT_DIR)
	@echo "Saving output to: $(COLLECT_DIR)"
	$(SUDO) ./out/osqtool-$(ARCH) run incident_response | tee $(COLLECT_DIR)/incident_response.txt
	$(SUDO) ./out/osqtool-$(ARCH) run policy | tee $(COLLECT_DIR)/policy.txt
	$(SUDO) ./out/osqtool-$(ARCH) run detection | tee $(COLLECT_DIR)/detection.txt

.PHONY: verify
verify: ./out/osqtool-$(ARCH)
	$(SUDO) ./out/osqtool-$(ARCH) --max-results=150000 --max-query-duration=15s --max-total-daily-duration=90m verify incident_response
	$(SUDO) ./out/osqtool-$(ARCH) --max-results=0 --max-query-duration=6s verify policy
	$(SUDO) ./out/osqtool-$(ARCH) --max-results=0 --max-query-duration=6s --max-total-daily-duration=2h30m --max-query-daily-duration=1h verify detection

all: out/odk-packs.zip

