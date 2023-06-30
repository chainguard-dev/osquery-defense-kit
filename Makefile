ARCH ?= $(shell uname -m)
COLLECT_DIR ?= "./out/$(shell hostname -s)-$(shell date +%Y-%m-%-d-%H-%M-%S)"
SUDO ?= "sudo"

out/osqtool-$(ARCH):
	mkdir -p out
	GOBIN=$(CURDIR)/out go install github.com/chainguard-dev/osqtool/cmd/osqtool@latest
	mv out/osqtool out/osqtool-$(ARCH)

out/odk-detection.conf: out/osqtool-$(ARCH) $(wildcard detection/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=8s --verify pack detection/ > out/.odk-detection.conf
	mv out/.odk-detection.conf out/odk-detection.conf

out/odk-policy.conf: out/osqtool-$(ARCH)  $(wildcard policy/*.sql)
	./out/osqtool-$(ARCH) --verify pack policy/ > out/.odk-policy.conf
	mv out/.odk-policy.conf out/odk-policy.conf

out/odk-incident-response.conf: out/osqtool-$(ARCH)  $(wildcard incident_response/*.sql)
	./out/osqtool-$(ARCH)  --max-query-duration=12s --verify pack incident_response/ > out/.odk-incident-response.conf
	mv out/.odk-incident-response.conf out/odk-incident-response.conf

# A privacy-aware variation of IR rules
out/odk-incident-response-privacy.conf: out/osqtool-$(ARCH)  $(wildcard incident_response/*.sql)
	./out/osqtool-$(ARCH) --exclude-tags=disabled,disabled-privacy pack incident_response/ > out/.odk-incident-response-privacy.conf
	mv out/.odk-incident-response-privacy.conf out/odk-incident-response-privacy.conf

out/osquery.conf:
	cat osquery.conf | sed s/"out\/"/""/g > out/osquery.conf

packs: out/odk-detection.conf out/odk-policy.conf out/odk-incident-response.conf out/odk-incident-response-privacy.conf

out/odk-packs.zip: packs out/osquery.conf
	cd out && rm -f .*.conf && zip odk-packs.zip *.conf

.PHONY: reformat
reformat:
	find . -type f -name "*.sql" | perl -ne 'chomp; system("cp $$_ /tmp/fix.sql && npx sql-formatter -l sqlite /tmp/fix.sql > $$_");'

.PHONY: reformat-updates
reformat-updates:
	git status -s | awk '{ print $$2 }' | grep ".sql" | perl -ne 'chomp; system("cp $$_ /tmp/fix.sql && npx sql-formatter -l sqlite /tmp/fix.sql > $$_");'

.PHONY: detect
detect: ./out/osqtool-$(ARCH)
	$(SUDO) ./out/osqtool-$(ARCH) run detection

.PHONY: run-detect-pack
run-detect-pack: out/odk-detection.conf
	$(SUDO) osqueryi --config_path osquery.conf --pack detection

.PHONY: run-ir-pack
run-ir-pack: out/odk-incident-response.conf
	$(SUDO) osqueryi --config_path osquery.conf --pack incident-response

.PHONY: collect
collect: ./out/osqtool-$(ARCH)
	mkdir -p $(COLLECT_DIR)
	@echo "Saving output to: $(COLLECT_DIR)"
	$(SUDO) ./out/osqtool-$(ARCH) run incident_response | tee $(COLLECT_DIR)/incident_response.txt
	$(SUDO) ./out/osqtool-$(ARCH) run policy | tee $(COLLECT_DIR)/policy.txt
	$(SUDO) ./out/osqtool-$(ARCH) run detection | tee $(COLLECT_DIR)/detection.txt

# Looser values for CI use
.PHONY: verify-ci
verify-ci: ./out/osqtool-$(ARCH)
	$(SUDO) ./out/osqtool-$(ARCH) --max-results=150000 --max-query-duration=30s --max-total-daily-duration=90m verify incident_response
	$(SUDO) ./out/osqtool-$(ARCH) --max-results=2 --max-query-duration=12s verify policy
	$(SUDO) ./out/osqtool-$(ARCH) --max-results=15 --max-query-duration=12s --max-total-daily-duration=2h30m --max-query-daily-duration=1h verify detection

# Local verification
.PHONY: verify
verify: ./out/osqtool-$(ARCH)
	$(SUDO) ./out/osqtool-$(ARCH) --max-results=150000 --max-query-duration=10s --max-total-daily-duration=15m verify incident_response
	$(SUDO) ./out/osqtool-$(ARCH) --max-results=0 --max-query-duration=6s --max-total-daily-duration=10m verify policy
	$(SUDO) ./out/osqtool-$(ARCH) --max-results=0 --max-query-duration=12s --max-total-daily-duration=2h30m --max-query-daily-duration=1h verify detection

all: out/odk-packs.zip

