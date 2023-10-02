ARCH ?= $(shell uname -m)
COLLECT_DIR ?= "./out/$(shell hostname -s)-$(shell date +%Y-%m-%-d-%H-%M-%S)"
SUDO ?= "sudo"

out/osqtool-$(ARCH):
	mkdir -p out
	GOBIN=$(CURDIR)/out go install github.com/chainguard-dev/osqtool/cmd/osqtool@latest
	mv out/osqtool out/osqtool-$(ARCH)

out/odk-detection-c2.conf: out/osqtool-$(ARCH) $(wildcard detection/c2/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=4s --verify -output out/odk-detection-c2.conf pack detection/c2

out/odk-detection-collection.conf: out/osqtool-$(ARCH) $(wildcard detection/collection/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=4s --verify -output out/odk-detection-collection.conf pack detection/collection

out/odk-detection-credentials.conf: out/osqtool-$(ARCH) $(wildcard detection/credentials/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=4s --verify -output out/odk-detection-credentials.conf pack detection/credentials

out/odk-detection-discovery.conf: out/osqtool-$(ARCH) $(wildcard detection/discovery/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=4s --verify -output out/odk-detection-discovery.conf pack detection/discovery

out/odk-detection-evasion.conf: out/osqtool-$(ARCH) $(wildcard detection/evasion/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=4s --verify -output out/odk-detection-evasion.conf pack detection/evasion

out/odk-detection-execution.conf: out/osqtool-$(ARCH) $(wildcard detection/execution/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=16s --verify -output out/odk-detection-execution.conf pack detection/execution

out/odk-detection-exfil.conf: out/osqtool-$(ARCH) $(wildcard detection/exfil/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=4s --verify -output out/odk-detection-exfil.conf pack detection/exfil

out/odk-detection-impact.conf: out/osqtool-$(ARCH) $(wildcard detection/impact/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=4s --verify -output out/odk-detection-impact.conf pack detection/impact

out/odk-detection-initial_access.conf: out/osqtool-$(ARCH) $(wildcard detection/initial_access/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=8s --verify -output out/odk-detection-initial_access.conf pack detection/initial_access

out/odk-detection-persistence.conf: out/osqtool-$(ARCH) $(wildcard detection/persistence/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=4s --verify -output out/odk-detection-persistence.conf pack detection/persistence

out/odk-detection-privesc.conf: out/osqtool-$(ARCH) $(wildcard detection/privesc/*.sql)
	./out/osqtool-$(ARCH) --max-query-duration=4s --verify -output out/odk-detection-privesc.conf pack detection/privesc

out/odk-policy.conf: out/osqtool-$(ARCH)  $(wildcard policy/*.sql)
	./out/osqtool-$(ARCH) --verify --output out/odk-policy.conf pack policy/

out/odk-vulnerabilities.conf: out/osqtool-$(ARCH)  $(wildcard vulnerabilities/*.sql)
	./out/osqtool-$(ARCH) --output out/odk-vulnerabilities.conf pack vulnerabilities/

out/odk-incident-response.conf: out/osqtool-$(ARCH)  $(wildcard incident_response/*.sql)
	./out/osqtool-$(ARCH)  --max-query-duration=12s --output out/odk-incident-response.conf --verify pack incident_response/

# A privacy-aware variation of IR rules
out/odk-incident-response-privacy.conf: out/osqtool-$(ARCH)  $(wildcard incident_response/*.sql)
	./out/osqtool-$(ARCH) --exclude-tags=disabled,disabled-privacy --output out/odk-incident-response-privacy.conf pack incident_response/

out/osquery.conf:
	cat osquery.conf | sed s/"out\/"/""/g > out/osquery.conf

packs: out/odk-detection-c2.conf out/odk-detection-collection.conf out/odk-detection-credentials.conf out/odk-detection-discovery.conf out/odk-detection-evasion.conf out/odk-detection-execution.conf out/odk-detection-exfil.conf out/odk-detection-impact.conf out/odk-detection-initial_access.conf out/odk-detection-persistence.conf out/odk-detection-privesc.conf  out/odk-policy.conf out/odk-incident-response.conf out/odk-incident-response-privacy.conf out/odk-vulnerabilities.conf

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
	$(SUDO) ./out/osqtool-$(ARCH) --max-results=0 --max-query-duration=16s --max-total-daily-duration=2h30m --max-query-daily-duration=1h verify detection

all: out/odk-packs.zip

