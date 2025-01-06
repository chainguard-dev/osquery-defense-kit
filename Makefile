ARCH ?= $(shell uname -m)
COLLECT_DIR ?= "./out/$(shell hostname -s)-$(shell date +%Y-%m-%-d-%H-%M-%S)"
SUDO ?= "sudo"
OSQTOOL_VERSION=v1.4.2

out/osqtool-$(ARCH)-$(OSQTOOL_VERSION):
	mkdir -p out
	GOBIN=$(CURDIR)/out go install github.com/chainguard-dev/osqtool/cmd/osqtool@$(OSQTOOL_VERSION)
	mv out/osqtool out/osqtool-$(ARCH)-$(OSQTOOL_VERSION)

out/detection.conf: out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) $(wildcard detection/*.sql)
	./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) --max-query-duration=16s --verify --exclude-tags=disabled,disabled-privacy,extra --output  out/detection.conf pack detection

out/policy.conf: out/osqtool-$(ARCH)-$(OSQTOOL_VERSION)  $(wildcard policy/*.sql)
	./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) --max-query-duration=8s --exclude-tags=disabled,disabled-privacy,extra --verify --output out/policy.conf pack policy/

out/vulnerabilities.conf: out/osqtool-$(ARCH)-$(OSQTOOL_VERSION)  $(wildcard vulnerabilities/*.sql)
	./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) --max-query-duration=8s --exclude-tags=disabled,disabled-privacy,extra --output out/vulnerabilities.conf pack vulnerabilities/

out/incident-response.conf: out/osqtool-$(ARCH)-$(OSQTOOL_VERSION)  $(wildcard incident_response/*.sql)
	./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) --max-query-duration=8s --exclude-tags=disabled,disabled-privacy,extra --output out/incident-response.conf pack incident_response/

out/osquery.conf:
	cat osquery.conf | sed s/"out\/"/""/g > out/osquery.conf

packs: out/detection.conf out/policy.conf out/incident-response.conf out/vulnerabilities.conf

out/packs.zip: packs out/osquery.conf
	cd out && rm -f .*.conf && zip odk-packs.zip *.conf

.PHONY: reformat
reformat:
	find . -type f -name "*.sql" -exec npx sql-formatter -l sqlite --fix {} \;

.PHONY: reformat-updates
reformat-updates:
	git status -s | awk '{ print $$2 }' | grep ".sql" | xargs -n1 npx sql-formatter -l sqlite --fix

.PHONY: detect
detect: ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION)
	$(SUDO) ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) run detection

.PHONY: run-detect-pack
run-detect-pack: out/detection.conf
	$(SUDO) osqueryi --config_path osquery.conf --pack detection

.PHONY: run-policy-pack
run-policy-pack: out/policy.conf
	$(SUDO) osqueryi --config_path osquery.conf --pack policy

.PHONY: run-vuln-pack
run-vuln-pack: out/vulnerabilities.conf
	$(SUDO) osqueryi --config_path osquery.conf --pack vulnerabilities

.PHONY: run-ir-pack
run-ir-pack: out/incident-response.conf
	$(SUDO) osqueryi --config_path osquery.conf --pack incident-response

.PHONY: collect
collect: ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION)
	mkdir -p $(COLLECT_DIR)
	@echo "Saving output to: $(COLLECT_DIR)"
	$(SUDO) ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) run incident_response | tee $(COLLECT_DIR)/incident_response.txt
	$(SUDO) ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) run policy | tee $(COLLECT_DIR)/policy.txt
	$(SUDO) ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) run detection | tee $(COLLECT_DIR)/detection.txt

# Looser values for CI use
.PHONY: verify-ci
verify-ci: ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION)
	$(SUDO) ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) --workers 1 --max-results=150000 --max-query-duration=30s --max-total-daily-duration=90m verify incident_response
	$(SUDO) ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) --workers 1 --max-results=50 --max-query-duration=30s verify policy
	$(SUDO) ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) --workers 1 --max-results=1000 --max-query-duration=30s --max-total-daily-duration=2h30m --max-query-daily-duration=1h verify detection

# Local verification
.PHONY: verify
verify: ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION)
	$(SUDO) ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) --workers 1 --max-results=150000 --max-query-duration=10s --max-total-daily-duration=15m verify incident_response
	$(SUDO) ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) --workers 1 --max-results=0 --max-query-duration=6s --max-total-daily-duration=10m verify policy
	$(SUDO) ./out/osqtool-$(ARCH)-$(OSQTOOL_VERSION) --workers 1 --max-results=0 --max-query-duration=16s --max-total-daily-duration=2h30m --max-query-daily-duration=1h verify detection

all: out/packs.zip
