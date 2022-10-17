-- Retrieves the current filters and chains per filter in the target system.
--
-- interval: 3600
-- platform: linux
-- value: Verify firewall settings are as restrictive as you need. Identify unwanted firewall holes made by malware or humans
-- version: 1.4.5
select
  *
from
  iptables;
