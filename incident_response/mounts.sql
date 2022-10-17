-- Retrieves the current list of mounted drives in the target system.
--
-- interval: 3600
-- platform: posix
-- value: Scope for lateral movement. Potential exfiltration locations. Potential dormant backdoors.
-- version: 1.4.5
select
  *
from
  mounts;
