-- Retrieves all the listening ports in the target system.
--
-- interval: 3600
-- platform: posix
-- value: Detect if a listening port iis not mapped to a known process. Find backdoors.
-- version: 1.4.5
select
  *
from
  listening_ports;
