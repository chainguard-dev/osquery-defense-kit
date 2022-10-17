-- Retrieves the current status of IP/IPv6 forwarding.
--
-- interval: 3600
-- platform: posix
-- value: Identify if a machine is being used as relay.
-- version: 1.4.5
select
  *
from
  system_controls
where
  oid = '4.30.41.1'
union
select
  *
from
  system_controls
where
  oid = '4.2.0.1';
