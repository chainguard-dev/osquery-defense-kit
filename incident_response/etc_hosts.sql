-- Retrieves all the entries in the target system /etc/hosts file.
--
-- interval: 86400
-- platform: posix
-- value: Identify network communications that are being redirected. Example: identify if security logging has been disabled
-- version: 1.4.5
select
  *
from
  etc_hosts;
