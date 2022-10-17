-- Retrieves all the ramdisk currently mounted in the target system.
--
-- interval: 3600
-- platform: posix
-- value: Identify if an attacker is using temporary, memory storage to avoid touching disk for anti-forensics purposes
-- version: 1.4.5
select
  *
from
  block_devices
where
  type = 'Virtual Interface';
