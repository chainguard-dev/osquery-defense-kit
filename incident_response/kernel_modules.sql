-- Retrieves all the information for the current kernel modules in the target Linux system.
--
-- interval: 3600
-- platform: linux
-- value: Identify malware that has a kernel module component.
-- version: 1.4.5
select
  *
from
  kernel_modules;
