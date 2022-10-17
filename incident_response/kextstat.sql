-- Retrieves all the information about the current kernel extensions for the target OSX system.
--
-- interval: 3600
-- platform: darwin
-- value: Identify malware that has a kernel extension component.
-- version: 1.4.5
select
  *
from
  kernel_extensions;
