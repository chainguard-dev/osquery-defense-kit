-- Retrieves the list of application scheme/protocol-based IPC handlers.
--
-- interval: 86400
-- platform: darwin
-- value: Post-priori hijack detection, detect potential sensitive information leakage.
-- version: 1.4.7
select
  *
from
  app_schemes;
