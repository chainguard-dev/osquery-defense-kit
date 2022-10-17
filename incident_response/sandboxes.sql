-- Lists the application bundle that owns a sandbox label.
--
-- interval: 86400
-- platform: darwin
-- value: Post-priori hijack detection, detect potential sensitive information leakage.
-- version: 1.4.7
select
  *
from
  sandboxes;
