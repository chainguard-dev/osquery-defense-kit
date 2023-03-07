-- Unusually tainted kernel - via a loaded kernel module
--
-- references:
--   * https://attack.mitre.org/techniques/T1014/ (Rootkit)
--   * https://docs.kernel.org/admin-guide/tainted-kernels.html
--
-- Confirmed to catch revenge-rtkit
--
-- false positives:
--   * custom kernel modules
--
-- tags: persistent kernel state
-- platform: linux
--
-- 12289 is an unsigned, out of tree, proprietary driver
-- 4097 is a signed, out of tree, proprietary driver
SELECT current_value AS value,
    current_value & 65536 AS is_aux,
    current_value & 8192 is_unsigned,
    current_value & 4096 AS out_of_tree,
    current_value & 512 AS kernel_warning,
    current_value & 614 AS requested_by_userspace,
    current_value & 8 AS force_unloaded,
    current_value & 4 AS out_of_spec,
    current_value & 2 AS force_loaded,
    current_value & 1 AS proprietary
FROM system_controls
WHERE name = "kernel.tainted"
    AND current_value NOT IN (0, 512, 12289, 12352, 4097)