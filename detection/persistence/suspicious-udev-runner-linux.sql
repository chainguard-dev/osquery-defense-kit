-- Look for sketchy udev entries, inspired by sedexp
-- references:
--  * https://www.aon.com/en/insights/cyber-labs/unveiling-sedexp
--
-- tags: volume filesystem
-- platform: linux
-- tags: volume filesystem
SELECT file.path,
    file.size,
    file.btime,
    file.ctime,
    file.mtime,
    hash.sha256,
    yara.*
FROM file
    JOIN yara ON file.path = yara.path
    LEFT JOIN hash ON file.path = hash.path
WHERE file.path IN (
        SELECT file.path
        FROM file
        WHERE file.path LIKE '/etc/udev/rules.d/%'
            OR file.path LIKE '/usr/lib/udev/rules.d/%'
            OR file.path LIKE '/lib/udev/rules.d/%'
            OR file.path LIKE '/usr/local/lib/udev/rules.d/%'
        GROUP BY file.inode
    )
    AND yara.sigrule = '
rule udev_kernel_memory_device_runner : critical {
    meta:
        description = "runs program once built-in memory device is created"
    strings:
        $action_add = "ACTION==\"add\""
        $major = "ENV{MAJOR}==\"1\""
        $run = "RUN+="
    condition:
        all of them
}

rule tiny_udev_runner_unusual : high {
    meta:
        description = "small udev entry that runs program based on unusual parameters"
    strings:
        $action_add = "ACTION==\"add\""
        $action_run = "RUN+="

        $not_attrs = "ATTRS{"
        $not_subsystem = "SUBSYSTEM=="
    condition:
        filesize < 256 and all of ($action*) and none of ($not*)
}

rule udev_kernel_builtin_runner : high {
    meta:
        description = "runs program once major device number is created, may have false-positives"
    strings:
        $action_add = "ACTION==\"add\""
        $major = "ENV{MAJOR}=="
        $run = "RUN+="
    condition:
        all of them
}'
    AND yara.count > 0