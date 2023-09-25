-- Programs running out of unexpected directories, such as /tmp (state-based)
--
-- references:
--   * https://blog.talosintelligence.com/2022/10/alchimist-offensive-framework.html
--
-- tags: transient process state
-- platform: linux
SELECT
  -- Child
  p0.pid AS p0_pid,
  p0.cgroup_path AS p0_cgroup,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.pid IN (
    SELECT DISTINCT
      pid
    FROM
      processes
    WHERE
      pid > 1
      AND path != ""
      AND INSTR(path, "/bin") != 1
      AND INSTR(path, "/sbin/") != 1
      AND INSTR(path, "/usr/bin/") != 1
      AND INSTR(path, "/usr/lib/") != 1
      AND INSTR(path, "/usr/lib64/") != 1
      AND INSTR(path, "/usr/libexec") != 1
      AND INSTR(path, "/usr/sbin/") != 1
      AND INSTR(path, "/usr/x86_64-pc-linux-gnu/bin") != 1
      AND INSTR(path, "/home/") != 1
      AND INSTR(path, "/nix/") != 1
      AND INSTR(path, "/opt/") != 1
      AND INSTR(path, "/snap/") != 1
      AND INSTR(path, "/var/lib/snapd/") != 1
      AND INSTR(path, "/usr/share/spotify") != 1
      AND INSTR(path, "/usr/share/code/") != 1
      AND INSTR(path, "/usr/local/") != 1
      AND INSTR(path, "/tmp/go-build") != 1
      AND INSTR(path, "/app/") != 1
      AND INSTR(path, "/ko-app") != 1
      AND INSTR(path, "/usr/share/teams/") != 1
      AND path NOT LIKE "%/.terraform%"
      AND NOT path LIKE '/tmp/%/osqtool'
      AND NOT path LIKE '/tmp/GoLand/___go_build_%_go'
      AND NOT cgroup_path LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/nerdctl-%'
      AND NOT cgroup_path LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-%'
      AND NOT cgroup_path LIKE '/system.slice/docker-%' -- Interactive terminal
      AND NOT (
        cgroup_path LIKE '/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-Alacritty-%.scope'
        AND path LIKE '/tmp/%'
      )
      AND NOT (
        euid > 500
        AND (
          path LIKE '/tmp/terraform_%/terraform'
          OR path LIKE '/tmp/%/output/%'
          OR path LIKE '/tmp/%/_output/%'
          OR path LIKE '/tmp/%/bin/%'
          OR path LIKE '%/.terraform/providers/%'
          OR path LIKE '/tmp/.mount_%'
        )
      )
    GROUP BY
      path
  )
GROUP BY
  p0.pid
