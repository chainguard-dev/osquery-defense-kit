-- Currently running programs, only the columns that are not constantly changing
--
-- tags: postmortem often
-- platform: posix
SELECT
  pid,
  name,
  path,
  cmdline,
  state,
  cwd,
  root,
  uid,
  gid,
  euid,
  egid,
  suid,
  sgid,
  on_disk,
  start_time,
  parent,
  pgroup,
  threads,
  nice,
  cgroup_path
FROM
  processes
