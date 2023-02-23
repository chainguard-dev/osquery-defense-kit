-- Currently running programs, only the columns that are not constantly changing
--
-- tags: postmortem
-- platform: posix
SELECT pid,
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
  seuid,
  sgid,
  on_disk,
  start_time,
  parent,
  pgroup,
  threads,
  nice,
  cgroup_path
FROM processes