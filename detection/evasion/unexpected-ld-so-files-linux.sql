-- Find unexpected ld.so.conf files
--
-- If you have Augeas available, you may want to use that in conjunction with this more limited check.
--
-- false positives:
--   * none known
--
-- tags: persistent seldom
-- platform: linux
SELECT
  file.path,
  uid,
  gid,
  mode,
  file.mtime,
  file.size,
  hash.sha256,
  CONCAT (file.path, ',', mode, ',', size, ',', sha256) AS exception_key
FROM
  file
  LEFT JOIN hash on file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    file.path IN ('/etc/ld.so.conf', '/etc/ld.so.preload')
    OR file.path LIKE '/etc/ld.so.conf.d/%'
    OR file.path LIKE '/etc/ld.so.conf.d/.%'
  )
  AND file.filename NOT IN ('.', '..')
  AND exception_key NOT IN (
    '/etc/ld.so.conf,0644,117,dad04a370e488aa85fb0a813a5c83cf6fd981ce01883fc59685447b092de84b5',
    '/etc/ld.so.conf,0644,28,239c865e4c0746a01f82b03d38d620853bab2a2ba8e81d6f5606c503e0ea379f',
    '/etc/ld.so.conf,0644,34,d4b198c463418b493208485def26a6f4c57279467b9dfa491b70433cedb602e8',
    '/etc/ld.so.conf.d/cuda.conf,0644,66,a65f7d96e2447eb40b1be9586b90eb0bd776a8938c93d21f9606d2880b548b28',
    '/etc/ld.so.conf.d/dyninst-x86_64.conf,0644,19,a4c740c1f59176d816ba18d429ba823317d3db416accf6d79a9cb0ac845d9d50',
    '/etc/ld.so.conf.d/fakeroot.conf,0644,21,564c4c4d369d005702d825d34edc5e5568cb1ab6ee1b19fa03d0d672fb8b3aee',
    '/etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf,0644,38,af7edc777dd224bade078ba540538444db69856533c02e18a7f9fbbdd23bd181',
    '/etc/ld.so.conf.d/i386-linux-gnu.conf,0644,168,023231b8d6d21a7f4b1a59b875576604395041c814c0fd640d4a1d3d29455e6a',
    '/etc/ld.so.conf.d/lib32-glibc.conf,0644,11,c27424154a6096ae32c0824b785e05de6acef33d9224fd6147d1936be9b4962b',
    '/etc/ld.so.conf.d/libc.conf,0644,44,90d4c7e43e7661cd116010eb9f50ad5817e43162df344bd1ad10898851b15d41',
    '/etc/ld.so.conf.d/libiscsi-x86_64.conf,0644,17,fa3839c3cb893d3a589a020a0a9a010de1332b8385ee8139660e2da8bcc932a3',
    '/etc/ld.so.conf.d/llvm13-x86_64.conf,0644,22,4da62e9ec76b030c527e2ea87ccfab1baeff7d0f9092f980231e49961bb97de0',
    '/etc/ld.so.conf.d/opencollada.conf,0644,21,2fc9656a2b881ca4528416daa91fc525adaa97d73e96a18b41aa7856270eba1f',
    '/etc/ld.so.conf.d/perf.conf,0644,14,c67f871bdc72182dc75c160b16ca3b5371fdab76a27199a29f14b52a5aed1d3f',
    '/etc/ld.so.conf.d/pipewire-jack-x86_64.conf,0644,30,cf4cb69feaa8ec8b99558c4e1123518831b3c56488981cbc34a662fe218ef221',
    '/etc/ld.so.conf.d/tix-x86_64.conf,0644,18,b2ef4843990ded5fd96e417fc08027a785fac59bd70eca6a26dd7b057542273a',
    '/etc/ld.so.conf.d/x86_64-linux-gnu.conf,0644,100,f03e4740e6922b4f4a1181cd696b52f62f9f10d003740a8940f7121795c59c98'
  )
