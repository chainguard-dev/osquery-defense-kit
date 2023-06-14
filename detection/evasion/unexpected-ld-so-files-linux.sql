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
    '/etc/ld.so.conf.d/000_cuda.conf,0644,41,a9327cff9435220eac872cffedc7f6144d915bdcb70d985304c72f4c3cb9a7d3',
    '/etc/ld.so.conf.d/989_cuda-11.conf,0644,44,915b1ed4caa95cf65a62a74d8255c5ef80ef864cc2767933c85e240a78957167',
    '/etc/ld.so.conf.d/bind-export-x86_64.conf,0644,26,efeec53def06657c947f064463d5ebdb68f7c6f9e40cc2e72fc11c263484942e',
    '/etc/ld.so.conf.d/cuda.conf,0644,66,a65f7d96e2447eb40b1be9586b90eb0bd776a8938c93d21f9606d2880b548b28',
    '/etc/ld.so.conf.d/dyninst-x86_64.conf,0644,19,a4c740c1f59176d816ba18d429ba823317d3db416accf6d79a9cb0ac845d9d50',
    '/etc/ld.so.conf.d/fakeroot.conf,0644,21,564c4c4d369d005702d825d34edc5e5568cb1ab6ee1b19fa03d0d672fb8b3aee',
    '/etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf,0644,38,af7edc777dd224bade078ba540538444db69856533c02e18a7f9fbbdd23bd181',
    '/etc/ld.so.conf.d/gds-11-8.conf,0644,46,2b48cb0abd03ff1d8926eca02a71540f4ee00ebccad5515e4d28a542dae8438a',
    '/etc/ld.so.conf.d/i386-linux-gnu.conf,0644,168,023231b8d6d21a7f4b1a59b875576604395041c814c0fd640d4a1d3d29455e6a',
    '/etc/ld.so.conf.d/intel-oneapi-compiler-dpcpp-cpp-runtime.conf,0644,48,c0c6efda46a86b0d0cbc620b910cec4ba455d09a2bc7a39adf45ce113093366d',
    '/etc/ld.so.conf.d/intel-oneapi-compiler-dpcpp-cpp-runtime.conf,0644,92,c4f62f0bfed45e548755c60b5e012e79c9062bb2a993c041db661951eb994476',
    '/etc/ld.so.conf.d/intel-oneapi-compiler-dpcpp-cpp-runtime-libs.conf,0644,44,9f123b367c8afdcd116047d24f91339a95724d6f6cd189967696d2eb8eda63b4',
    '/etc/ld.so.conf.d/intel-oneapi-compiler-shared-opencl-cpu.conf,0644,92,c4f62f0bfed45e548755c60b5e012e79c9062bb2a993c041db661951eb994476',
    '/etc/ld.so.conf.d/intel-oneapi-compiler-shared-runtime.conf,0644,157,0b4a1c81fcab2d345f99e0187f29cf28f085ae67bf42c86d7b509c06b345186e',
    '/etc/ld.so.conf.d/intel-oneapi-compiler-shared-runtime.conf,0644,92,c4f62f0bfed45e548755c60b5e012e79c9062bb2a993c041db661951eb994476',
    '/etc/ld.so.conf.d/intel-oneapi-compiler-shared-runtime-libs.conf,0644,65,0e9c472578fe009314f02ab64613fc41114f4d07cfd3a805191a5b755d780a43',
    '/etc/ld.so.conf.d/intel-oneapi-openmp.conf,0644,155,160358af96f4a1a92e624fa84a1776d45c1a2c4695c8b96070374f6d66bf6061',
    '/etc/ld.so.conf.d/intel-oneapi-openmp.conf,0644,155,76736fa4deb3f3f4a7a96a068eb01b610faf9492814d47d36b3acbc1b4fb9fd3',
    '/etc/ld.so.conf.d/intel-oneapi-tbb.conf,0644,48,ab4d154371df8bf81c4fd8f079137994c5c9a60f43bef4132e6ffcbfbb08e99d',
    '/etc/ld.so.conf.d/kernel-3.10.0-1160.83.1.el7.x86_64.conf,0444,63,37cb41e22b4cb69bb7b8652111c59d3d07b6522ac1f4a635e794ca7eaf411dd7',
    '/etc/ld.so.conf.d/kernel-3.10.0-1160.el7.x86_64.conf,0444,63,37cb41e22b4cb69bb7b8652111c59d3d07b6522ac1f4a635e794ca7eaf411dd7',
    '/etc/ld.so.conf.d/lib32-glibc.conf,0644,11,c27424154a6096ae32c0824b785e05de6acef33d9224fd6147d1936be9b4962b',
    '/etc/ld.so.conf.d/libc.conf,0644,44,90d4c7e43e7661cd116010eb9f50ad5817e43162df344bd1ad10898851b15d41',
    '/etc/ld.so.conf.d/libiscsi-x86_64.conf,0644,17,fa3839c3cb893d3a589a020a0a9a010de1332b8385ee8139660e2da8bcc932a3',
    '/etc/ld.so.conf.d/llvm13-x86_64.conf,0644,22,4da62e9ec76b030c527e2ea87ccfab1baeff7d0f9092f980231e49961bb97de0',
    '/etc/ld.so.conf.d/llvm15-x86_64.conf,0644,22,30e995961d9e382d287469acce7e168d15811356bf20971fc17bb582a8d62afa',
    '/etc/ld.so.conf.d/mariadb-x86_64.conf,0644,17,598466b4954bc66c6f45f1f119211b0698d4a549f6c01b5d9a933a2511b82626',
    '/etc/ld.so.conf.d/mingw64-hostlib.conf,0644,29,df1b65371bead6dddc703346f56dde023e22d52d9f071a3b646beaaec75a53c9',
    '/etc/ld.so.conf.d/nessus.conf,0644,16,5a9dc65a4a0daa50ce9dd70ff3973fcceef9660cc3fdf5bb0beec8e0b6c57708',
    '/etc/ld.so.conf.d/opencollada.conf,0644,21,2fc9656a2b881ca4528416daa91fc525adaa97d73e96a18b41aa7856270eba1f',
    '/etc/ld.so.conf.d/perf.conf,0644,14,c67f871bdc72182dc75c160b16ca3b5371fdab76a27199a29f14b52a5aed1d3f',
    '/etc/ld.so.conf.d/pipewire-jack-x86_64.conf,0644,30,cf4cb69feaa8ec8b99558c4e1123518831b3c56488981cbc34a662fe218ef221',
    '/etc/ld.so.conf.d/tix-x86_64.conf,0644,18,b2ef4843990ded5fd96e417fc08027a785fac59bd70eca6a26dd7b057542273a',
    '/etc/ld.so.conf.d/x86_64-linux-gnu.conf,0644,100,f03e4740e6922b4f4a1181cd696b52f62f9f10d003740a8940f7121795c59c98',
    '/etc/ld.so.conf.d/zz_i386-biarch-compat.conf,0644,56,4e3c617050427d51497a0e5969b0159421580cf5e7c9649e39f45b5e2fcb47b6',
    '/etc/ld.so.conf.d/zz_x32-biarch-compat.conf,0644,58,af55087d2769067a6a7c9069fd70f9ac2adb0e0ae29bfbd4e9df7504396c9bf2'
  )
