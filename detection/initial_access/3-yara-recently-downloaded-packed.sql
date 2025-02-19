-- Flag packed binaries that have recently been downloaded
--
-- tags: volume filesystem persistent seldom
SELECT
  file.path,
  file.size,
  file.btime,
  file.ctime,
  file.mtime,
  magic.data,
  hash.sha256,
  yara.*
FROM
  file
  JOIN yara ON file.path = yara.path
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN hash ON file.path = hash.path
WHERE
  file.path IN (
    SELECT
      path
    FROM
      file
    WHERE
      (
        file.path LIKE '/home/%/Downloads/%'
        OR file.path LIKE '/home/%/Downloads/%/%'
        OR file.path LIKE '/Users/%/Downloads/%'
        OR file.path LIKE '/Users/%/Downloads/%/%'
        OR file.path LIKE '/tmp/%'
        OR file.path LIKE '/var/tmp/%'
      )
      AND file.type = "regular"
      AND file.size > 2000
      AND file.size < 400000
      AND (
        file.btime > (strftime('%s', 'now') -43200)
        OR file.ctime > (strftime('%s', 'now') -43200)
        OR file.mtime > (strftime('%s', 'now') -43200)
      )
  )
  AND yara.sigrule = '
rule cxFreeze_Python_executable : high {
  meta:
    hash_2023_MacStealer_weed = "6a4f8b65a568a779801b72bce215036bea298e2c08ec54906bb3ebbe5c16c712"
  strings:
    $cxfreeze = "cx_Freeze"
  condition:
    filesize < 10485760 and $cxfreeze
}
import "math"

rule obfuscated_elf : high {
  meta:
    description = "Obfuscated ELF binary (missing content)"
    hash_2023_APT31_1d60 = "1d60edb577641ce47dc2a8299f8b7f878e37120b192655aaf80d1cde5ee482d2"
    hash_2023_UPX_0c25 = "0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d"
    hash_2023_Earthwrom_1ae6 = "1ae62dbec330695d2eddc7cb9a65d47bad5f45af95e6c8a803f0780e0749a3ad"
  strings:
    $dlsym = "dlsym" fullword
    $gcc = "gcc" fullword
    $libstdc = "libstdc" fullword
    $glibc = "glibc" fullword
    $setsid = "setsid" fullword
    $gmon = "__gmon_start__"
    $glibc2 = "@GLIBC"
    $cxa = "__cxa_finalize"
    $dereg = "__deregister_frame_info"
    $symtab = ".symtab" fullword
    $__libc_start_main = "__libc_start_main"
  condition:
    uint32(0) == 1179403647 and none of them
}

rule high_entropy_header : high {
  meta:
    description = "Obfuscated ELF binary (high entropy content)"
    hash_2023_UPX_0c25 = "0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d"
    hash_2023_UPX_5a59 = "5a5960ccd31bba5d47d46599e4f10e455b74f45dad6bc291ae448cef8d1b0a59"
    hash_2023_FontOnLake_38B09D690FAFE81E964CBD45EC7CF20DCB296B4D_elf = "f155fafa36d1094433045633741df98bbbc1153997b3577c3fa337cc525713c0"
  strings:
    $not_pyinst = "pyi-bootloader-ignore-signals"
    $not_go = "syscall_linux.go"
    $not_go2 = "vdso_linux.go"
  condition:
    uint32(0) == 1179403647 and math.entropy(1200, 4096) > 7 and none of ($not*)
}
import "math"

private rule smallBinary {
	condition:
		// matches ELF or machO binary
		filesize < 64MB and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962)
}

rule high_entropy_7_5 : medium {
    meta:
        description = "higher entropy binary (>7.5)"
    condition:
		smallBinary and math.entropy(1,filesize) >= 7.5
}

rule high_entropy_7_9 : high {
    meta:
        description = "high entropy binary (>7.9)"
	strings:
		// prevent bazel false positive
		$bin_java = "bin/java"
    condition:
		smallBinary and math.entropy(1,filesize) >= 7.9 and not $bin_java
}
rule kiteshield : high {
  meta:
    author = "Alex.Turing, Wang Hao"
    date = "2024-05-28"
    description = "Rule to identify files packed by Kiteshield"
    hash_amdc6766_1 = "2c80808b38140f857dc8b2b106764dd8"
    hash_amdc6766_2 = "909c015d5602513a770508fa0b87bc6f"
    hash_amdc6766_3 = "5ea33d0655cb5797183746c6a46df2e9"
    hash_gafgyt = "4afedf6fbf4ba95bbecc865d45479eaf"
    hash_winnti = "f5623e4753f4742d388276eaee72dea6"
    reference = "https://blog.xlab.qianxin.com/kiteshield_packer_is_being_abused_by_linux_cyber_threat_actors"
    tool = "Kiteshield"
    tool_repository = "https://github.com/GunshipPenguin/kiteshield"

  strings:
    $loader_jmp = {31 D2 31 C0 31 C9 31 F6 31 FF 31 ED 45 31 C0 45 31 C9 45 31 D2 45 31 DB 45 31 E4 45 31 ED 45 31 F6 45 31 FF 5B FF E3}
    // "/proc/%d/status"
    $loader_s1 = {ac f4 f7 e9 e4 a7 ac ee a4 ff f9 ef fb e5 e2}
    // "TracerPid:"
    $loader_s2 = {d7 f6 e4 e5 e2 fa d9 e3 ef b6}
    // "/proc/%d/stat"
    $loader_s3 = {ac f4 f7 e9 e4 a7 ac ee a4 ff f9 ef fb}
    // "LD_PRELOAD"
    $loader_s4 = {cf c0 da d6 d5 cd c5 c5 ca c8}
    // "LD_AUDIT"
    $loader_s5 = {cf c0 da c7 d2 cc c0 de}
    // "LD_DEBUG"
    $loader_s6 = {cf c0 da c2 c2 ca dc cd}
    // "0123456789abcdef"
    $loader_s7 = {b3 b5 b7 b5 b3 bd bf bd b3 b5 ec ec ec f4 f4 f4}

  condition:
    $loader_jmp and all of ($loader_s*) and
    // ELF Magic at offset 0
    uint32(0) == 0x464c457f and
    // ET_EXEC at offset 16
    uint16(16) == 0x0002 and
    (
        // x86_64 at offset 18
        uint16(18) == 0x003e or
        // aarch64 at offset 18
        uint16(18) == 0x00b7
    )
}

rule shc : high {
  meta:
    description = "Binary generated with SHC (Shell Script Compiler)"
    ref = "https://github.com/neurobin/shc"
    hash_2023_Linux_Malware_Samples_1328 = "1328f1c2c9fe178f13277c18847dd9adb9474f389985e17126fcb895aac035f2"
    hash_2023_Linux_Malware_Samples_77b8 = "77b881109c2141aef8a86263de75e041794556489055c1488f1d36feb7d70dd3"
    hash_2023_Linux_Malware_Samples_edbe = "edbee3b92100cc9a6a8a3c1a5fc00212627560c5e36d29569d497613ea3e3c16"
  strings:
    $ref = "argv[0] nor $_"
  condition:
    $ref
}

rule upx : high {
  meta:
    description = "Binary is packed with UPX"
    hash_2023_UPX_0c25 = "0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d"
    hash_2023_UPX_5a59 = "5a5960ccd31bba5d47d46599e4f10e455b74f45dad6bc291ae448cef8d1b0a59"
    hash_2023_FontOnLake_38B09D690FAFE81E964CBD45EC7CF20DCB296B4D_elf = "f155fafa36d1094433045633741df98bbbc1153997b3577c3fa337cc525713c0"
  strings:
    $u_upx_sig = "UPX!"
    $u_packed = "executable packer"
    $u_is_packed = "This file is packed"
    $not_upx = "UPX_DEBUG_DOCTEST_DISABLE"
  condition:
    any of ($u*) in (0..1024) and none of ($not*)
}

rule upx_elf : high {
  meta:
    description = "Linux ELF binary packed with UPX"
    hash_2023_UPX_0c25 = "0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d"
    hash_2023_UPX_5a59 = "5a5960ccd31bba5d47d46599e4f10e455b74f45dad6bc291ae448cef8d1b0a59"
    hash_2023_FontOnLake_1F52DB8E3FC3040C017928F5FFD99D9FA4757BF8_elf = "efbd281cebd62c70e6f5f1910051584da244e56e2a3228673e216f83bdddf0aa"
  strings:
    $proc_self = "/proc/self/exe"
    $prot_exec = "PROT_EXEC|PROT_WRITE failed"
  condition:
    uint32(0) == 1179403647 and $prot_exec and $proc_self
}

rule upx_elf_tampered : critical {
  meta:
    description = "Linux ELF binary packed with modified UPX"
    hash_2023_Unix_Trojan_DarkNexus_2527 = "2527fc4d6491bd8fc9a79344790466eaedcce8795efe540ac323ea93e59c5ab5"
    hash_2023_Unix_Trojan_DarkNexus_2e1d = "2e1d9acd6ab43d63f3eab9fc995080fc67a0a5bbdc66be3aff53ed3745c9e811"
    hash_2023_Unix_Trojan_DarkNexus_3a55 = "3a55dcda90c72acecb548f4318d41708bb73c4c3fb099ff65c988948dc8b216f"
  strings:
    $prot_exec = "PROT_EXEC|PROT_WRITE failed"
    $upx = "UPX!"
  condition:
    uint32(0) == 1179403647 and $prot_exec and not $upx
}
  '
  AND yara.count > 0
