-- macOS application layer firewall (ALF) service exceptions.
--
-- false positives:
--   * locally built software
--
-- tags: persistent state filesystem
-- platform: darwin
SELECT
  ae.path,
  ae.state,
  file.mtime,
  file.ctime,
  file.uid,
  file.directory,
  file.size,
  file.type,
  hash.sha256,
  signature.identifier,
  signature.authority,
  CONCAT (
    signature.authority,
    ',',
    signature.identifier,
    ',',
    ae.path,
    ',',
    MIN(file.uid, 501)
  ) AS exception_key
FROM
  alf_exceptions ae
  LEFT JOIN file ON ae.path = file.path
  LEFT JOIN hash ON ae.path = hash.path
  LEFT JOIN signature ON ae.path = signature.path
WHERE -- Filter out stock exceptions to decrease overhead
  ae.path NOT IN (
    '/System/Library/CoreServices/UniversalControl.app/',
    '/System/Library/PrivateFrameworks/Admin.framework/Versions/A/Resources/readconfig',
    '/System/Library/PrivateFrameworks/EmbeddedOSInstall.framework/Versions/A/XPCServices/EmbeddedOSInstallService.xpc/',
    '/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/',
    '/usr/bin/nmblookup',
    '/usr/libexec/bootpd',
    '/usr/libexec/configd',
    '/usr/libexec/discoveryd',
    '/usr/libexec/xartstorageremoted',
    '/usr/sbin/mDNSResponder',
    '/usr/sbin/racoon'
  ) -- Ignore files that ahve already been removed
  AND file.filename NOT NULL
  AND exception_key NOT IN (
    ',a.out,/private/tmp/learning-labs-static/server,501',
    ',a.out,/Users/amouat/proj/learning-labs-static/server,501',
    ',a.out,/Users/dlorenc/.wash/downloads/nats-server,501',
    ',com.docker.docker,/Applications/Docker.app/,501',
    ',deskflow-server,/Applications/Deskflow.app/Contents/MacOS/deskflow-server,501',
    'Apple Mac OS Application Signing,io.tailscale.ipn.macos.network-extension,/Applications/Tailscale.app/Contents/PlugIns/IPNExtension.appex/,0',
    'Apple Mac OS Application Signing,io.tailscale.ipn.macos.network-extension,/Applications/Tailscale.localized/Tailscale.app/Contents/PlugIns/IPNExtension.appex/,0',
    'Developer ID Application: Adguard Software Limited (TC3Q7MAJXF),com.adguard.mac.adguard.network-extension,/Library/SystemExtensions/AD3BCA34-237A-4135-B7A4-0F7477D9144C/com.adguard.mac.adguard.network-extension.systemextension/,0',
    'Developer ID Application: Ned Deily (DJ3H93M7VJ),org.python.python,/Library/Frameworks/Python.framework/Versions/3.11/Resources/Python.app/,0',
    'Developer ID Application: Python Software Foundation (BMM5U3QVKW),org.python.python,/Library/Frameworks/Python.framework/Versions/3.11/Resources/Python.app/,0',
    'Developer ID Application: Python Software Foundation (BMM5U3QVKW),org.python.python,/Library/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/,0',
    'Developer ID Application: Tailscale Inc. (W5364U7YZB),io.tailscale.ipn.macsys.network-extension,/Library/SystemExtensions/A30AF854-E980-4345-A658-17000BF66D00/io.tailscale.ipn.macsys.network-extension.systemextension/,0'
  )
  -- Signed
  AND NOT exception_key LIKE 'Developer ID Application:%,/Applications/%.app/,501'
  -- Unsigned
  AND NOT exception_key LIKE ',,/Applications/%.app/,'
  -- Locally compiled
  AND NOT exception_key LIKE ',a.out,/Users/%,501'
  -- Homebrew
  AND NOT exception_key LIKE ',%,/opt/homebrew/Cellar/%,501'
  -- Nix
  AND NOT exception_key LIKE ',%,/nix/store/%,0'
  AND NOT exception_key LIKE ',%,/nix/store/%,501'
  -- Apple (root)
  AND NOT exception_key LIKE 'Software Signing,com.apple.%,0'
  -- App Store
  AND NOT exception_key LIKE 'Apple Mac OS Application Signing,%,/Applications/%.app/,0'
  -- Other weirdo apps
  AND NOT exception_key LIKE 'Developer ID Application: Cypress.Io, Inc. (7D655LWGLY),com.electron.cypress,/Users/%/Library/Caches/Cypress/%/Cypress.app/,501'
  AND NOT exception_key LIKE 'Developer ID Application: Tailscale Inc. (W5364U7YZB),io.tailscale.ipn.macsys.network-extension,/Library/SystemExtensions/%'
  AND NOT exception_key LIKE 'Developer ID Application: The Foundry (82R497YNSK),org.python.python,/Applications/Nuke%/Contents/Frameworks/Python.framework/Versions/%/Resources/Python.app/,501'
  AND NOT signature.authority IN (
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    'Developer ID Application: OpenAI, L.L.C. (2DC432GLL2)',
    'Developer ID Application: The Foundry (82R497YNSK)'
  )
  AND NOT (
    signature.identifier LIKE 'fake-%'
    AND ae.path LIKE '%/exe/fake'
  )
  AND NOT (
    signature.identifier = 'nix'
    AND ae.path LIKE '/nix/store/%-nix-%/bin/nix'
  )
  AND NOT (
    ae.path LIKE '/Users/%/Library/Application%20Support/Steam/Steam.AppBundle/Steam/'
  )
  AND NOT (
    signature.authority = ''
    AND signature.identifier = 'org.chromium.Chromium'
    AND ae.path LIKE '/Users/%/Library/pnpm/global/%/.pnpm/carlo@%/node_modules/carlo/lib/.local-data/mac-%/chrome-mac/Chromium.app/'
  )
  -- End user tools
  AND NOT (
    (
      signature.identifier = 'a.out'
      OR signature.identifier LIKE '%-%'
    )
    AND file.uid > 500
    AND (
      file.directory LIKE '/opt/homebrew/Cellar/%/bin'
      OR file.directory LIKE '/private/var/folders/%/T/go-build%/exe'
      OR file.directory LIKE '/Users/%/%-cli'
      OR file.directory LIKE '/Users/%/bin'
      OR file.directory LIKE '/Users/%/code/%'
      OR file.directory LIKE '/Users/%/debug/%'
      OR file.directory LIKE '/Users/%/gh/%'
      OR file.directory LIKE '/Users/%/git/%'
      OR file.directory LIKE '/Users/%/node_modules/.bin/%'
      OR file.directory LIKE '/Users/%/sigstore/%'
      OR file.directory LIKE '/Users/%/src/%'
      OR file.directory LIKE '/Users/%/target/%'
      OR file.directory LIKE '/Users/%/tmp/%'
    )
  )
GROUP BY
  exception_key
