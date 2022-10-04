SELECT
  p.name,
  p.path AS path,
  p.cmdline AS cmd,
  p.pid,
  p.parent,
  pp.name AS parent_name,
  pp.path AS parent_path,
  pp.cmdline AS parent_cmd,
  hash.sha256 AS parent_sha256
FROM
  processes p
  LEFT JOIN processes pp ON pp.pid = p.parent
  LEFT JOIN hash ON pp.path = hash.path
WHERE
  p.name IN ("sh", "fish", "zsh", "bash", "dash")
  -- Ignore partial table joins
  AND parent_path != ""
  -- Editors & terminals mostly
  AND pp.name NOT IN (
    "abrt-handle-eve",
    "alacritty",
    "bash",
    "build-script-build",
    "clang-11",
    "Code - Insiders Helper (Renderer)",
    "Code Helper (Renderer)",
    "collect2",
    "conmon",
    "containerd-shim",
    "dash",
    "demoit",
    "direnv",
    "chezmoi",
    "find",
    "FinderSyncExtension",
    "fish",
    "go",
    "goland",
    "java",
    "ko",
    "kubectl",
    "make",
    "monorail",
    "nix-daemon",
    "nix",
    "nix-build",
    "package_script_service",
    "node",
    "nvim",
    "perl",
    "PK-Backend",
    "python",
    "roxterm",
    "sdzoomplugin",
    "skhd",
    "swift",
    "systemd",
    "helm",
    "terminator",
    "test2json",
    "tmux:server",
    "tmux",
    "vi",
    "vim",
    "watch",
    "wezterm-gui",
    "sshd",
    "xargs",
    "xcrun",
    "xfce4-terminal",
    "yum",
    "zsh"
  )
  AND parent_path NOT IN (
    "/Applications/Docker.app/Contents/MacOS/Docker",
    "/bin/dash",
    "/bin/sh",
    "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateDaemon",
    "/opt/X11/libexec/launchd_startx",
    "/sbin/launchd",
    "/usr/bin/alacritty",
    "/usr/bin/apt-get",
    "/usr/bin/bash",
    "/usr/bin/bwrap",
    "/usr/bin/sysdiagnose",
    "/usr/bin/crond",
    "/usr/bin/login",
    "/Applications/Docker.app/Contents/Resources/bin/com.docker.cli",
    "/usr/bin/man",
    "/usr/bin/sudo",
    "/usr/bin/xargs",
    "/usr/bin/zsh",
    "/usr/libexec/gnome-terminal-server",
    "/usr/libexec/periodic-wrapper",
    "/usr/bin/su"
  )
  -- npm run server
  AND NOT p.cmdline IN (
    "sh -c -- exec-bin node_modules/.bin/hugo/hugo server",
    "sh -c xcode-select --print-path >/dev/null 2>&1 && xcrun --sdk macosx --show-sdk-path 2>/dev/null"
  )
  AND NOT (
    pp.name = "sshd"
    AND p.cmdline LIKE "%askpass%"
  )
  AND NOT (
    pp.name = "bash"
    AND p.cmdline LIKE "sh -s _hostname %"
  )
  AND NOT (
    pp.cmdline LIKE "perl%/help2man%"
    AND p.cmdline LIKE "sh -c man/%"
  )

  AND NOT p.cmdline LIKE "%/Library/Apple/System/Library/InstallerSandboxes%"
  AND NOT p.cmdline LIKE "%gcloud config config-helper%"
  AND NOT pp.cmdline LIKE "/Applications/Warp.app/%"
  AND NOT pp.cmdline LIKE "%brew.rb%"
  AND NOT pp.cmdline LIKE "%/Homebrew/build.rb%"
  AND NOT pp.cmdline LIKE "%Code Helper%"
  AND NOT pp.cmdline LIKE "%gcloud.py config config-helper%"
  AND NOT pp.name LIKE "%term%"
  AND NOT pp.name LIKE "%Term%"
  AND NOT pp.name LIKE "Emacs%"
  AND NOT pp.name LIKE "terraform-provider-%"
  AND NOT pp.path LIKE "/Users/%/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS/GoogleSoftwareUpdateAgent"
  -- Oh, NixOS.
  AND NOT pp.name LIKE "%/bin/bash"
  AND NOT pp.name LIKE "%/bin/direnv"
  AND NOT parent_path LIKE "/nix/store/%sh"
  AND NOT parent_path LIKE "/opt/homebrew/%"

