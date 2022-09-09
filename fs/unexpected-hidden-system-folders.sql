SELECT path, mtime, ctime, size, type
FROM file
WHERE (
        path LIKE '/lib/.%'
        OR path LIKE '/.%'
        OR path LIKE '/bin/%/.%'
        OR path LIKE '/lib/%/.%'
        OR path LIKE '/libexec/.%'
        OR path LIKE '/Library/.%'
        OR path LIKE '/sbin/.%'
        OR path LIKE '/sbin/%/.%'
        OR path LIKE '/tmp/.%'
        OR path LIKE '/usr/bin/.%'
        OR path LIKE '/usr/lib/.%'
        OR path LIKE '/usr/lib/%/.%'
        OR path LIKE '/usr/libexec/.%'
        OR path LIKE '/usr/local/bin/.%'
        OR path LIKE '/usr/local/lib/.%'
        OR path LIKE '/usr/local/lib/.%'
        OR path LIKE '/usr/local/libexec/.%'
        OR path LIKE '/usr/local/sbin/.%'
        OR path LIKE '/usr/sbin/.%'
        OR path LIKE '/var/.%'
        OR path LIKE '/var/lib/.%'
        OR path LIKE '/var/tmp/.%'
        OR path LIKE '/dev/.%'
    )
    AND path NOT IN (
        '/.autorelabel',
        '/.file',
        '/.vol/',
        '/.VolumeIcon.icns',
        '/tmp/._contentbarrier_installed',
        '/tmp/../',
        '/tmp/./',
        '/tmp/.%.lock',
        '/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress',
        '/tmp/.dotnet/',
        '/tmp/.font-unix/',
        '/tmp/.ICE-unix/',
        '/tmp/.Test-unix/',
        '/tmp/.X0-lock',
        '/tmp/.X1-lock',
        '/tmp/.X11-unix/',
        '/tmp/.XIM-unix/',
        '/var/.Parallels_swap/'
    )
    AND path NOT LIKE '/tmp/.#%'
    AND path NOT LIKE '/tmp/.com.google.Chrome.%'
    AND path NOT LIKE '/tmp/.org.chromium.Chromium%'
    AND path NOT LIKE '/tmp/.X1%-lock'
    AND PATH NOT LIKE '/usr/local/%/.keepme'
    AND PATH NOT LIKE '%/../'
    AND PATH NOT LIKE '%/./'
    AND PATH NOT LIKE '%/.build-id/'
    AND PATH NOT LIKE '%/.dwz/'
    AND PATH NOT LIKE '%/.updated'
    AND PATH NOT LIKE '/%bin/bootstrapping/.default_components'
    AND PATH NOT LIKE '%/google-cloud-sdk/.install/'
    AND PATH NOT LIKE '/tmp/.%.gcode'
    AND (
        type != 'regular'
        OR size > 1
    )