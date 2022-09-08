SELECT *
FROM chrome_extensions
WHERE (
        from_webstore != true
        OR CAST(permissions AS text) LIKE '%google.com%'
        OR CAST(permissions AS text) LIKE '%github.com%'
        OR CAST(permissions AS text) LIKE '%clipboardWrite%'
        OR CAST(permissions AS text) LIKE '%<all_urls>%'
        OR CAST(permissions AS text) LIKE '%tabs%'
        OR CAST(permissions AS text) LIKE '%cookies%'
        OR CAST(permissions AS text) LIKE '%://*/%'
    )
 AND identifier NOT IN (
    'aabcgdmkeabbnleenpncegpcngjpnjkc', -- Easy Auto Refresh; {tabs,browsingData,notifications,http://*/,https://*/}
    'aeblfdkhhhdcdjpifhhbdiojplfjncoa', -- 1Password – Password Manager; {<all_urls>,contextMenus,downloads,idle,management,nativeMessaging,notifications,privacy,tabs,webNavigation,webRequest,webRequestBlocking}
    'aegnopegbbhjeeiganiajffnalhlkkjb', -- Safe Torrent Scanner; {storage,tabs}
    'andgibkjiikabclfdkecpmdkfanpdapf', -- GIPHY for Gmail; {https://mail.google.com/,https://inbox.google.com/,https://api.giphy.com/*}
    'aomjjhallfgjeglblehebfpbcfeobpgk', -- 1Password extension (desktop app required); {contextMenus,nativeMessaging,storage,tabs,webRequest,webRequestBlocking,http://*/*,https://*/*}
    'apboafhkiegglekeafbckfjldecefkhn', -- Lucidchart Diagrams; {unlimitedStorage,notifications,clipboardRead,clipboardWrite}
    'apdfllckaahabafndbhieahigkjlhalf', -- Google Drive; {clipboardRead,clipboardWrite,notifications}
    'bdakmnplckeopfghnlpocafcepegjeap', -- RescueTime for Chrome and Chrome OS; {tabs,idle,https://*.rescuetime.com/,storage,cookies}
    'bgkodfmeijboinjdegggmkbkjfiagaan', -- WhatsChrome; {webview,notifications,videoCapture,audioCapture,fileSystem,storage,alarms,clipboardWrite}
    'bhdplaindhdkiflmbfbciehdccfhegci', -- Google Optimize; {storage,debugger,webRequest,webRequestBlocking,tabs,http://*/,https://*/}
    'bkdgflcldnnnapblkhphbgpggdiikppg', -- DuckDuckGo Privacy Essentials; {contextMenus,webRequest,webRequestBlocking,*://*/*,webNavigation,activeTab,tabs,storage,<all_urls>,alarms}
    'blaaajhemilngeeffpbfkdjjoefldkok', -- LeechBlock NG; {downloads,contextMenus,storage,tabs,unlimitedStorage,webNavigation}
    'bleoifhkdalbjfbobjackfdifdneehpo', -- Espruino Web IDE; {serial,audioCapture,videoCapture,storage,http://*/,https://*/}
    'bmnlcjabgnpnenekpadlanbbkooimhnj', -- Honey: Automatic Coupons & Cash Back; {cookies,storage,unlimitedStorage,webRequest,webRequestBlocking,http://*/*,https://*/*}
    'bpojelgakakmcfmjfilgdlmhefphglae', -- Set Character Encoding; {tabs,contextMenus,webRequest,webRequestBlocking,storage,<all_urls>}
    'callobklhcbilhphinckomhgkigmfocg', -- Endpoint Verification; {cookies,idle,nativeMessaging,storage,*://*.google.com/*,download,enterprise.reportingPrivate,browsingData,enterprise.deviceAttributes,enterprise.platformKeys,gcm,identity,identity.email,platformKeys}
    'cfhdojbkjhnklbpkdaibdccddilifddb', -- Adblock Plus - free ad blocker; {tabs,<all_urls>,contextMenus,webRequest,webRequestBlocking,webNavigation,storage,unlimitedStorage,notifications}
    'cgdjpilhipecahhcilnafpblkieebhea', -- Send to Kindle for Google Chrome™; {tabs,<all_urls>,storage,unlimitedStorage}
    'chphlpgkkbolifaimnlloiipkdnihall', -- OneTab; {chrome://favicon/,unlimitedStorage,storage,tabs,contextMenus,activeTab}
    'ciagpekplgpbepdgggflgmahnjgiaced', -- Add to Amazon Wish List; {tabs,http://*/*,https://*/*}
    'cjpalhdlnbpafiamejdnhcphjbkeiagm', -- uBlock Origin; {contextMenus,privacy,storage,tabs,unlimitedStorage,webNavigation,webRequest,webRequestBlocking,<all_urls>}
    'cmedhionkhpnakcndndgjdbohmhepckk', -- Adblock for Youtube™; {storage,unlimitedStorage,webRequest,webRequestBlocking,<all_urls>}
    'cppjkneekbjaeellbfkmgnhonkkjfpdn', -- Clear Cache; {browsingData,cookies,<all_urls>}
    'dbepggeogbaibhgnhhndojpepiihcmeb', -- Vimium; {tabs,bookmarks,history,clipboardRead,storage,sessions,notifications,webNavigation,<all_urls>}
    'dcgcnpooblobhncpnddnhoendgbnglpn', -- Superhuman; {background,gcm,notifications,storage,system.cpu,system.display,system.memory,tabs,unlimitedStorage,<all_urls>}
    'dkbjhjljfaagngbdhomnlcheiiangfle', -- Innovative Exams Screensharing; {tabs,desktopCapture,contextMenus}
    'dookpfaalaaappcdneeahomimbllocnb', -- FoxyProxy Basic; {tabs,contextMenus,management,proxy,storage,webNavigation,webRequest,webRequestBlocking,system.cpu,<all_urls>}
    'edacconmaakjimmfgnblocblbcdcpbko', -- Session Buddy; {tabs,unlimitedStorage}
    'eednccpckdkpojaiemedoejdngappaag', -- Prevent Duplicate Tabs; {tabs}
    'eemlkeanncmjljgehlbplemhmdmalhdc', -- Chrome Connectivity Diagnostics; {clipboardWrite,dns,diagnostics,networkingPrivate,metricsPrivate,http://*.google.com/*,https://*.google.com/*}
    'efaidnbmnnnibpcajpcglclefindmkaj', -- Adobe Acrobat: PDF edit, convert, sign tools; {contextMenus,<all_urls>,tabs,downloads,nativeMessaging,webRequest,webRequestBlocking}
    'egnjhciaieeiiohknchakcodbpgjnchh', -- Tab Wrangler; {contextMenus,sessions,storage,tabs}
    'eifflpmocdbdmepbjaopkkhbfmdgijcc', -- JSON Viewer Pro; {*://*/*,contextMenus}
    'eimadpbcbfnmbkopoojfekhnkhdbieeh', -- Dark Reader; {alarms,fontSettings,storage,tabs,<all_urls>}
    'epcnnfbjfcgphgdmggkamkmgojdagdnn', -- uBlock - free ad blocker; {contextMenus,storage,tabs,unlimitedStorage,webNavigation,webRequest,webRequestBlocking,<all_urls>}
    'fdgfkebogiimcoedlicjlajpkdmockpc', -- Facebook Pixel Helper; {tabs,webNavigation,webRequest,webRequestBlocking,storage,identity,*://*/*,clipboardWrite}
    'febilkbfcbhebfnokafefeacimjdckgl', -- Markdown Preview Plus; {storage,clipboardWrite,<all_urls>}
    'fgddmllnllkalaagkghckoinaemmogpe', -- ExpressVPN: VPN proxy for a better internet; {cookies,nativeMessaging,privacy,storage,webRequest,webRequestBlocking,tabs,unlimitedStorage,notifications,<all_urls>}
    'fhbjgbiflinjbdggehcddcbncdddomop', -- Postman; {webview,system.display,http://*/*,https://*/*,contextMenus,unlimitedStorage,storage,fileSystem,fileSystem.write,notifications,identity}
    'fleenceagaplaefnklabikkmocalkcpo', -- Lolli: Earn Bitcoin When You Shop; {<all_urls>,tabs,webNavigation,webRequest}
    'fljalecfjciodhpcledpamjachpmelml', -- Caret; {clipboardRead,clipboardWrite,contextMenus,storage,notifications,syncFileSystem,app.window.fullscreen.overrideEsc}
    'fmkadmapgofadopljbjfkapdkoienihi', -- React Developer Tools; {file:///*,http://*/*,https://*/*}
    'fnbdnhhicmebfgdgglcdacdapkcihcoh', -- Page Analytics (by Google); {storage,https://www.googleapis.com/,tabs,*://*/*,background,cookies,*://*.google.com/*,webNavigation,webRequest,*://*.google-analytics.com/*,*://stats.g.doubleclick.net/*}
    'fngmhnnpilhplaeedifhccceomclgfbg', -- EditThisCookie; {tabs,<all_urls>,cookies,contextMenus,notifications,clipboardWrite,webRequest,webRequestBlocking}
    'fnpbeacklnhmkkilekogeiekaglbmmka', -- Norton Safe Web; {tabs,background,webNavigation,storage,<all_urls>,webRequest,webRequestBlocking,downloads,notifications}
    'gaedmjdfmmahhbjefcbgaolhhanlaolb', -- Authy; {http://*.authy.com/*,http://*.amazonaws.com/*,http://*.amazonaws.com.cn/*,https://*/*,storage,webview,clipboardWrite,unlimitedStorage,fileSystem,idle,notifications,gcm,system.network}
    'gaonpiemcjiihedemhopdoefaohcjoch', -- GoToMeeting for Google Calendar; {cookies,storage,https://api.getgo.com/*,https://*.logmein.com/*,identity}
    'gbkeegbaiigmenfmjfclcdgdpimamgkj', -- Office Editing for Docs, Sheets & Slides; {clipboardRead,clipboardWrite,cookies,downloads,*://*.google.com/*,fileSystem,fileSystem.write,https://www.google-analytics.com/,https://www.googleapis.com/,identity,identity.email,metricsPrivate,storage,unlimitedStorage}
    'gbmdgpbipfallnflgajpaliibnhdgobh', -- JSON Viewer; {*://*/*,<all_urls>}
    'gcbommkclmclpchllfjekcdonpmejbdp', -- HTTPS Everywhere; {webNavigation,webRequest,webRequestBlocking,tabs,cookies,storage,*://*/*,ftp://*/*}
    'ghbmnnjooekpmoecnnnilnnbdlolhkhi', -- Google Docs Offline; {alarms,storage,unlimitedStorage,https://docs.google.com/*,https://drive.google.com/*}
    'gieabiemggnpnminflinemaickipbebg', -- CSS Scan; {storage,activeTab,<all_urls>,contextMenus,clipboardWrite}
    'gighmmpiobklfepjocnamgkkbiglidom', -- AdBlock — best ad blocker; {tabs,<all_urls>,contextMenus,webRequest,webRequestBlocking,webNavigation,storage,unlimitedStorage,notifications,idle,alarms}
    'gkbmnjmlhjnakmfjcejhlhpnibcbjdnl', -- Ads Transparency Spotlight (Alpha); {activeTab,background,webNavigation,webRequest,webRequestBlocking,<all_urls>}
    'gkojfkhlekighikafcpjkiklfbnlmeio', -- Hola VPN - The Website Unblocker; {proxy,webRequest,webRequestBlocking,<all_urls>,storage,tabs,webNavigation,cookies}
    'gmbmikajjgmnabiglmofipeabaddhgne', -- Save to Google Drive; {contextMenus,identity,printerProvider,notifications,pageCapture,storage,tabs,webRequest,<all_urls>}
    'gpghebehjahceknfdcfifeifhdbongld', -- Web Results for Chrome™; {<all_urls>,contextMenus,tabs,storage,cookies,webRequest,notifications,idle}
    'gppongmhjkpfnbhagpmjfkannfbllamg', -- Wappalyzer - Technology profiler; {cookies,storage,tabs,webRequest,webNavigation,http://*/*,https://*/*}
    'haafibkemckmbknhfkiiniobjpgkebko', -- Panda 5 - Your favorite websites in one place; {storage}
    'hdokiejnpimakedhajhdlcegeplioahd', -- LastPass: Free Password Manager; {tabs,idle,notifications,contextMenus,unlimitedStorage,webRequest,webNavigation,webRequestBlocking,http://*/*,https://*/*,chrome://favicon/*}
    'hgmloofddffdnphfgcellkdfbfbjeloo', -- Advanced REST client; {<all_urls>,storage,unlimitedStorage,identity,syncFileSystem}
    'hhlhjgianpocpoppaiihmlpgcoehlhio', -- Super Simple Highlighter; {clipboardWrite,tts,storage,contextMenus,unlimitedStorage,webNavigation,tabs,<all_urls>}
    'hjcneejoopafkkibfbcaeoldpjjiamog', -- Clockwise: Team Time & Calendar Management; {activeTab,https://calendar.google.com/calendar/*}
    'hkgfoiooedgoejojocmhlaklaeopbecg', -- Picture-in-Picture Extension (by Google); {<all_urls>,storage}
    'hmjkmjkepdijhoojdojkdfohbdgmmhki', -- Google Keep - Notes and Lists; {fileSystem,identity,identity.email,storage,unlimitedStorage,https://*.googleapis.com/,https://keep.google.com/media/,https://*.googleusercontent.com/,https://*.client-channel.google.com/client-channel,https://clients4.google.com/client-channel/client,https://www.google-analytics.com/,https://www.google.com/,https://play.google.com/log,geolocation,management,notifications}
    'hmpigflbjeapnknladcfphgkemopofig', -- Ubiquiti Device Discovery Tool; {system.network,clipboardRead,clipboardWrite,notifications,storage,unlimitedStorage}
    'hnfanknocfeofbddgcijnmhnfnkdnaad', -- Coinbase Wallet extension; {storage,alarms,activeTab}
    'hnmpcagpplmpfojmgmnngilcnanddlhb', -- Windscribe - Free Proxy and Ad Blocker; {<all_urls>,proxy,management,tabs,webRequest,webRequestBlocking,activeTab,storage,unlimitedStorage,contextMenus,privacy,webNavigation,notifications,cookies}
    'hpfmedbkgaakgagknibnonpkimkibkla', -- Copper CRM for Gmail; {https://app.copper.com/,webRequest,webRequestBlocking,*://mail.google.com/*,tabs,storage,notifications,*://calendar.google.com/*}
    'iabeihobmhlgpkcgjiloemdbofjbdcic', -- Bitly | Short links and QR Codes; {activeTab,clipboardWrite,identity,storage,contextMenus,https://api-ssl.bitly.com/}
    'idehaflielbgpaokehlhidbjlehlfcep', -- Event Merge for Google Calendar™; {https://www.google.com/calendar/*,https://calendar.google.com/*,storage}
    'igeehkedfibbnhbfponhjjplpkeomghi', -- Tabli; {storage,tabs,bookmarks,chrome://favicon/*}
    'ighdmehidhipcmcojjgiloacoafjmpfk', -- AngularJS Batarang; {tabs,<all_urls>}
    'inlikjemeeknofckkjolnjbpehgadgge', -- Distill Web Monitor; {contextMenus,*://*/*,notifications,tabs,unlimitedStorage}
    'inomeogfingihgjfjlpeplalcfajhgai', -- Chrome Remote Desktop; {clipboardRead,clipboardWrite,nativeMessaging,downloads,downloads.open}
    'ioalpmibngobedobkmbhgmadaphocjdn', -- OneLogin for Google Chrome; {storage,webRequest,webRequestBlocking,tabs,http://*/*,https://*/*,cookies,webNavigation}
    'iodihamcpbpeioajjeobimgagajmlibd', -- Secure Shell; {clipboardRead,clipboardWrite,contextMenus,idle,notifications,storage,terminalPrivate,unlimitedStorage,fileSystemProvider,accessibilityFeatures.read,crashReportPrivate,metricsPrivate}
    'jbgedkkfkohoehhkknnmlodlobbhafge', -- Google Analytics Parameter Stripper; {webNavigation,<all_urls>}
    'jccdpflnecheidefpofmlblgebobbloc', -- Jamstash; {unlimitedStorage,notifications,http://*/*,https://*/*}
    'jeogkiiogjbmhklcnbgkdcjoioegiknm', -- Slack; {unlimitedStorage,notifications,clipboardRead,clipboardWrite}
    'jfnifeihccihocjbfcfhicmmgpjicaec', -- GSConnect; {nativeMessaging,tabs,contextMenus}
    'jndclpdbaamdhonoechobihbbiimdgai', -- Chromebook Recovery Utility; {https://dl.google.com/dl/edgedl/chromeos/recovery/recovery2.json,https://dl.google.com/dl/edgedl/chromeos/recovery/cloudready_recovery2.json,https://www.google-analytics.com/,chromeosInfoPrivate,feedbackPrivate,fileSystem,imageWriterPrivate,metricsPrivate,storage}
    'jngkenaoceimiimeokpdbmejeonaaami', -- PlayTo for Chromecast™; {storage,webRequest,<all_urls>,tabs,webRequestBlocking}
    'jnhgnonknehpejjnehehllkliplmbmhn', -- Web Scraper - Free Web Scraping; {<all_urls>,tabs,notifications,storage,unlimitedStorage}
    'jpdapbcmfllbpojmkefcikllfeoahglb', -- Slickdeals: Automatic Coupons and Deals; {<all_urls>,contextMenus,cookies,gcm,notifications,storage,tabs,unlimitedStorage,webNavigation,webRequest,webRequestBlocking}
    'jplnlifepflhkbkgonidnobkakhmpnmh', -- Private Internet Access; {activeTab,storage,unlimitedStorage,cookies,webRequest,webRequestBlocking,proxy,privacy,contentSettings,alarms,background,downloads,<all_urls>}
    'kbfnbcaeplbcioakkpcpgfkobkghlhen', -- Grammarly: Grammar Checker and Writing App; {http://*/*,https://*/*,tabs,notifications,cookies,storage}
    'kbmfpngjjgdllneeigpgjifpgocmfgmb', -- Reddit Enhancement Suite; {https://*.reddit.com/*,tabs,history,storage,unlimitedStorage,webRequest}
    'kefmekfmfacbdefimlancoccpocmgmpb', -- Commerce Inspector; {storage,webRequest,webRequestBlocking,webNavigation,*://*/*,https://www.google.com/accounts/OAuthGetRequestToken,https://www.google.com/accounts/OAuthAuthorizeToken,https://www.google.com/accounts/OAuthGetAccessToken}
    'kejbdjndbnbjgmefkgdddjlbokphdefk', -- Tag Assistant Legacy (by Google); {identity,storage,tabs,webNavigation,webRequestBlocking,webRequest,http://*/,https://*/}
    'kgjfgplpablkjnlkjmjdecgdpfankdle', -- Zoom Scheduler; {unlimitedStorage,https://www.google.com/calendar/*,https://www.google.com/recaptcha/*,https://www.gstatic.com/recaptcha/*,https://calendar.google.com/calendar/*,https://*.zoom.us/*,https://*.zoom.com/*}
    'kglhbbefdnlheedjiejgomgmfplipfeb', -- Jitsi Meetings; {https://calendar.google.com/*}
    'kljfphapkgkjaiiddfmfpbdmeaplojge', -- Reflect; {storage,alarms,webNavigation,activeTab,scripting,contextMenus}
    'knheggckgoiihginacbkhaalnibhilkk', -- Notion Web Clipper; {activeTab,storage,cookies}
    'kpcibgnngaaabebmcabmkocdokepdaki', -- Utime; {clipboardWrite,contextMenus,notifications}
    'ldjkgaaoikpmhmkelcgkgacicjfbofhh', -- Instapaper; {storage,activeTab,contextMenus,http://*/*,https://*/*}
    'lfpjkncokllnfokkgpkobnkbkmelfefj', -- Linkclump; {bookmarks,http://*/*,https://*/*}
    'lgjhepbpjcmfmjlpkkdjlbgomamkgonb', -- Google Docs Dark Mode; {storage,tabs}
    'liecbddmkiiihnedobmlmillhodjkdmb', -- Loom – Free Screen Recorder & Screen Capture; {<all_urls>,tabCapture,webNavigation,activeTab,contextMenus,storage,tabs,desktopCapture,notifications,cookies,*://*.useloom.com/,*://*.loom.com/,http://localhost/*}
    'lkmofgnohbedopheiphabfhfjgkhfcgf', -- User-Agent Switcher; {webRequest,webRequestBlocking,<all_urls>}
    'lmhkmmkefopogbadhkfcaccjnaihajbh', -- Rest API Inspector; {<all_urls>,webRequest,webRequestBlocking,storage}
    'lnkdbjbjpnpjeciipoaflmpcddinpjjp', -- SmartVideo For YouTube™; {tabs}
    'lpcaedmchfhocbbapmcbpinfpgnhiddi', -- Google Keep Chrome Extension; {activeTab,identity,identity.email,contextMenus,file://*/*,http://*/,https://*/,storage,tabs,unlimitedStorage}
    'mfiddfehmfdojjfdpfngagldgaaafcfo', -- BrowserStack Local; {https://*.bsstag.com/*,https://*.browserstack.com/*,clipboardWrite,app.window,storage}
    'mihcahmgecmbnbcchbopgniflfhgnkff', -- Google Mail Checker; {alarms,tabs,webNavigation,*://*.google.com/}
    'mmimngoggfoobjdlefbcabngfnmieonb', -- Google Play Books; {clipboardWrite,unlimitedStorage}
    'moibopkbhjceeedibkbkbchbjnkadmom', -- retire.js; {<all_urls>,webRequest,tabs}
    'mpbbnannobiobpnfblimoapbephgifkm', -- Chrome RDP for Google Cloud Platform; {clipboardRead,clipboardWrite,unlimitedStorage,storage,notifications,overrideEscFullscreen}
    'mpnlkmlkncncpgnnkmkgoobfpnjmblnk', -- Norton Safe Search; {tabs,webRequest,webRequestBlocking,https://*.norton.com/*,storage}
    'naijndjklgmffmpembnkfbcjbognokbf', -- UET Tag Helper (by Microsoft Advertising); {activeTab,downloads,tabs,webNavigation,webRequest,http://*/,https://*/}
    'nbdmccoknlfggadpfkmcpnamfnbkmkcp', -- Cloud9; {clipboardRead,clipboardWrite}
    'nblmokgbialjjgfhfofbgfcghhbkejac', -- Cloud Vision; {clipboardWrite,contextMenus,notifications,file://*,<all_urls>}
    'nckgahadagoaajjgafhacjanaoiihapd', -- Google Hangouts; {alarms,background,cookies,idle,notifications,storage,system.display,tabs,*://*.google.com/*}
    'neebplgakaahbhdphmkckjjcegoiijjo', -- Keepa - Amazon Price Tracker; {storage,cookies,contextMenus,*://*.keepa.com/*,*://*.amazon.com/*,*://*.amzn.com/*,*://*.amazon.co.uk/*,*://*.amazon.de/*,*://*.amazon.fr/*,*://*.amazon.it/*,*://*.amazon.ca/*,*://*.amazon.com.mx/*,*://*.amazon.es/*,*://*.amazon.co.jp/*,*://*.amazon.in/*,*://*.amazon.com.br/*,*://*.amazon.nl/*,*://*.amazon.com.au/*}
    'nenlahapcbofgnanklpelkaejcehkggg', -- Capital One Shopping: Add to Chrome for Free; {tabs,contextMenus,storage,cookies,webRequest,webRequestBlocking,<all_urls>}
    'nfhdjopbhlggibjlimhdbogflgmbiahc', -- Better Pull Request for GitHub; {contextMenus,storage,*://*.github.com/*}
    'nhdogjmejiglipccpnnnanhbledajbpd', -- Vue.js devtools; {<all_urls>,storage}
    'niloccemoadcdkdjlinkgdfekeahmflj', -- Save to Pocket; {tabs,contextMenus,cookies,storage}
    'nkbihfbeogaeaoehlefnkodbefgpgknn', -- MetaMask; {storage,unlimitedStorage,clipboardWrite,http://localhost:8545/,https://*.infura.io/,https://chainid.network/chains.json,https://lattice.gridplus.io/*,activeTab,webRequest,*://*.eth/,notifications}
    'nlbjncdgjeocebhnmkbbbdekmmmcbfjd', -- RSS Subscription Extension (by Google); {tabs,http://*/*,https://*/*,storage}
    'nlgphodeccebbcnkgmokeegopgpnjfkc', -- Super Dark Mode; {storage,<all_urls>,contextMenus}
    'nmmhkkegccagdldgiimedpiccmgmieda', -- Chrome Web Store Payments; {identity,webview,https://www.google.com/,https://www.googleapis.com/*,https://payments.google.com/payments/v4/js/integrator.js,https://sandbox.google.com/payments/v4/js/integrator.js}
    'nngceckbapebfimnlniiiahkandclblb', -- Bitwarden - Free Password Manager; {tabs,contextMenus,storage,unlimitedStorage,clipboardRead,clipboardWrite,idle,http://*/*,https://*/*,webRequest,webRequestBlocking}
    'noondiphcddnnabmjcihcjfbhfklnnep', -- Password Alert; {identity,identity.email,notifications,storage,tabs,<all_urls>}
    'ohcpnigalekghcmgcdcenkpelffpdolg', -- ColorPick Eyedropper; {activeTab,tabs,<all_urls>,storage,alarms}
    'ojilllmhjhibplnppnamldakhpmdnibd', -- SSH for Google Cloud Platform; {clipboardRead,clipboardWrite}
    'pianggobfjcgeihlmfhfgkfalopndooo', -- coLaboratory Notebook; {identity,webview,unlimitedStorage,storage,clipboardRead,clipboardWrite}
    'pioclpoplcdbaefihamjohnefbikjilc', -- Evernote Web Clipper; {activeTab,tabs,cookies,contextMenus,<all_urls>,notifications}
    'pkehgijcmpdhfbdbbnkijodmdjhbjlgp', -- Privacy Badger; {tabs,http://*/*,https://*/*,webNavigation,webRequest,webRequestBlocking,storage,privacy}
    'pliibjocnfmkagafnbkfcimonlnlpghj', -- ClickUp: Tasks, Screenshots, Email, Time; {alarms,identity,storage,unlimitedStorage,tabs,activeTab,notifications,contextMenus,downloads,<all_urls>,http://*/*,https://*/*}
    'pmjeegjhjdlccodhacdgbgfagbpmccpe', -- Clockify Time Tracker; {background,contextMenus,storage,tabs,activeTab,identity,idle,notifications,scripting,alarms}
    'pnhechapfaindjhompbnflcldabbghjo' -- DEPRECATED Secure Shell App; {clipboardRead,clipboardWrite,idle,notifications,storage,terminalPrivate,unlimitedStorage,fileSystemProvider,accessibilityFeatures.read,crashReportPrivate,metricsPrivate}
 )
