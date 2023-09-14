-- Highlight chrome extensions with wide-ranging permissions that are not part of your whitelist
--
-- references:
--   * https://attack.mitre.org/techniques/T1176/ (Browser Extensions)
--
-- false positives:
--   * Almost unlimited: any extension that isn't on your whitelist
--
-- tags: persistent seldom browser
SELECT
  name,
  profile,
  chrome_extensions.description AS 'descr',
  persistent AS persists,
  author,
  chrome_extensions.path,
  referenced AS in_config,
  file.ctime,
  file.btime,
  file.mtime,
  from_webstore AS in_store,
  TRIM(CAST(permissions AS text)) AS perms,
  state AS 'enabled',
  CONCAT (
    from_webstore,
    ',',
    author,
    ',',
    name,
    ',',
    identifier
  ) AS exception_key,
  hash.sha256
FROM
  users
  CROSS JOIN chrome_extensions USING (uid)
  LEFT JOIN file ON chrome_extensions.path = file.path
  LEFT JOIN hash ON chrome_extensions.path = hash.path
WHERE
  state = 1
  AND (
    (
      from_webstore != 'true'
      AND (
        perms LIKE "%nativeMessaging%"
        OR perms LIKE '%bookmarks%'
        OR perms LIKE "%pageCapture%"
        OR perms LIKE "%session%" -- Sigstore
        OR perms LIKE "%http%"
        OR perms LIKE "%webRequest%"
      )
    )
    OR (
      perms LIKE '%://*/%'
      OR perms LIKE '%<all_urls>%'
      OR perms LIKE '%clipboardRead%'
      OR perms LIKE '%cookies%'
      OR perms LIKE '%coinbase%'
      OR perms LIKE '%blockchain%'
      OR perms LIKE '%debugger%'
      OR perms LIKE '%declarativeNetRequestFeedback%'
      OR perms LIKE '%desktopCapture%'
      OR perms LIKE '%github.com%'
      OR perms LIKE '%google.com%'
      OR perms LIKE "%history%"
      OR perms LIKE "%nativeMessaging%"
      OR perms LIKE "%proxy%"
      OR perms LIKE "%webAuthenticationProxy%"
      OR perms LIKE "%management%"
    )
  )
  AND NOT exception_key IN (
    'true,,Acorns Earn,facncfnojagdpibmijfjdmhkklabakgd',
    'true,Adaware,Safe Torrent Scanner,aegnopegbbhjeeiganiajffnalhlkkjb',
    'true,,Adblock for Youtube™,cmedhionkhpnakcndndgjdbohmhepckk',
    'true,Adblock, Inc.,AdBlock — best ad blocker,gighmmpiobklfepjocnamgkkbiglidom',
    'true,,Add to Amazon Wish List,ciagpekplgpbepdgggflgmahnjgiaced',
    'true,,Adobe Acrobat: PDF edit, convert, sign tools,efaidnbmnnnibpcajpcglclefindmkaj',
    'true,AgileBits,1Password extension (desktop app required),aomjjhallfgjeglblehebfpbcfeobpgk',
    'true,AgileBits,1Password – Password Manager,aeblfdkhhhdcdjpifhhbdiojplfjncoa',
    'true,Alexander Shutau,Dark Reader,eimadpbcbfnmbkopoojfekhnkhdbieeh',
    'true,All uBlock contributors,uBlock - free ad blocker,epcnnfbjfcgphgdmggkamkmgojdagdnn',
    'true,,Application Launcher For Drive (by Google),lmjegmlicamnimmfhcmpkclmigmmcbeh',
    'true,,axe DevTools - Web Accessibility Testing,lhdoppojpmngadmnindnejefpokejbdd',
    'true,,Bardeen - automate manual work,ihhkmalpkhkoedlmcnilbbhhbhnicjga',
    'true,,Bardeen - automate workflows with one click,ihhkmalpkhkoedlmcnilbbhhbhnicjga',
    'true,Benjamin Hollis,JSONView,gmegofmjomhknnokphhckolhcffdaihd',
    'true,BetaFish,AdBlock — best ad blocker,gighmmpiobklfepjocnamgkkbiglidom',
    'true,,Bionic Reading,kdfkejelgkdjgfoolngegkhkiecmlflj',
    'true,Bitwarden Inc.,Bitwarden - Free Password Manager,nngceckbapebfimnlniiiahkandclblb',
    'true,,BlockSite: Block Websites & Stay Focused,eiimnmioipafcokbfikbljfdeojpcgbh',
    'true,,BrowserStack Local,mfiddfehmfdojjfdpfngagldgaaafcfo',
    'true,CAD Team,Cookie AutoDelete,fhcgjolkccmbidfldomjliifgaodjagh',
    'true,,Canvas Blocker - Fingerprint Protect,nomnklagbgmgghhjidfhnoelnjfndfpd',
    'true,,Capital One Shopping: Add to Chrome for Free,nenlahapcbofgnanklpelkaejcehkggg',
    'true,,Caret,fljalecfjciodhpcledpamjachpmelml',
    'true,,Chrome Capture - Gif & Screenshot tool,ggaabchcecdbomdcnbahdfddfikjmphe',
    'true,chromeos-recovery-tool-admin@google.com,Chromebook Recovery Utility,jndclpdbaamdhonoechobihbbiimdgai',
    'true,,Chrome RDP for Google Cloud Platform,mpbbnannobiobpnfblimoapbephgifkm',
    'true,,Chrome Remote Desktop,inomeogfingihgjfjlpeplalcfajhgai',
    'true,,Chrome Web Store Payments,nmmhkkegccagdldgiimedpiccmgmieda',
    'true,,Cisco Webex Extension,jlhmfgmfgeifomenelglieieghnjghma',
    'true,,Clear Cache,cppjkneekbjaeellbfkmgnhonkkjfpdn',
    'true,,ClickUp: Tasks, Screenshots, Email, Time,pliibjocnfmkagafnbkfcimonlnlpghj',
    'true,,Clockify Time Tracker,pmjeegjhjdlccodhacdgbgfagbpmccpe',
    'true,Clockwise Inc.,Clockwise: AI Calendar & Scheduling Assistant,hjcneejoopafkkibfbcaeoldpjjiamog',
    'true,Clockwise Inc.,Clockwise: Team Time & Calendar Management,hjcneejoopafkkibfbcaeoldpjjiamog',
    'true,,Cloud9,nbdmccoknlfggadpfkmcpnamfnbkmkcp',
    'true,,Cloud Vision,nblmokgbialjjgfhfofbgfcghhbkejac',
    'true,,coLaboratory Notebook,pianggobfjcgeihlmfhfgkfalopndooo',
    'true,,ColorPick Eyedropper,ohcpnigalekghcmgcdcenkpelffpdolg',
    'true,,Copper CRM for Gmail,hpfmedbkgaakgagknibnonpkimkibkla',
    'true,,Copper CRM for Gmail™,hpfmedbkgaakgagknibnonpkimkibkla',
    'true,,crouton integration,gcpneefbbnfalgjniomfjknbcgkbijom',
    'true,Crowdcast, Inc.,Crowdcast Screensharing,kgmadhplahebfoiijgloflhakfjlkbpb',
    'true,,Crunchbase - B2B Company & Contact Info,mdfjplgeknamfodpoghbmhhlcjoacnbp',
    'true,,CSS Scan,gieabiemggnpnminflinemaickipbebg',
    "true,Daniel Kladnik @ kiboke studio,I don't care about cookies,fihnjjcciajhdojfnbdddfaoknhalnja",
    'true,,Datanyze Chrome Extension,mlholfadgbpidekmhdibonbjhdmpmafd',
    'true,,DealFinder by VoucherCodes,jhgicjdnnonfaedodemjjinbgcoeiajo',
    'true,,DEPRECATED Secure Shell App,pnhechapfaindjhompbnflcldabbghjo',
    'true,,Disconnect,jeoacafpbcihiomhlakheieifhpjdfeo',
    'true,,Distill Web Monitor,inlikjemeeknofckkjolnjbpehgadgge',
    'true,,DuckDuckGo Privacy Essentials,bkdgflcldnnnapblkhphbgpggdiikppg',
    'true,,EditThisCookie,fngmhnnpilhplaeedifhccceomclgfbg',
    'true,,Endpoint Verification,callobklhcbilhphinckomhgkigmfocg',
    'true,,Eno® from Capital One®,clmkdohmabikagpnhjmgacbclihgmdje',
    'true,,Espruino Web IDE,bleoifhkdalbjfbobjackfdifdneehpo',
    'true,,Event Merge for Google Calendar™,idehaflielbgpaokehlhidbjlehlfcep',
    'true,Evernote,Evernote Web Clipper,pioclpoplcdbaefihamjohnefbikjilc',
    'true,ExpressVPN,ExpressVPN: VPN proxy for a better internet,fgddmllnllkalaagkghckoinaemmogpe',
    'true,eyeo GmbH,Adblock Plus - free ad blocker,cfhdojbkjhnklbpkdaibdccddilifddb',
    'true,,Facebook Pixel Helper,fdgfkebogiimcoedlicjlajpkdmockpc',
    'true,Federico Brigante,GitHub Issue Link Status,nbiddhncecgemgccalnoanpnenalmkic',
    'true,,FoxyProxy Basic,dookpfaalaaappcdneeahomimbllocnb',
    'true,,Free Maps Ruler,ejpahoknghmacibohhgleeacndkglgmo',
    "true,Gareth Stephenson,My O'Reilly Downloader,deebiaolijlopiocielojiipnpnaldlk",
    'true,Ghostery,Ghostery – Privacy Ad Blocker,mlomiejdfkolichcflejclcbmpeaniij',
    'true,,Github Absolute Dates,iepecohjelcmdnahbddleblfphbaheno',
    'true,,GitHub Red Alert,kmiekjkmkbhbnlempjkaombjjcfhdnfe',
    'true,,Google Analytics Parameter Stripper,jbgedkkfkohoehhkknnmlodlobbhafge',
    'true,,Google Docs Offline,ghbmnnjooekpmoecnnnilnnbdlolhkhi',
    'true,,Google Drive,apdfllckaahabafndbhieahigkjlhalf',
    'true,,Google Hangouts,nckgahadagoaajjgafhacjanaoiihapd',
    'true,,Google Keep Chrome Extension,lpcaedmchfhocbbapmcbpinfpgnhiddi',
    'true,,Google Keep - Notes and Lists,hmjkmjkepdijhoojdojkdfohbdgmmhki',
    'true,,Google Mail Checker,mihcahmgecmbnbcchbopgniflfhgnkff',
    'true,,Google Optimize,bhdplaindhdkiflmbfbciehdccfhegci',
    'true,,Google Play Books,mmimngoggfoobjdlefbcabngfnmieonb',
    'true,,Grammarly: Grammar Checker and AI Writing App,kbfnbcaeplbcioakkpcpgfkobkghlhen',
    'true,,Grammarly: Grammar Checker and Writing App,kbfnbcaeplbcioakkpcpgfkobkghlhen',
    'true,,Gravit Designer,pdagghjnpkeagmlbilmjmclfhjeaapaa',
    'true,,GSConnect,jfnifeihccihocjbfcfhicmmgpjicaec',
    'true,Guilherme Nascimento,Prevent Duplicate Tabs,eednccpckdkpojaiemedoejdngappaag',
    'true,,Honey: Automatic Coupons & Cash Back,bmnlcjabgnpnenekpadlanbbkooimhnj',
    'true,,Honey: Automatic Coupons & Rewards,bmnlcjabgnpnenekpadlanbbkooimhnj',
    'true,,HTTPS Everywhere,gcbommkclmclpchllfjekcdonpmejbdp',
    'true,https://metamask.io,MetaMask,nkbihfbeogaeaoehlefnkodbefgpgknn',
    'true,,HubSpot Sales,oiiaigjnkhngdbnoookogelabohpglmd',
    'true,,IBA Opt-out (by Google),gbiekjoijknlhijdjbaadobpkdhmoebb',
    'true,,iCloud Bookmarks,fkepacicchenbjecpbpbclokcabebhah',
    'true,,Instapaper,ldjkgaaoikpmhmkelcgkgacicjfbofhh',
    'true,James Anderson,LeechBlock NG,blaaajhemilngeeffpbfkdjjoefldkok',
    'true,,Jamstash,jccdpflnecheidefpofmlblgebobbloc',
    'true,,Jitsi Meetings,kglhbbefdnlheedjiejgomgmfplipfeb',
    'true,,JSON Formatter,bcjindcccaagfpapjjmafapmmgkkhgoa',
    'true,,JSON Viewer Pro,eifflpmocdbdmepbjaopkkhbfmdgijcc',
    'true,Kas Elvirov,GitHub Gloc,kaodcnpebhdbpaeeemkiobcokcnegdki',
    'true,Keepa GmbH,Keepa - Amazon Price Tracker,neebplgakaahbhdphmkckjjcegoiijjo',
    'true,LastPass,LastPass: Free Password Manager,hdokiejnpimakedhajhdlcegeplioahd',
    'true,Leadjet,Leadjet - Make your CRM work on LinkedIn,kojhcdejfimplnokhhhekhiapceggamn',
    'true,,Link to Text Fragment,pbcodcjpfjdpcineamnnmbkkmkdpajjg',
    'true,,Lolli: Earn Bitcoin When You Shop,fleenceagaplaefnklabikkmocalkcpo',
    'true,,Loom – Free Screen Recorder & Screen Capture,liecbddmkiiihnedobmlmillhodjkdmb',
    'true,,Loom – Screen Recorder & Screen Capture,liecbddmkiiihnedobmlmillhodjkdmb',
    'true,,Lucidchart Diagrams,apboafhkiegglekeafbckfjldecefkhn',
    'true,,Markdown Preview Plus,febilkbfcbhebfnokafefeacimjdckgl',
    'true,Marker.io,Marker.io: Visual bug reporting for websites,jofhoojcehdmaiibilpcoofpdbbddkkl',
    'true,,Meta Pixel Helper,fdgfkebogiimcoedlicjlajpkdmockpc',
    'true,Microsoft Corporation,Microsoft 365,ndjpnladcallmjemlbaebfadecfhkepb',
    'true,NortonLifeLock Inc,Norton Safe Web,fnpbeacklnhmkkilekogeiekaglbmmka',
    'true,,NoScript,doojmbjmlfjjnbmnoijecmcbfeoakpjm',
    'true,,Notion Web Clipper,knheggckgoiihginacbkhaalnibhilkk',
    'true,,Office Editing for Docs, Sheets & Slides,gbkeegbaiigmenfmjfclcdgdpimamgkj',
    'true,,Office - Enable Copy and Paste,ifbmcpbgkhlpfcodhjhdbllhiaomkdej',
    'true,,Okta Browser Plugin,glnpjglilkicbckjpbgcfkogebgllemb',
    'true,,OneLogin for Google Chrome,ioalpmibngobedobkmbhgmadaphocjdn',
    'true,,OneTab,chphlpgkkbolifaimnlloiipkdnihall',
    'true,Opera Norway AS,Opera AI Prompts,mljbnbeedpkgakdchcmfapkjhfcogaoc',
    'true,Opera Software AS,Rich Hints Agent,enegjkbbakeegngfapepobipndnebkdk',
    'true,,Outbrain Pixel Tracker,daebadnaphbiobojnpgcenlkgpihmbdc',
    'true,,Outreach Everywhere,chmpifjjfpeodjljjadlobceoiflhdid',
    'true,,Page Analytics (by Google),fnbdnhhicmebfgdgglcdacdapkcihcoh',
    'true,,Password Alert,noondiphcddnnabmjcihcjfbhfklnnep',
    'true,Pawel Psztyc,Advanced REST client,hgmloofddffdnphfgcellkdfbfbjeloo',
    'true,,Picture-in-Picture Extension (by Google),hkgfoiooedgoejojocmhlaklaeopbecg',
    'true,,Playback Rate,jgmkoefgnppfpagkhifpialkkkgnfgag',
    'true,,PlayTo for Chromecast™,jngkenaoceimiimeokpdbmejeonaaami',
    'true,,Postman,fhbjgbiflinjbdggehcddcbncdddomop',
    'true,,Privacy Badger,pkehgijcmpdhfbdbbnkijodmdjhbjlgp',
    'true,,Private Internet Access,jplnlifepflhkbkgonidnobkakhmpnmh',
    'true,Pushbullet,Pushbullet,chlffgpmiacpedhhbkiomidkjlcfhogd',
    'true,,QuillBot for Chrome,iidnbdjijdkbmajdffnidomddglmieko',
    'true,Rakuten,Rakuten: Get Cash Back For Shopping,chhjbpecpncaggjpdakmflnfcopglcmi',
    'true,Raymond Hill & contributors,uBlock Origin,cjpalhdlnbpafiamejdnhcphjbkeiagm',
    'true,,React Developer Tools,fmkadmapgofadopljbjfkapdkoienihi',
    'true,,Reader Mode,llimhhconnjiflfimocjggfjdlmlhblm',
    'true,,Readwise Highlighter,jjhefcfhmnkfeepcpnilbbkaadhngkbi',
    'true,Reddit Enhancement Suite contributors,Reddit Enhancement Suite,kbmfpngjjgdllneeigpgjifpgocmfgmb',
    'true,,Refined GitHub,hlepfoohegkhhmjieoechaddaejaokhf',
    'true,,RetailMeNot Deal Finder™️,jjfblogammkiefalfpafidabbnamoknm',
    'true,,RSS Subscription Extension (by Google),nlbjncdgjeocebhnmkbbbdekmmmcbfjd',
    'true,,Save to Google Drive,gmbmikajjgmnabiglmofipeabaddhgne',
    'true,,Save to Pocket,niloccemoadcdkdjlinkgdfekeahmflj',
    'true,,Scraper,poegfpiagjgnenagjphgdklmgcpjaofi',
    'true,,Secure Shell,iodihamcpbpeioajjeobimgagajmlibd',
    'true,,Selenium IDE,mooikfkahbdckldjjndioackbalphokd',
    'true,,Send from Gmail (by Google),pgphcomnlaojlmmcjmiddhdapjpbgeoc',
    'true,,Sendspark Video and Screen Recorder,blimjkpadkhcpmkeboeknjcmiaogbkph',
    'true,,Send to Kindle for Google Chrome™,cgdjpilhipecahhcilnafpblkieebhea',
    'true,,Session Buddy,edacconmaakjimmfgnblocblbcdcpbko',
    'true,,Set Character Encoding,bpojelgakakmcfmjfilgdlmhefphglae',
    'true,,Shodan,jjalcfnidlmpjhdfepjhjbhnhkbgleap',
    'true,,Simple Tab Sorter,cgfpgnepljlgenjclbekbjdlgcodfmjp',
    'true,,Skype Calling,blakpkgjpemejpbmfiglncklihnhjkij',
    'true,,Slack,jeogkiiogjbmhklcnbgkdcjoioegiknm',
    'true,,SSH for Google Cloud Platform,ojilllmhjhibplnppnamldakhpmdnibd',
    'true,stefanXO,Tab Manager Plus for Chrome,cnkdjjdmfiffagllbiiilooaoofcoeff',
    'true,,Super Dark Mode,nlgphodeccebbcnkgmokeegopgpnjfkc',
    'true,,Superhuman,dcgcnpooblobhncpnddnhoendgbnglpn',
    'true,,Tabli,igeehkedfibbnhbfponhjjplpkeomghi',
    'true,,Tab Wrangler,egnjhciaieeiiohknchakcodbpgjnchh',
    'true,,Tag Assistant Legacy (by Google),kejbdjndbnbjgmefkgdddjlbokphdefk',
    'true,,Tampermonkey BETA,gcalenpjmijncebpfijmoaglllgpjagf',
    'true,Team Octotree,Octotree - GitHub code tree,bkhaagjahfmjljalopjnoealnfndnagc',
    'true,Thomas Rientjes,Decentraleyes,ldpochfccmkkmhdbclfhpagapcfdljkj',
    'true,,TickTick - Todo & Task List,diankknpkndanachmlckaikddgcehkod',
    'true,,Todoist for Chrome,jldhpllghnbhlbpcmnajkpdmadaolakh',
    'true,Tomas Popela, tpopela@redhat.com,Fedora User Agent,hojggiaghnldpcknpbciehjcaoafceil',
    'true,Tulio Ornelas <ornelas.tulio@gmail.com>,JSON Viewer,gbmdgpbipfallnflgajpaliibnhdgobh',
    'true,,Ubiquiti Device Discovery Tool,hmpigflbjeapnknladcfphgkemopofig',
    'true,,uBlock,epcnnfbjfcgphgdmggkamkmgojdagdnn',
    'true,,UET Tag Helper (by Microsoft Advertising),naijndjklgmffmpembnkfbcjbognokbf',
    'true,,Universal Video Downloader,cogmkaeijeflocngklepoknelfjpdjng',
    'true,,User-Agent Switcher for Chrome,djflhoibgkdhkhhcedjiklpkjnoahfmg',
    'true,,Utime,kpcibgnngaaabebmcabmkocdokepdaki',
    'true,,VidyoWebConnector,mmedphfiemffkinodeemalghecnicmnh',
    'true,,Vimcal,akopimcimmdmklcmegcflfidpfegngke',
    'true,Vimeo,Vimeo Record - Screen & Webcam Recorder,ejfmffkmeigkphomnpabpdabfddeadcb',
    'true,,Vimium,dbepggeogbaibhgnhhndojpepiihcmeb',
    'true,,Vue.js devtools,nhdogjmejiglipccpnnnanhbledajbpd',
    'true,Wappalyzer,Wappalyzer - Technology profiler,gppongmhjkpfnbhagpmjfkannfbllamg',
    'true,,WAVE Evaluation Tool,jbbplnpkjmmeebjpijfedlgcdilocofh',
    'true,,Wikiwand: Wikipedia Modernized,emffkefkbkpkgpdeeooapgaicgmcbolj',
    'true,,Windscribe - Free Proxy and Ad Blocker,hnmpcagpplmpfojmgmnngilcnanddlhb',
    'true,,Wisdolia,ciknpklcipibmfbgjmdmfdfalklfdlne',
    'true,,WiseStamp email signature,pbcgnkmbeodkmiijjfnliicelkjfcldg',
    'true,,writeGPT - ChatGPT Prompt Engineer Assistant,dflcdbibjghipieemcligeelbmackgco',
    'true,,Yesware Sales Engagement,gkjnkapjmjfpipfcccnjbjcbgdnahpjp',
    'true,Yuri Konotopov <ykonotopov@gnome.org>,GNOME Shell integration,gphhapmejobijbbhgpjhcjognlahblep',
    'true,,Zoom,hmbjbjdpkobdjplfobhljndfdfdipjhg',
    'true,,ZoomInfo Engage Chrome Extension,mnbjlpbmllanehlpbgilmbjgocpmcijp',
    'true,,Zoom Scheduler,kgjfgplpablkjnlkjmjdecgdpfankdle'
  )
  AND NOT (
    exception_key = 'false,AgileBits,1Password – Password Manager,dppgmdbiimibapkepcbdbmkaabgiofem'
    AND chrome_extensions.path LIKE '%/Microsoft Edge/%'
  )
GROUP BY
  exception_key
