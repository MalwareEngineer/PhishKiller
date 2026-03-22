/*
    PhishKiller — Evasion Technique Detection Rules
    Detect anti-analysis and anti-bot techniques used by phishing kits.
*/

rule PhishKit_Antibot_Htaccess
{
    meta:
        description = ".htaccess rules blocking security bots and crawlers"
        author = "PhishKiller"
        severity = "medium"
        category = "evasion"

    strings:
        $rewrite = "RewriteEngine" ascii nocase
        $ua1 = "googlebot" ascii nocase
        $ua2 = "bingbot" ascii nocase
        $ua3 = "crawler" ascii nocase
        $ua4 = "spider" ascii nocase
        $ua5 = "phishtank" ascii nocase
        $ua6 = "netcraft" ascii nocase
        $deny = "deny from" ascii nocase
        $block = "403" ascii

    condition:
        $rewrite and (2 of ($ua*) or ($deny and $block))
}

rule PhishKit_Antibot_PHP
{
    meta:
        description = "PHP-based bot detection and blocking"
        author = "PhishKiller"
        severity = "medium"
        category = "evasion"

    strings:
        $ua_check  = "HTTP_USER_AGENT" ascii
        $bot1      = "googlebot" ascii nocase
        $bot2      = "bingbot" ascii nocase
        $bot3      = "crawler" ascii nocase
        $bot4      = "spider" ascii nocase
        $bot5      = "curl" ascii nocase
        $bot6      = "wget" ascii nocase
        $block1    = "die(" ascii
        $block2    = "exit(" ascii
        $block3    = "header(\"Location" ascii
        $block4    = "403" ascii

    condition:
        $ua_check and 2 of ($bot*) and any of ($block*)
}

rule PhishKit_Antibot_JavaScript
{
    meta:
        description = "JavaScript-based bot/automation detection"
        author = "PhishKiller"
        severity = "low"
        category = "evasion"

    strings:
        $s1 = "navigator.webdriver" ascii
        $s2 = "window._phantom" ascii
        $s3 = "window.callPhantom" ascii
        $s4 = "__selenium_unwrapped" ascii
        $s5 = "document.documentElement.getAttribute" ascii
        $s6 = "ChromeDriverw" ascii

    condition:
        2 of them
}

rule PhishKit_PHP_Obfuscation_Eval
{
    meta:
        description = "PHP eval/assert obfuscation wrappers"
        author = "PhishKiller"
        severity = "medium"
        category = "evasion"

    strings:
        $eval1 = /eval\s*\(\s*base64_decode\s*\(/ ascii nocase
        $eval2 = /eval\s*\(\s*gzinflate\s*\(/ ascii nocase
        $eval3 = /eval\s*\(\s*gzuncompress\s*\(/ ascii nocase
        $eval4 = /eval\s*\(\s*str_rot13\s*\(/ ascii nocase
        $eval5 = /assert\s*\(\s*base64_decode\s*\(/ ascii nocase
        $eval6 = /preg_replace\s*\(\s*['"]\/.*\/e['"]/ ascii

    condition:
        any of them
}

rule PhishKit_PHP_Obfuscation_Hex
{
    meta:
        description = "PHP hex-encoded string obfuscation"
        author = "PhishKiller"
        severity = "medium"
        category = "evasion"

    strings:
        $hex_concat = /\$\w+\s*=\s*"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){5,}"/i ascii
        $chr_concat = /chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)/ ascii

    condition:
        any of them
}

rule PhishKit_IP_Blocking
{
    meta:
        description = "IP-based visitor blocking (security companies, VPNs)"
        author = "PhishKiller"
        severity = "medium"
        category = "evasion"

    strings:
        $remote = "REMOTE_ADDR" ascii
        $block1 = "blocked" ascii nocase
        $block2 = "blacklist" ascii nocase
        $block3 = "banned" ascii nocase
        $api1   = "ip-api.com" ascii nocase
        $api2   = "ipinfo.io" ascii nocase
        $api3   = "geoip" ascii nocase

    condition:
        $remote and (any of ($block*) or any of ($api*))
}

rule PhishKit_Double_Login
{
    meta:
        description = "Double-login technique to capture credentials twice"
        author = "PhishKiller"
        severity = "high"
        category = "technique"

    strings:
        $session = "$_SESSION" ascii
        $post    = "$_POST" ascii
        $step1   = /step.?1|first.?login|login.?1/i ascii
        $step2   = /step.?2|second.?login|login.?2/i ascii
        $wrong   = /wrong|incorrect|invalid|try.?again/i ascii

    condition:
        $session and $post and ($step1 or $step2) and $wrong
}

rule PhishKit_Cloudflare_Turnstile_Gate
{
    meta:
        description = "Cloudflare Turnstile CAPTCHA used as anti-analysis gate"
        author = "PhishKiller"
        severity = "medium"
        category = "evasion"

    strings:
        $turnstile1 = "challenges.cloudflare.com/turnstile" ascii nocase
        $turnstile2 = "cf-turnstile" ascii nocase
        $turnstile3 = "turnstile.render" ascii nocase
        $sitekey    = /sitekey.*0x4[A-Za-z0-9]{22}/ ascii
        $callback   = "callback" ascii nocase

    condition:
        2 of ($turnstile*) or ($sitekey and $callback)
}

rule PhishKit_FingerprintJS_Tracking
{
    meta:
        description = "FingerprintJS used for visitor fingerprinting in phishing"
        author = "PhishKiller"
        severity = "medium"
        category = "evasion"

    strings:
        $fp1 = "fingerprintjs" ascii nocase
        $fp2 = "FingerprintJS" ascii
        $fp3 = "fpjs" ascii nocase
        $fp4 = "getVisitorId" ascii
        $fp5 = "visitorId" ascii
        $canvas = "canvas" ascii nocase
        $webgl  = "webgl" ascii nocase

    condition:
        any of ($fp*) and ($canvas or $webgl)
}

rule PhishKit_AntiVM_Detection
{
    meta:
        description = "Browser-side VM/sandbox detection in phishing page"
        author = "PhishKiller"
        severity = "high"
        category = "evasion"

    strings:
        $vm1 = "SwiftShader" ascii
        $vm2 = "VirtualBox" ascii
        $vm3 = "VMware" ascii
        $vm4 = "ANGLE" ascii
        $hw1 = "hardwareConcurrency" ascii
        $hw2 = "deviceMemory" ascii
        $webgl = "WEBGL_debug_renderer_info" ascii
        $score = /sandbox.?score|risk.?score|vm.?score/i ascii

    condition:
        (any of ($vm*) and any of ($hw*)) or ($webgl and $score)
}

rule PhishKit_AntiDevTools
{
    meta:
        description = "Anti-DevTools detection techniques in phishing page"
        author = "PhishKiller"
        severity = "medium"
        category = "evasion"

    strings:
        $dbg1 = "debugger" ascii
        $dbg2 = /outerWidth.*innerWidth/i ascii
        $dbg3 = /outerHeight.*innerHeight/i ascii
        $key1 = "F12" ascii
        $key2 = "Ctrl+Shift+I" ascii nocase
        $key3 = "keydown" ascii
        $ctx  = "contextmenu" ascii
        $prev = "preventDefault" ascii

    condition:
        ($dbg1 and any of ($dbg2, $dbg3)) or (any of ($key*) and $ctx and $prev)
}

rule PhishKit_WASM_Obfuscation
{
    meta:
        description = "WebAssembly module used for obfuscation in phishing page"
        author = "PhishKiller"
        severity = "high"
        category = "evasion"

    strings:
        $wasm1 = "WebAssembly" ascii
        $wasm2 = "AGFzbQ" ascii
        $wasm3 = "wasm" ascii nocase
        $inst  = "instantiate" ascii
        $mem   = "WebAssembly.Memory" ascii

    condition:
        ($wasm1 and ($inst or $mem)) or ($wasm2 and ($wasm1 or $wasm3))
}
