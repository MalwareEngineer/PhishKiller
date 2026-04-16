/*
    Darla — AiTM PhaaS Kit Detection Rules
    Detect Adversary-in-the-Middle phishing-as-a-service patterns derived
    from avoutfitters/monexyit.cfd and himediagroup/northmiamifl-gov.com
    campaign analysis (2026-03).
*/

rule AiTM_Empty_Tag_String_Splitting
{
    meta:
        description = "Empty inline HTML tags used to split strings and defeat text extraction"
        author = "Darla"
        severity = "high"
        category = "evasion"
        mitre = "T1027"

    strings:
        $tag_b      = "<b></b>"      ascii nocase
        $tag_i      = "<i></i>"      ascii nocase
        $tag_em     = "<em></em>"    ascii nocase
        $tag_strong = "<strong></strong>" ascii nocase
        $tag_span   = "<span></span>" ascii nocase
        $tag_u      = "<u></u>"      ascii nocase
        $tag_s      = "<s></s>"      ascii nocase
        $tag_small  = "<small></small>" ascii nocase

    condition:
        #tag_b > 10 or #tag_i > 10 or #tag_em > 10 or #tag_strong > 10 or
        #tag_span > 10 or #tag_u > 10 or #tag_s > 10 or #tag_small > 10
}

rule AiTM_PageValidator_BotDetection
{
    meta:
        description = "PageValidator anti-headless browser detection framework"
        author = "Darla"
        severity = "high"
        category = "evasion"

    strings:
        $pv_create = "PageValidator.create" ascii
        $pv_base   = "PageValidator" ascii
        $strict    = "strict" ascii
        $webdriver = "navigator.webdriver" ascii
        $headless  = "headless" ascii nocase

    condition:
        $pv_create or ($pv_base and 2 of ($strict, $webdriver, $headless))
}

rule AiTM_Randomized_CSS_Variables
{
    meta:
        description = "Randomized CSS class names and JS variable suffixes typical of PhaaS kits"
        author = "Darla"
        severity = "medium"
        category = "evasion"

    strings:
        $css_container = /a_container_\d{2,4}/ ascii
        $css_block     = /a_block_\d{2,4}/ ascii
        $js_context    = /var_context_\d{2,4}/ ascii

    condition:
        2 of them
}

rule AiTM_Honeypot_Fields
{
    meta:
        description = "Off-screen honeypot input fields with sys_ prefix used to trap bots"
        author = "Darla"
        severity = "high"
        category = "evasion"

    strings:
        $sys_field  = /name\s*=\s*["']sys_\d{3,5}["']/ ascii nocase
        $offscreen1 = "left:-9999px" ascii nocase
        $offscreen2 = "left: -9999px" ascii nocase
        $offscreen3 = "position:absolute" ascii nocase
        $offscreen4 = "position: absolute" ascii nocase
        $opacity    = "opacity:0" ascii nocase
        $overflow   = "overflow:hidden" ascii nocase

    condition:
        $sys_field and any of ($offscreen*, $opacity, $overflow)
}

rule AiTM_Relay_Proxy_Indicators
{
    meta:
        description = "AiTM relay proxying real Microsoft/Google authentication endpoints"
        author = "Darla"
        severity = "critical"
        category = "technique"
        mitre = "T1557"

    strings:
        $auth1 = "login.microsoftonline.com" ascii nocase
        $auth2 = "login.microsoft.com" ascii nocase
        $auth3 = "accounts.google.com" ascii nocase
        $auth4 = "login.live.com" ascii nocase
        $auth5 = "login.windows.net" ascii nocase
        $auth6 = "sts.windows.net" ascii nocase
        $auth7 = "aadcdn.msauth.net" ascii nocase
        $auth8 = "aadcdn.msftauth.net" ascii nocase

        $fetch1 = "fetch(" ascii
        $fetch2 = "XMLHttpRequest" ascii
        $fetch3 = "$.ajax" ascii
        $fetch4 = "$.post" ascii
        $fetch5 = ".submit(" ascii

        $cred1 = "password" ascii nocase
        $cred2 = "credential" ascii nocase
        $cred3 = "ESTSAUTH" ascii
        $cred4 = "$Config" ascii
        $cred5 = "ConvergedSignIn" ascii

    condition:
        2 of ($auth*) and (any of ($fetch*) or any of ($cred*))
}

rule AiTM_Credential_Exfil_REST
{
    meta:
        description = "REST API credential exfiltration with CORS preflight pattern"
        author = "Darla"
        severity = "high"
        category = "exfiltration"

    strings:
        $endpoint1 = "/restore" ascii
        $endpoint2 = "/collect" ascii
        $endpoint3 = "/receive" ascii
        $endpoint4 = "/gate" ascii
        $endpoint5 = "/submit" ascii

        $cors1 = "Access-Control-Allow-Origin" ascii
        $cors2 = "Access-Control-Allow-Methods" ascii
        $cors3 = "OPTIONS" ascii

        $cred1 = "password" ascii nocase
        $cred2 = "credential" ascii nocase
        $cred3 = "token" ascii nocase
        $cred4 = "session" ascii nocase

    condition:
        any of ($endpoint*) and any of ($cors*) and any of ($cred*)
}

rule AiTM_PhaaS_URL_Parameters
{
    meta:
        description = "PhaaS kit URL parameter fingerprint scheme (session/ray/geo/jst/ver)"
        author = "Darla"
        severity = "medium"
        category = "kit_family"

    strings:
        $param_session = /[?&]session=[0-9a-f]{16,40}/ ascii nocase
        $param_ray     = /[?&]ray=[0-9a-f]{12,32}/ ascii nocase
        $param_geo     = /[?&]geo=[A-Z]{2}/ ascii
        $param_jst     = /[?&]jst=[0-9a-f]{16,40}/ ascii nocase
        $param_ver     = /[?&]ver=\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii

    condition:
        4 of them
}

rule AiTM_Mousemove_Gated_DOM
{
    meta:
        description = "Mousemove event listener gates DOM element injection for bot detection"
        author = "Darla"
        severity = "high"
        category = "evasion"

    strings:
        $mousemove = /addEventListener\s*\(\s*["']mousemove["']/ ascii
        $create    = "createElement" ascii
        $append1   = "appendChild" ascii
        $append2   = "append(" ascii
        $class1    = "className" ascii
        $class2    = "classList" ascii
        $class3    = "setAttribute" ascii

    condition:
        $mousemove and ($create or any of ($append*)) and any of ($class*)
}
