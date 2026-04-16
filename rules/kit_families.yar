/*
    Darla — Known Kit Family Detection Rules
    Signatures for identifying specific phishing kit builders and templates.
*/

rule PhishKit_16Shop
{
    meta:
        description = "16Shop phishing kit framework"
        author = "Darla"
        severity = "high"
        category = "kit_family"
        family = "16Shop"

    strings:
        $s1 = "16Shop" ascii nocase
        $s2 = "antibot.php" ascii
        $s3 = "blocker.php" ascii
        $s4 = ".antibot" ascii
        $s5 = "bot_and" ascii nocase

    condition:
        2 of them
}

rule PhishKit_KingPhisher
{
    meta:
        description = "King Phisher campaign toolkit markers"
        author = "Darla"
        severity = "high"
        category = "kit_family"
        family = "KingPhisher"

    strings:
        $s1 = "king phisher" ascii nocase
        $s2 = "kingphisher" ascii nocase
        $s3 = "campaign_id" ascii nocase
        $s4 = "message_id" ascii nocase

    condition:
        ($s1 or $s2) or ($s3 and $s4)
}

rule PhishKit_Chase_Template
{
    meta:
        description = "Chase bank phishing template"
        author = "Darla"
        severity = "high"
        category = "brand_target"
        brand = "Chase"

    strings:
        $brand1 = "chase.com" ascii nocase
        $brand2 = "Chase Bank" ascii nocase
        $brand3 = "JPMorgan Chase" ascii nocase
        $form   = "<form" ascii nocase
        $post   = "$_POST" ascii
        $ssn    = /ssn|social.?security/i ascii

    condition:
        any of ($brand*) and $form and ($post or $ssn)
}

rule PhishKit_Office365_Template
{
    meta:
        description = "Microsoft Office 365 phishing template"
        author = "Darla"
        severity = "high"
        category = "brand_target"
        brand = "Microsoft"

    strings:
        $brand1 = "office365" ascii nocase
        $brand2 = "Office 365" ascii nocase
        $brand3 = "outlook.com" ascii nocase
        $brand4 = "microsoftonline" ascii nocase
        $brand5 = "login.microsoft" ascii nocase
        $form   = "type=\"password\"" ascii nocase
        $post   = "method=\"post\"" ascii nocase

    condition:
        any of ($brand*) and $form and $post
}

rule PhishKit_PayPal_Template
{
    meta:
        description = "PayPal phishing template"
        author = "Darla"
        severity = "high"
        category = "brand_target"
        brand = "PayPal"

    strings:
        $brand1 = "paypal.com" ascii nocase
        $brand2 = "PayPal" ascii nocase
        $form   = "<form" ascii nocase
        $cc     = /credit.?card/i ascii
        $post   = "$_POST" ascii
        $ssn    = /ssn|social.?security|billing/i ascii

    condition:
        any of ($brand*) and $form and ($cc or $ssn or $post)
}

rule PhishKit_Apple_Template
{
    meta:
        description = "Apple ID / iCloud phishing template"
        author = "Darla"
        severity = "high"
        category = "brand_target"
        brand = "Apple"

    strings:
        $brand1 = "apple.com" ascii nocase
        $brand2 = "Apple ID" ascii nocase
        $brand3 = "icloud.com" ascii nocase
        $brand4 = "appleid" ascii nocase
        $form   = "type=\"password\"" ascii nocase
        $post   = "method=\"post\"" ascii nocase

    condition:
        any of ($brand*) and $form and $post
}

rule PhishKit_Google_Template
{
    meta:
        description = "Google/Gmail phishing template"
        author = "Darla"
        severity = "high"
        category = "brand_target"
        brand = "Google"

    strings:
        $brand1 = "accounts.google.com" ascii nocase
        $brand2 = "googleapis.com" ascii nocase
        $brand3 = "google-signin" ascii nocase
        $brand4 = "gstatic.com" ascii nocase
        $brand5 = "Sign in with Google" ascii nocase
        $form   = "type=\"password\"" ascii nocase
        $post   = "method=\"post\"" ascii nocase

    condition:
        2 of ($brand*) and $form and $post
}

rule PhishKit_LinkedIn_Template
{
    meta:
        description = "LinkedIn phishing template"
        author = "Darla"
        severity = "high"
        category = "brand_target"
        brand = "LinkedIn"

    strings:
        $brand1 = "linkedin.com" ascii nocase
        $brand2 = "LinkedIn" ascii nocase
        $brand3 = "licdn.com" ascii nocase
        $form   = "type=\"password\"" ascii nocase
        $post   = "method=\"post\"" ascii nocase

    condition:
        any of ($brand*) and $form and $post
}

rule PhishKit_Builder_Watermark
{
    meta:
        description = "Kit builder watermark or signature"
        author = "Darla"
        severity = "medium"
        category = "attribution"

    strings:
        $wm1 = /coded.?by\s*[:=]/i ascii
        $wm2 = /created.?by\s*[:=]/i ascii
        $wm3 = /author\s*[:=]\s*['"]/i ascii
        $wm4 = /developer\s*[:=]\s*['"]/i ascii
        $wm5 = /made.?by\s*[:=]/i ascii
        $wm6 = "scam page" ascii nocase
        $wm7 = "phishing" ascii nocase

    condition:
        any of ($wm1, $wm2, $wm3, $wm4, $wm5) and any of ($wm6, $wm7)
}

rule PhishKit_OAuth_Redirect_Phishing
{
    meta:
        description = "OAuth redirect-based credential phishing"
        author = "Darla"
        severity = "high"
        category = "technique"
        brand = "Microsoft"

    strings:
        $oauth1 = "oauth/authorize" ascii nocase
        $oauth2 = "client_id=" ascii nocase
        $oauth3 = "redirect_uri=" ascii nocase
        $oauth4 = "response_type=" ascii nocase
        $redir1 = "workers.dev" ascii nocase
        $redir2 = "pages.dev" ascii nocase
        $redir3 = "ngrok" ascii nocase
        $redir4 = "trycloudflare.com" ascii nocase
        $scope  = "openid" ascii nocase

    condition:
        2 of ($oauth*) and (any of ($redir*) or $scope)
}

rule PhishKit_Device_Code_Phishing
{
    meta:
        description = "Device code flow phishing (OAuth2 device auth abuse)"
        author = "Darla"
        severity = "critical"
        category = "technique"

    strings:
        $dc1 = "devicecode" ascii nocase
        $dc2 = "device_code" ascii nocase
        $dc3 = "user_code" ascii nocase
        $dc4 = "microsoft.com/devicelogin" ascii nocase
        $dc5 = "aka.ms/devicelogin" ascii nocase
        $dc6 = "verification_uri" ascii nocase
        $poll = "grant_type=urn:ietf:params:oauth:grant-type:device_code" ascii nocase

    condition:
        2 of them
}

rule PhishKit_Cloudflare_Workers_Hosted
{
    meta:
        description = "Phishing page hosted on Cloudflare Workers/Pages"
        author = "Darla"
        severity = "medium"
        category = "infrastructure"

    strings:
        $host1 = "workers.dev" ascii nocase
        $host2 = "pages.dev" ascii nocase
        $form  = "type=\"password\"" ascii nocase
        $post  = "method=\"post\"" ascii nocase
        $brand1 = "microsoft" ascii nocase
        $brand2 = "office" ascii nocase
        $brand3 = "outlook" ascii nocase
        $brand4 = "onedrive" ascii nocase
        $brand5 = "sharepoint" ascii nocase

    condition:
        any of ($host*) and ($form or $post) and any of ($brand*)
}
