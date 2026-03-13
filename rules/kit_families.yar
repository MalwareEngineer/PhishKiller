/*
    PhishKiller — Known Kit Family Detection Rules
    Signatures for identifying specific phishing kit builders and templates.
*/

rule PhishKit_16Shop
{
    meta:
        description = "16Shop phishing kit framework"
        author = "PhishKiller"
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
        author = "PhishKiller"
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
        author = "PhishKiller"
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
        author = "PhishKiller"
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
        author = "PhishKiller"
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
        author = "PhishKiller"
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

rule PhishKit_Builder_Watermark
{
    meta:
        description = "Kit builder watermark or signature"
        author = "PhishKiller"
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
