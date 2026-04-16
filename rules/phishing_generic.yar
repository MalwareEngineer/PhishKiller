/*
    Darla — Generic Phishing Kit Detection Rules
    These rules detect common patterns found across phishing kits regardless of family.
*/

rule PhishKit_Credential_Exfil_Email
{
    meta:
        description = "PHP mail() used to exfiltrate stolen credentials"
        author = "Darla"
        severity = "high"
        category = "exfiltration"

    strings:
        $mail1 = "mail(" ascii nocase
        $mail2 = "$to" ascii nocase
        $mail3 = "$subject" ascii nocase
        $cred1 = "$password" ascii nocase
        $cred2 = "$pass" ascii nocase
        $cred3 = "password" ascii nocase
        $post = "$_POST" ascii

    condition:
        $mail1 and $post and any of ($cred*) and any of ($mail2, $mail3)
}

rule PhishKit_Credential_Exfil_Telegram
{
    meta:
        description = "Telegram Bot API used for credential exfiltration"
        author = "Darla"
        severity = "high"
        category = "exfiltration"

    strings:
        $tg_api = "api.telegram.org/bot" ascii nocase
        $send   = "sendMessage" ascii
        $post   = "$_POST" ascii
        $chat   = "chat_id" ascii nocase

    condition:
        $tg_api and ($send or $chat) and $post
}

rule PhishKit_Credential_Exfil_Telegram_JS
{
    meta:
        description = "Telegram Bot API used for credential exfiltration via JavaScript"
        author = "Darla"
        severity = "high"
        category = "exfiltration"

    strings:
        $tg_api = "api.telegram.org/bot" ascii nocase
        $send   = "sendMessage" ascii
        $fetch1 = "fetch(" ascii
        $fetch2 = "XMLHttpRequest" ascii
        $fetch3 = "$.ajax" ascii
        $chat   = "chat_id" ascii nocase
        $pass   = "password" ascii nocase

    condition:
        $tg_api and ($chat or $send) and any of ($fetch*) and $pass
}

rule PhishKit_Credential_Exfil_SMTP
{
    meta:
        description = "SMTP used to exfiltrate stolen credentials"
        author = "Darla"
        severity = "high"
        category = "exfiltration"

    strings:
        $smtp1 = "smtp" ascii nocase
        $smtp2 = "PHPMailer" ascii nocase
        $smtp3 = "SMTP" ascii
        $host  = "smtp_host" ascii nocase
        $port  = /smtp.?port/i ascii
        $post  = "$_POST" ascii
        $cred  = "password" ascii nocase

    condition:
        any of ($smtp*) and ($host or $port) and $post and $cred
}

rule PhishKit_Login_Form
{
    meta:
        description = "HTML login form targeting credentials"
        author = "Darla"
        severity = "medium"
        category = "phishing_page"

    strings:
        $form    = "<form" ascii nocase
        $action  = "action=" ascii nocase
        $method  = "method=\"post\"" ascii nocase
        $input1  = "type=\"password\"" ascii nocase
        $input2  = "type=\"email\"" ascii nocase
        $input3  = "type=\"text\"" ascii nocase
        $label1  = /sign.?in/i ascii
        $label2  = /log.?in/i ascii
        $label3  = "verify" ascii nocase

    condition:
        $form and ($method or $action) and $input1 and any of ($input2, $input3) and any of ($label*)
}

rule PhishKit_Credential_Logger
{
    meta:
        description = "PHP script that logs credentials to a file"
        author = "Darla"
        severity = "high"
        category = "exfiltration"

    strings:
        $fopen  = "fopen(" ascii
        $fwrite = "fwrite(" ascii
        $post   = "$_POST" ascii
        $append = /[\"']a[+]?[\"']/ ascii
        $pass   = "password" ascii nocase

    condition:
        $fopen and $fwrite and $post and $pass and $append
}

rule PhishKit_Social_Engineering_Lure
{
    meta:
        description = "Common social engineering phrases in phishing pages"
        author = "Darla"
        severity = "low"
        category = "social_engineering"

    strings:
        $lure1 = "verify your account" ascii nocase
        $lure2 = "confirm your identity" ascii nocase
        $lure3 = "update your information" ascii nocase
        $lure4 = "unusual activity" ascii nocase
        $lure5 = "suspended" ascii nocase
        $lure6 = "unauthorized access" ascii nocase
        $lure7 = "security alert" ascii nocase
        $lure8 = "action required" ascii nocase

    condition:
        2 of them
}

rule PhishKit_QR_Code_Phishing
{
    meta:
        description = "QR code embedded in phishing page for credential harvesting"
        author = "Darla"
        severity = "high"
        category = "technique"

    strings:
        $qr1 = "qrcode" ascii nocase
        $qr2 = "QRCode" ascii
        $qr3 = "qr-code" ascii nocase
        $qr4 = "toDataURL" ascii
        $qr5 = "qrious" ascii nocase
        $qr6 = "data:image/png;base64" ascii nocase
        $scan = /scan.?this|scan.?the.?code|scan.?qr/i ascii
        $auth = "authenticat" ascii nocase
        $mfa  = /mfa|2fa|two.?factor|multi.?factor/i ascii

    condition:
        any of ($qr*) and ($scan or $auth or $mfa)
}

rule PhishKit_MFA_Phishing_Proxy
{
    meta:
        description = "Real-time MFA/2FA phishing proxy (EvilGinx-style)"
        author = "Darla"
        severity = "critical"
        category = "technique"

    strings:
        $proxy1 = "reverse proxy" ascii nocase
        $proxy2 = "evilginx" ascii nocase
        $proxy3 = "muraena" ascii nocase
        $proxy4 = "modlishka" ascii nocase
        $mfa1   = "2fa" ascii nocase
        $mfa2   = "mfa" ascii nocase
        $mfa3   = "otp" ascii nocase
        $mfa4   = "verification code" ascii nocase
        $sess   = "session" ascii nocase
        $cookie = "cookie" ascii nocase

    condition:
        any of ($proxy*) or (any of ($mfa*) and ($sess or $cookie) and any of ($proxy*))
}

rule PhishKit_Credential_Exfil_Discord
{
    meta:
        description = "Discord webhook used for credential exfiltration"
        author = "Darla"
        severity = "high"
        category = "exfiltration"

    strings:
        $hook1 = "discord.com/api/webhooks" ascii nocase
        $hook2 = "discordapp.com/api/webhooks" ascii nocase
        $pass  = "password" ascii nocase
        $fetch = "fetch(" ascii
        $post  = "POST" ascii

    condition:
        any of ($hook*) and $pass and ($fetch or $post)
}

rule PhishKit_Microsoft_Branded_Page
{
    meta:
        description = "Microsoft-branded phishing page with login form"
        author = "Darla"
        severity = "high"
        category = "brand_target"
        brand = "Microsoft"

    strings:
        $ms1 = "microsoft" ascii nocase
        $ms2 = "msft" ascii nocase
        $ms3 = "aadcdn.msftauth" ascii nocase
        $ms4 = "logincdn.msftauth" ascii nocase
        $ms5 = "Please wait" ascii nocase
        $logo1 = "microsoft-logo" ascii nocase
        $logo2 = "msft-logo" ascii nocase
        $form = "type=\"password\"" ascii nocase
        $email = "type=\"email\"" ascii nocase

    condition:
        (2 of ($ms*) or any of ($logo*)) and ($form or $email)
}

rule PhishKit_Redirect_Chain_Suspicious
{
    meta:
        description = "Suspicious redirect chain patterns common in phishing"
        author = "Darla"
        severity = "medium"
        category = "technique"

    strings:
        $redir1 = "window.location" ascii
        $redir2 = "location.href" ascii
        $redir3 = "location.replace" ascii
        $redir4 = "meta http-equiv=\"refresh\"" ascii nocase
        $redir5 = "header(\"Location:" ascii nocase
        $href   = "href.li" ascii nocase
        $b64    = "atob(" ascii
        $decode = "decodeURIComponent" ascii

    condition:
        2 of ($redir*) and ($b64 or $decode or $href)
}
