/*
    PhishKiller — Generic Phishing Kit Detection Rules
    These rules detect common patterns found across phishing kits regardless of family.
*/

rule PhishKit_Credential_Exfil_Email
{
    meta:
        description = "PHP mail() used to exfiltrate stolen credentials"
        author = "PhishKiller"
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
        $mail1 and $post and any of ($cred*)
}

rule PhishKit_Credential_Exfil_Telegram
{
    meta:
        description = "Telegram Bot API used for credential exfiltration"
        author = "PhishKiller"
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

rule PhishKit_Credential_Exfil_SMTP
{
    meta:
        description = "SMTP used to exfiltrate stolen credentials"
        author = "PhishKiller"
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
        author = "PhishKiller"
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
        $form and $method and $input1 and any of ($input2, $input3) and any of ($label*)
}

rule PhishKit_Credential_Logger
{
    meta:
        description = "PHP script that logs credentials to a file"
        author = "PhishKiller"
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
        author = "PhishKiller"
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
