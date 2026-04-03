rule SuspiciousStrings {
    meta:
        description = "Strings commonly found in malware"
        author = "ARGOS"
    strings:
        $s1 = "cmd.exe /c" nocase
        $s2 = "powershell -enc" nocase
        $s3 = "wget http" nocase
        $s4 = "curl http" nocase
        $s5 = "/bin/sh -i" nocase
        $s6 = "base64 -d" nocase
    condition:
        2 of them
}
rule WebShell {
    meta:
        description = "Common PHP/ASP web shell patterns"
    strings:
        $php1 = "eval(base64_decode" nocase
        $php2 = "system($_" nocase
        $php3 = "exec($_GET" nocase
        $asp1 = "Response.Write(Shell" nocase
    condition:
        any of them
}
