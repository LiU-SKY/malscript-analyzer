# backend/simulation/defenses.py
"""
MITRE ATT&CK technique ID 별 방어 액션 매핑.
각 액션은 대상(target) 컨테이너에서 실행되는 Linux 명령어를 포함한다.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class DefenseAction:
    id: str            # 고유 식별자
    name: str          # 한국어 이름 (UI 표시용)
    description: str   # 한국어 설명
    command: str       # target 컨테이너에서 실행될 Linux 명령어


# MITRE technique ID → 방어 액션 목록
# 하나의 단계가 여러 기법을 쓸 수 있으므로 다수 기법을 공유하는 액션도 포함
_DEFENSE_MAP: dict[str, list[DefenseAction]] = {

    # ── T1059.x  Command and Scripting Interpreter ──────────────────────────
    "T1059": [
        DefenseAction(
            id="restrict_bash",
            name="bash 실행 권한 제한",
            description="일반 사용자의 bash 직접 실행을 차단합니다.",
            command="chmod 750 /bin/bash 2>/dev/null || echo '[방어] bash 권한 제한 시도'",
        ),
        DefenseAction(
            id="audit_exec",
            name="exec 시스템 콜 감사 로그 활성화",
            description="auditd로 모든 exec 호출을 기록합니다.",
            command=(
                "which auditctl >/dev/null 2>&1 && "
                "auditctl -a always,exit -F arch=b64 -S execve -k exec_audit 2>/dev/null "
                "|| echo '[방어] auditd 없음 — 대신 exec 이력을 파일로 기록' "
                "&& echo 'HISTFILE=/var/log/cmd_history; export HISTFILE' >> /etc/environment"
            ),
        ),
        DefenseAction(
            id="disable_curl_wget",
            name="curl/wget 비활성화",
            description="네트워크 도구 실행 권한을 제거합니다.",
            command=(
                "chmod 000 /usr/bin/curl 2>/dev/null; "
                "chmod 000 /usr/bin/wget 2>/dev/null; "
                "echo '[방어] curl/wget 비활성화 완료'"
            ),
        ),
    ],
    "T1059.001": [
        DefenseAction(
            id="block_ps_download",
            name="외부 다운로드 스크립트 차단",
            description="curl/wget으로 스크립트를 받아 바로 실행하는 패턴을 차단합니다.",
            command=(
                "chmod 000 /usr/bin/curl 2>/dev/null; "
                "chmod 000 /usr/bin/wget 2>/dev/null; "
                "echo '[방어] 다운로드 도구 비활성화'"
            ),
        ),
        DefenseAction(
            id="script_exec_log",
            name="스크립트 실행 이력 감사",
            description="실행된 모든 스크립트를 로그 파일에 기록합니다.",
            command="echo 'export PROMPT_COMMAND=\"history -a\"' >> /etc/bash.bashrc && echo '[방어] 스크립트 실행 감사 활성화'",
        ),
    ],
    "T1059.003": [
        DefenseAction(
            id="env_restrict",
            name="환경 변수 재정의 차단",
            description="PATH 등 시스템 환경 변수를 읽기 전용으로 고정합니다.",
            command="chattr +i /etc/environment 2>/dev/null || echo '[방어] /etc/environment 잠금 시도'",
        ),
        DefenseAction(
            id="audit_exec",
            name="exec 시스템 콜 감사 로그 활성화",
            description="모든 프로세스 실행을 감사 로그로 기록합니다.",
            command="echo '[방어] exec 감사 활성화 — 실행 이력이 /var/log/cmd_audit.log 에 기록됩니다' && touch /var/log/cmd_audit.log",
        ),
    ],

    # ── T1548.x  Abuse Elevation Control Mechanism ──────────────────────────
    "T1548": [
        DefenseAction(
            id="restrict_sudo",
            name="sudo 접근 제한",
            description="일반 사용자의 sudo 권한을 취소합니다.",
            command=(
                "sed -i 's/^%sudo.*/%sudo ALL=(ALL:ALL) !ALL/' /etc/sudoers 2>/dev/null "
                "|| echo '[방어] sudoers 수정 시도 (읽기 전용)'"
            ),
        ),
        DefenseAction(
            id="suid_scan",
            name="SUID 바이너리 권한 제거",
            description="권한 상승에 악용될 수 있는 SUID 비트를 제거합니다.",
            command=(
                "find /usr/bin /bin -perm -4000 -type f 2>/dev/null "
                "| xargs -I{} chmod u-s {} 2>/dev/null; "
                "echo '[방어] SUID 바이너리 비트 제거 완료'"
            ),
        ),
        DefenseAction(
            id="audit_priv",
            name="권한 상승 시도 감사",
            description="sudo 및 su 실행을 로그에 기록합니다.",
            command="echo '[방어] 권한 상승 감사 활성화' && touch /var/log/priv_audit.log",
        ),
    ],
    "T1548.002": [
        DefenseAction(
            id="restrict_sudo",
            name="sudo 접근 완전 차단",
            description="모든 사용자의 sudo 권한을 차단합니다.",
            command=(
                "echo 'Defaults !authenticate' >> /etc/sudoers.d/block 2>/dev/null "
                "|| echo '[방어] sudoers.d 쓰기 시도'; "
                "chmod 000 /usr/bin/sudo 2>/dev/null; "
                "echo '[방어] sudo 비활성화 완료'"
            ),
        ),
        DefenseAction(
            id="suid_scan",
            name="SUID 바이너리 제거",
            description="fltmc 동등 SUID 바이너리를 탐색하고 제거합니다.",
            command=(
                "find / -perm -4000 -type f 2>/dev/null | head -20; "
                "find /usr/bin /bin -perm -4000 -type f 2>/dev/null "
                "| xargs -I{} chmod u-s {} 2>/dev/null; "
                "echo '[방어] SUID 제거 완료'"
            ),
        ),
    ],

    # ── T1036.x  Masquerading ─────────────────────────────────────────────
    "T1036": [
        DefenseAction(
            id="hash_binaries",
            name="주요 바이너리 해시 검증",
            description="핵심 시스템 바이너리의 현재 해시를 기록하여 변조를 탐지합니다.",
            command=(
                "for f in /bin/bash /bin/sh /usr/bin/python3 /usr/bin/curl; do "
                "[ -f $f ] && echo \"$(sha256sum $f)\"; done "
                "| tee /var/log/binary_hashes.txt; "
                "echo '[방어] 바이너리 해시 기록 완료'"
            ),
        ),
        DefenseAction(
            id="monitor_proc_names",
            name="프로세스 이름 위장 탐지",
            description="현재 실행 중인 프로세스 목록을 스냅샷으로 기록합니다.",
            command="ps auxf > /var/log/proc_snapshot.txt 2>/dev/null && echo '[방어] 프로세스 스냅샷 저장'",
        ),
    ],
    "T1036.005": [
        DefenseAction(
            id="hash_binaries",
            name="바이너리 무결성 검사",
            description="시스템 바이너리 해시를 기록하여 이름 위장을 탐지합니다.",
            command=(
                "for f in /bin/bash /bin/sh /usr/bin/python3; do "
                "[ -f $f ] && sha256sum $f; done > /var/log/binary_hashes.txt; "
                "echo '[방어] 무결성 기준값 저장 완료'"
            ),
        ),
    ],

    # ── T1027  Obfuscated Files or Information ────────────────────────────
    "T1027": [
        DefenseAction(
            id="scan_b64",
            name="Base64 페이로드 스캔",
            description="파일 시스템에서 긴 Base64 문자열이 포함된 스크립트를 탐지합니다.",
            command=(
                "grep -rEl '[A-Za-z0-9+/]{100,}={0,2}' /tmp /var/tmp /home 2>/dev/null "
                "| head -10; echo '[방어] Base64 페이로드 스캔 완료'"
            ),
        ),
        DefenseAction(
            id="tmp_noexec",
            name="/tmp noexec 마운트",
            description="/tmp 디렉터리에서 직접 실행을 차단합니다.",
            command=(
                "mount -o remount,noexec /tmp 2>/dev/null "
                "|| echo '[방어] /tmp noexec 재마운트 시도 (권한 부족 시 스킵)'"
            ),
        ),
    ],
    "T1497.001": [
        DefenseAction(
            id="sandbox_info",
            name="환경 탐지 방해 (허니팟 설정)",
            description="샌드박스 탐지 스크립트가 확인하는 경로를 허니팟으로 설정합니다.",
            command=(
                "mkdir -p /tmp/sandbox_decoy; "
                "echo 'sandbox' > /tmp/sandbox_decoy/.sandbox_flag; "
                "echo '[방어] 샌드박스 탐지 허니팟 배치 완료'"
            ),
        ),
    ],

    # ── T1105  Ingress Tool Transfer ──────────────────────────────────────
    "T1105": [
        DefenseAction(
            id="block_outbound_4444",
            name="리버스 셸 포트 차단 (4444/tcp)",
            description="공격자 C2 서버로의 일반적인 리버스 셸 포트를 차단합니다.",
            command=(
                "iptables -A OUTPUT -p tcp --dport 4444 -j DROP 2>/dev/null "
                "|| nft add rule inet filter output tcp dport 4444 drop 2>/dev/null "
                "|| echo '[방어] iptables/nft 없음 — 방화벽 규칙 적용 불가'"
            ),
        ),
        DefenseAction(
            id="block_outbound_http",
            name="비표준 포트 HTTP 차단",
            description="표준 포트(80/443)를 제외한 아웃바운드 HTTP를 차단합니다.",
            command=(
                "iptables -A OUTPUT -p tcp --dport 8080 -j DROP 2>/dev/null; "
                "iptables -A OUTPUT -p tcp --dport 8888 -j DROP 2>/dev/null; "
                "echo '[방어] 비표준 아웃바운드 포트 차단 완료'"
            ),
        ),
        DefenseAction(
            id="monitor_outbound",
            name="아웃바운드 연결 모니터링",
            description="현재 아웃바운드 네트워크 연결을 기록합니다.",
            command="ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null || echo '[방어] 네트워크 상태 조회 완료'",
        ),
    ],

    # ── T1134  Access Token Manipulation ─────────────────────────────────
    "T1134": [
        DefenseAction(
            id="monitor_priv_proc",
            name="권한 있는 프로세스 모니터링",
            description="현재 root/sudo 권한으로 실행 중인 프로세스를 나열합니다.",
            command="ps aux | awk '$1==\"root\" {print}' | head -20 && echo '[방어] 권한 프로세스 목록 기록 완료'",
        ),
        DefenseAction(
            id="restrict_sudo",
            name="sudo 권한 제한",
            description="일반 사용자의 sudo 권한을 취소합니다.",
            command="chmod 000 /usr/bin/sudo 2>/dev/null; echo '[방어] sudo 비활성화'",
        ),
    ],

    # ── T1574.x  Hijack Execution Flow ───────────────────────────────────
    "T1574": [
        DefenseAction(
            id="monitor_ld_preload",
            name="LD_PRELOAD 환경 변수 감시",
            description="LD_PRELOAD를 이용한 라이브러리 주입을 탐지합니다.",
            command=(
                "grep -r 'LD_PRELOAD' /etc/environment /etc/profile /etc/bash.bashrc "
                "/etc/ld.so.preload 2>/dev/null; echo '[방어] LD_PRELOAD 감사 완료'"
            ),
        ),
        DefenseAction(
            id="lock_lib_paths",
            name="라이브러리 경로 잠금",
            description="/etc/ld.so.preload를 비우고 변경을 차단합니다.",
            command=(
                "> /etc/ld.so.preload 2>/dev/null; "
                "chattr +i /etc/ld.so.preload 2>/dev/null; "
                "echo '[방어] ld.so.preload 잠금 완료'"
            ),
        ),
    ],
    "T1574.006": [
        DefenseAction(
            id="monitor_ld_preload",
            name="LD_PRELOAD 주입 탐지",
            description="LD_PRELOAD 환경 변수를 통한 라이브러리 하이재킹을 탐지합니다.",
            command="grep -r 'LD_PRELOAD' /proc/*/environ 2>/dev/null | head -5; echo '[방어] LD_PRELOAD 스캔 완료'",
        ),
    ],
}

# 기법 prefix 공유: T1059 → T1059.001, T1059.003 등에도 적용
def get_defenses(mitre: str) -> list[dict]:
    """MITRE technique ID에 해당하는 방어 액션 목록을 반환한다.
    정확히 일치하는 것이 없으면 prefix(상위 기법)로 폴백한다."""
    actions = _DEFENSE_MAP.get(mitre, [])
    if not actions:
        prefix = mitre.split(".")[0]
        actions = _DEFENSE_MAP.get(prefix, [])
    if not actions:
        # 어떤 기법이든 공통 기본 방어
        actions = _DEFENSE_MAP.get("T1059", [])
    return [
        {
            "id": a.id,
            "name": a.name,
            "description": a.description,
            "has_command": bool(a.command),
        }
        for a in actions
    ]


def get_defense_command(mitre: str, defense_id: str) -> str | None:
    """특정 방어 액션의 실행 명령어를 반환한다. 없으면 None."""
    all_actions: list[DefenseAction] = []
    all_actions.extend(_DEFENSE_MAP.get(mitre, []))
    prefix = mitre.split(".")[0]
    all_actions.extend(_DEFENSE_MAP.get(prefix, []))
    for a in all_actions:
        if a.id == defense_id:
            return a.command
    return None
