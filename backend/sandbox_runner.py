"""
sandbox_runner.py — Windows Sandbox 기반 격리 셸 실행기

아키텍처:
  1. 공유 폴더(temp/sandbox_shared/{session_id}/) 생성
  2. PowerShell "셸 데몬" 스크립트를 공유 폴더에 배치
  3. .wsb 설정 파일로 Windows Sandbox 실행
     - 공유 폴더를 Sandbox 내 C:\shared\ 에 마운트
     - 네트워크 비활성화 (격리)
     - 데몬 스크립트를 LogonCommand로 실행
  4. 명령 전송: input/cmd_{n}.txt 파일 작성
  5. 결과 수집: output/out_{n}.txt 폴링
  6. 세션 종료: sandbox_exit.txt 파일 작성 → 데몬 자동 종료
"""

from __future__ import annotations
import asyncio
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import AsyncGenerator

# ── 상수 ────────────────────────────────────────────────────────
SANDBOX_EXE = r"C:\Windows\System32\WindowsSandbox.exe"
SHARED_ROOT  = Path(os.environ.get("TEMP", "C:/Temp")) / "malscript_sandbox"
POLL_INTERVAL = 0.15    # 초
CMD_TIMEOUT   = 30.0    # 명령 1개당 최대 대기 (초)
STARTUP_TIMEOUT = 120.0 # Sandbox 부팅 대기 (초) — 첫 부팅은 60~90초 소요

# PowerShell 셸 데몬 스크립트 (Sandbox 내부에서 실행됨)
DAEMON_PS1 = r"""
$base   = "C:\shared"
$inDir  = "$base\input"
$outDir = "$base\output"
New-Item -ItemType Directory -Force -Path $inDir, $outDir | Out-Null

# 준비 완료 신호
"ready" | Out-File "$base\daemon_ready.txt" -Encoding UTF8

$counter = 0
while ($true) {
    # 종료 신호 확인
    if (Test-Path "$base\sandbox_exit.txt") {
        "exited" | Out-File "$base\daemon_done.txt" -Encoding UTF8
        break
    }

    $cmdFile = "$inDir\cmd_$counter.txt"
    if (Test-Path $cmdFile) {
        $cmd = Get-Content $cmdFile -Raw -Encoding UTF8
        try {
            # PowerShell 명령 실행, stdout+stderr 모두 캡처
            $result = Invoke-Expression $cmd 2>&1 | Out-String
            if (-not $result) { $result = "(출력 없음)" }
        } catch {
            $result = "ERROR: $_"
        }
        $result | Out-File "$outDir\out_$counter.txt" -Encoding UTF8
        $counter++
    }
    Start-Sleep -Milliseconds 100
}
"""


class SandboxSession:
    """
    Windows Sandbox 세션 하나를 관리합니다.
    WebSocket 핸들러에서 하나의 session_id에 대해 인스턴스 생성.
    """

    def __init__(self, session_id: str | None = None, networking: bool = False):
        self.session_id = session_id or str(uuid.uuid4())[:12]
        self.networking = networking
        self.base_dir   = SHARED_ROOT / self.session_id
        self.input_dir  = self.base_dir / "input"
        self.output_dir = self.base_dir / "output"
        self._cmd_counter = 0
        self._process: subprocess.Popen | None = None
        self._ready = False

    # ── 내부 파일 경로 헬퍼 ─────────────────────────────────────
    def _sandbox_path(self, rel: str) -> str:
        """Host 절대경로 → Sandbox 내부 C:\shared\ 경로 (string)"""
        return r"C:\shared" + "\\" + rel

    # ── 세션 시작 ───────────────────────────────────────────────
    async def start(
        self,
        status_callback: "asyncio.Coroutine | None" = None,
        extra_timeout: float = 0.0,
    ) -> bool:
        """
        Windows Sandbox를 시작합니다.
        status_callback: async callable(message: str) — 진행 상태 메시지 전달용
        반환값: True = 정상 시작, False = 실패 (Sandbox 미설치 등)
        """
        if not Path(SANDBOX_EXE).exists():
            return False

        # ── 이미 부팅 중이었던 Sandbox 체크 (재연결 시) ────────────────
        ready_file = self.base_dir / "daemon_ready.txt"
        if self._process is not None and self._process is not False and ready_file.exists():
            self._ready = True
            return True

        # 공유 디렉터리 생성
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.input_dir.mkdir(exist_ok=True)
        self.output_dir.mkdir(exist_ok=True)

        # 데몬 스크립트 저장
        daemon_file = self.base_dir / "daemon.ps1"
        daemon_file.write_text(DAEMON_PS1, encoding="utf-8")

        # .wsb 설정 파일 생성
        net = "Enable" if self.networking else "Disable"
        wsb = f"""<Configuration>
  <Networking>{net}</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{self.base_dir}</HostFolder>
      <SandboxFolder>C:\\shared</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell -NoProfile -ExecutionPolicy Bypass -File C:\\shared\\daemon.ps1</Command>
  </LogonCommand>
</Configuration>"""
        wsb_file = self.base_dir / "session.wsb"
        wsb_file.write_text(wsb, encoding="utf-8")

        # ── 관리자 권한 + HV 서비스 확인 후 Sandbox 실행 ───────────
        # WindowsSandbox.exe 는 VM 컨테이너를 생성한 뒤 부모 프로세스가 종료되는
        # 정상 동작이므로 PassThru 추적 없이 fire-and-forget 으로 실행합니다.
        ps_check = (
            "$isAdmin = ([Security.Principal.WindowsPrincipal]"
            " [Security.Principal.WindowsIdentity]::GetCurrent())"
            ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);"
            "if (-not $isAdmin) { Write-Output 'NOT_ADMIN'; exit }"
            " $hvSvc = (Get-Service HvHost -ErrorAction SilentlyContinue).Status;"
            " if ($hvSvc -ne 'Running') { Write-Output \"HV_STOPPED:$hvSvc\"; exit }"
            " Write-Output 'OK'"
        )
        check_stdout = ""
        check_error  = ""
        try:
            chk = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_check],
                capture_output=True, text=True, timeout=10,
            )
            check_stdout = (chk.stdout or "").strip()
            check_error  = (chk.stderr or "").strip()
        except Exception as e:
            check_error = str(e)

        if "NOT_ADMIN" in check_stdout:
            if status_callback:
                try:
                    await status_callback(
                        "❌ 서버가 관리자 권한으로 실행되지 않았습니다.\n\n"
                        "Windows Sandbox는 Hyper-V 접근에 관리자 권한이 필요합니다.\n"
                        "start.bat을 우클릭 → '관리자 권한으로 실행' 후 다시 시도하세요."
                    )
                except Exception:
                    pass
            return False

        if "HV_STOPPED" in check_stdout:
            svc_status = check_stdout.replace("HV_STOPPED:", "")
            if status_callback:
                try:
                    await status_callback(
                        f"❌ Hyper-V Host Service가 중지되어 있습니다 (상태: {svc_status}).\n\n"
                        "services.msc → 'HV Host Service' → 시작 으로 해결하거나\n"
                        "관리자 PowerShell에서: Start-Service HvHost"
                    )
                except Exception:
                    pass
            return False

        # Sandbox 실행 (fire-and-forget — 부모 프로세스 종료가 정상)
        launch_error = ""
        try:
            subprocess.Popen(
                [SANDBOX_EXE, str(wsb_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        except Exception as e:
            launch_error = str(e)
            # 폴백: PowerShell Start-Process
            try:
                subprocess.Popen(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     f'Start-Process -FilePath "{SANDBOX_EXE}" -ArgumentList \'"{wsb_file}"\''],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                launch_error = ""
            except Exception as e2:
                launch_error += f" | PS fallback: {e2}"

        self._process = True  # 시작 시도됨 마커

        if status_callback:
            try:
                await status_callback("✅ Windows Sandbox 실행 명령 전달됨, 부팅 대기 중...")
            except Exception:
                pass

        # 데몬 준비 신호 대기 (최대 STARTUP_TIMEOUT 초)
        ready_file = self.base_dir / "daemon_ready.txt"
        elapsed_start = time.monotonic()
        next_report   = 10.0  # 10초마다 진행 상태 알림

        while time.monotonic() - elapsed_start < STARTUP_TIMEOUT:
            if ready_file.exists():
                self._ready = True
                return True

            elapsed = time.monotonic() - elapsed_start
            if status_callback and elapsed >= next_report:
                remaining = int(STARTUP_TIMEOUT - elapsed)
                try:
                    await status_callback(
                        f"⏳ Windows Sandbox 부팅 중... ({elapsed:.0f}초 경과, 최대 {remaining}초 남음)"
                    )
                except Exception:
                    pass
                next_report += 10.0

            await asyncio.sleep(0.5)

        return False  # 타임아웃

    # ── 명령 실행 ───────────────────────────────────────────────
    async def run_command(self, command: str) -> str:
        """
        단일 명령을 Sandbox 내부에서 실행하고 결과를 반환합니다.
        """
        if not self._ready:
            return "ERROR: Sandbox가 아직 준비되지 않았습니다."

        n = self._cmd_counter
        self._cmd_counter += 1

        # 명령 파일 작성
        cmd_file = self.input_dir / f"cmd_{n}.txt"
        cmd_file.write_text(command, encoding="utf-8")

        # 결과 파일 폴링
        out_file = self.output_dir / f"out_{n}.txt"
        start = time.monotonic()
        while time.monotonic() - start < CMD_TIMEOUT:
            if out_file.exists():
                result = out_file.read_text(encoding="utf-8", errors="replace")
                return result.rstrip()
            await asyncio.sleep(POLL_INTERVAL)

        return f"ERROR: 명령 타임아웃 ({CMD_TIMEOUT:.0f}초)"

    # ── 스트리밍 실행 (WebSocket용) ─────────────────────────────
    async def run_command_stream(self, command: str) -> AsyncGenerator[str, None]:
        """
        명령을 실행하고 결과를 청크 단위로 yield합니다.
        실제로는 완료 후 한 번에 반환되지만, 대기 중 도트를 주기적으로 yield합니다.
        """
        if not self._ready:
            yield "ERROR: Sandbox가 아직 준비되지 않았습니다.\r\n"
            return

        n = self._cmd_counter
        self._cmd_counter += 1
        cmd_file = self.input_dir / f"cmd_{n}.txt"
        cmd_file.write_text(command, encoding="utf-8")

        out_file = self.output_dir / f"out_{n}.txt"
        start = time.monotonic()
        dot_time = start

        while time.monotonic() - start < CMD_TIMEOUT:
            if out_file.exists():
                result = out_file.read_text(encoding="utf-8", errors="replace")
                yield result.rstrip() + "\r\n"
                return
            # 2초마다 "처리 중" 도트 출력
            if time.monotonic() - dot_time > 2.0:
                yield ""  # keepalive (빈 문자열)
                dot_time = time.monotonic()
            await asyncio.sleep(POLL_INTERVAL)

        yield f"ERROR: 명령 타임아웃 ({CMD_TIMEOUT:.0f}초)\r\n"

    # ── 세션 종료 ───────────────────────────────────────────────
    async def stop(self):
        """Sandbox를 종료합니다."""
        exit_file = self.base_dir / "sandbox_exit.txt"
        exit_file.write_text("exit", encoding="utf-8")
        await asyncio.sleep(1.0)
        if self._process and hasattr(self._process, "poll") and self._process.poll() is None:
            try:
                self._process.terminate()
            except Exception:
                pass

    # ── 상태 확인 ───────────────────────────────────────────────
    @property
    def is_ready(self) -> bool:
        return self._ready

    @staticmethod
    def is_available() -> bool:
        """Windows Sandbox가 설치/활성화되어 있으면 True"""
        return Path(SANDBOX_EXE).exists()


# ── 전역 세션 레지스트리 (lab_id → SandboxSession) ──────────────
_sessions: dict[str, SandboxSession] = {}


def get_or_create_session(lab_id: str, networking: bool = False) -> SandboxSession:
    if lab_id not in _sessions:
        _sessions[lab_id] = SandboxSession(session_id=lab_id, networking=networking)
    return _sessions[lab_id]


def remove_session(lab_id: str):
    _sessions.pop(lab_id, None)


# ── CLI 테스트 ───────────────────────────────────────────────────
if __name__ == "__main__":
    if not SandboxSession.is_available():
        print("Windows Sandbox가 설치되어 있지 않거나 비활성화 상태입니다.")
        print("관리자 PowerShell에서 실행:")
        print("  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All")
        sys.exit(1)

    async def _test():
        print("[+] Sandbox 세션 시작 중...")
        session = SandboxSession()
        ok = await session.start()
        if not ok:
            print("[-] Sandbox 시작 실패 (타임아웃)")
            return
        print("[+] Sandbox 준비 완료!")

        cmds = [
            "whoami",
            "systeminfo | Select-String 'OS'",
            "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name,CPU",
        ]
        for cmd in cmds:
            print(f"\nPS> {cmd}")
            result = await session.run_command(cmd)
            print(result)

        await session.stop()
        print("\n[+] 세션 종료됨")

    asyncio.run(_test())
