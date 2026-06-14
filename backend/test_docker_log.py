#!/usr/bin/env python3
"""
Docker Desktop 로그 tee 기능 테스트
  - 단위 테스트: Docker 없이 로직 검증
  - 통합 테스트: Docker 사용 가능 시 실제 exec+tee 동작 확인
실행: cd backend && python test_docker_log.py
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

def test(name, cond, detail=""):
    mark = PASS if cond else FAIL
    print(f"  [{mark}] {name}" + (f"  ({detail})" if detail else ""))
    return cond

# ────────────────────────────────────────────────────────────────────────────
print("=" * 60)
print("  [1] 단위 테스트 — _build_log_header")
print("=" * 60)

from docker_mgr.docker_manager import _build_log_header

h1 = _build_log_header(1, "T1059.003", "환경 초기화", "uname -m")
test("헤더에 STEP 포함",      "STEP 1" in h1)
test("헤더에 MITRE 포함",     "T1059.003" in h1)
test("헤더에 제목 포함",      "환경 초기화" in h1)
test("헤더에 명령어 포함",    "uname -m" in h1)
test("헤더에 구분선 포함",    "===" in h1 or "═" in h1 or "=" * 10 in h1)

h2 = _build_log_header(0, "", "", "echo hello")
test("메타없는 헤더 명령어",  "echo hello" in h2)
test("메타없는 헤더 에러없음", True)

# 매우 긴 명령어는 120자로 잘림
long_cmd = "x" * 200
h3 = _build_log_header(2, "T1105", "다운로드", long_cmd)
cmd_line = [l for l in h3.split("\n") if "$ " in l][0]
test("긴 명령어 120자 truncate", len(cmd_line) <= 140,
     f"cmd_line len={len(cmd_line)}")

print()
print("=" * 60)
print("  [2] 단위 테스트 — DRY-RUN 경로 (Docker 없음)")
print("=" * 60)

from docker_mgr.docker_manager import exec_in_attacker

out = exec_in_attacker("nonexistent-lab", "echo test")
test("없는 랩 → DRY-RUN 반환",   out.startswith("[DRY-RUN]"), f"out={out!r}")
test("명령어 내용 포함",           "echo test" in out)

out2 = exec_in_attacker("nonexistent-lab", "echo test",
                         step_num=3, mitre="T1548", title="권한상승")
test("메타 파라미터 허용",         out2.startswith("[DRY-RUN]"), f"out2={out2!r}")

print()
print("=" * 60)
print("  [3] 단위 테스트 — sim_engine _exec_step lambda signature")
print("=" * 60)

import inspect, ast as _ast
path = os.path.join(os.path.dirname(__file__), "simulation", "sim_engine.py")
with open(path, encoding="utf-8") as f:
    src = f.read()

test("step_num 전달",  "step_num=step.step_number" in src)
test("mitre 전달",     'mitre=getattr(step, "mitre_technique"' in src)
test("title 전달",     'title=getattr(step, "title"' in src)
test("lambda 래핑",    "lambda:" in src and "exec_in_attacker" in src)
_ast.parse(src)
test("sim_engine.py 문법 OK", True)

print()
print("=" * 60)
print("  [4] 통합 테스트 — Docker 연결 및 실제 exec+tee")
print("=" * 60)

import subprocess
try:
    r = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
    docker_ok = r.returncode == 0
except Exception:
    docker_ok = False

if not docker_ok:
    print("  [SKIP] Docker Desktop 미실행 — 통합 테스트 건너뜀")
    print("         (Docker 실행 후 재실행하면 통합 테스트가 수행됩니다)")
else:
    print("  Docker 연결됨 — 경량 컨테이너로 tee 검증 시작...")
    try:
        import docker as _docker
        client = _docker.from_env()

        # ubuntu:22.04 로컬에 없으면 스킵
        try:
            client.images.get("ubuntu:22.04")
        except _docker.errors.ImageNotFound:
            print("  [SKIP] ubuntu:22.04 이미지 없음 — pull 후 재실행")
            sys.exit(0)

        # 테스트 컨테이너 시작
        cname = "malscript-test-tee"
        try:
            old = client.containers.get(cname)
            old.remove(force=True)
        except Exception:
            pass

        c = client.containers.run(
            "ubuntu:22.04", "sleep 30",
            detach=True, name=cname, remove=False,
        )
        import time; time.sleep(1)

        # _write_to_container_stdout 직접 호출
        from docker_mgr.docker_manager import _write_to_container_stdout, _build_log_header
        _write_to_container_stdout(c, "[TEST] tee header\n")

        # exec + tee
        wrapped = "( echo 'hello_tee_test' ) 2>&1 | tee /proc/1/fd/1 || true"
        res = c.exec_run(["sh", "-c", wrapped], stdout=True, stderr=True)
        out_bytes = res.output or b""
        out_str = out_bytes.decode("utf-8", errors="replace").strip()

        test("exec 출력 정상", "hello_tee_test" in out_str, f"out={out_str!r}")

        # Docker 컨테이너 로그에서 tee 기록 확인
        time.sleep(0.5)
        logs = c.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        test("컨테이너 로그에 헤더 기록",   "[TEST] tee header" in logs, f"logs[:200]={logs[:200]!r}")
        test("컨테이너 로그에 출력 기록",   "hello_tee_test" in logs)

        # 정리
        c.remove(force=True)
        print("  테스트 컨테이너 정리 완료")

    except Exception as ex:
        print(f"  [FAIL] 통합 테스트 예외: {type(ex).__name__}: {ex}")

print()
print("=" * 60)
print("  테스트 완료")
print("=" * 60)
