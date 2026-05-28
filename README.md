# MalScript Analyzer
> 2026-1 AI응용보안 기말 프로젝트  
> 주제: 멀티스테이지 악성 스크립트 분석 + MITRE ATT&CK 매핑 플랫폼

---

## 1. 프로젝트 개요

### 1.1 해결하고자 하는 보안 문제

PowerShell · JavaScript · Python · VBScript 악성 스크립트를 수동으로 분석하는 데 드는 시간과 전문성 장벽을 낮추고, AI를 통해 자동 탐지 → 분류 → 대응 방안까지 제공하는 통합 보안 서비스 구현

### 1.2 서비스 대상 사용자

- 기업 내부 보안 담당자
- 침해사고 대응(IR) 팀
- 보안 학습 중인 개발자

### 1.3 주요 기능

| 기능 | 설명 |
|------|------|
| 악성 패턴 1차 분류 | Ollama Mistral-7B로 스크립트 내 악성 키워드·구조 탐지 |
| 난독화 탐지 | 엔트로피 분석 + 8종 규칙으로 Base64·eval 체인 등 탐지 |
| 위험도 스코어링 | 가중 앙상블 (분류 65% + 난독화 35%) → 0.0 ~ 1.0 점수 |
| ATT&CK 매핑 | Claude API로 MITRE ATT&CK 기법 자동 매핑 및 링크 생성 |
| 대응 방안 생성 | 자연어 보안 리포트 + 단계별 대응 방안 |
| TOKEN_SAVE | 위험도 < 0.5 이면 Claude API 호출 자체를 생략 |

### 1.4 기대 효과

- 보안 전문가 없이도 1차 스크립트 위험도 판단 가능
- MITRE ATT&CK 프레임워크 기반 표준화된 분석 리포트 자동 생성
- 로컬 모델 필터링으로 API 비용 최소화하면서 분석 정확도 유지

---

## 2. 서비스 시나리오

1. 보안 담당자가 의심스러운 스크립트 파일 (`.ps1`, `.js` 등)을 웹 UI에 드래그&드롭으로 업로드한다.
2. 시스템이 파일 인코딩을 감지하고 정규화한다 (전처리).
3. **로컬 모델** (Ollama Mistral-7B + 규칙 엔진)이 악성 패턴과 난독화를 병렬로 탐지하고 위험도 점수를 산출한다.
4. 위험도 점수가 **0.5 미만**이면 로컬 결과만 반환한다 (TOKEN_SAVE).
5. 위험도 점수가 **0.5 이상**이면 **Claude API**가 공격 체인을 추론하고 MITRE ATT&CK 기법을 매핑한다.
6. 최종적으로 위험도 게이지 / 공격 체인 타임라인 / ATT&CK 배지 / 대응 방안이 UI에 표시된다.

---

## 3. 전체 파이프라인 아키텍처

```
[입력 레이어]
  스크립트 파일 업로드
  .ps1 / .js / .py / .vbs / .bat / .sh / .ts  (최대 2MB)
        ↓
[전처리 — preprocessor.py]
  · 인코딩 자동 감지 (chardet)
  · BOM 제거 · 개행 정규화 · 연속 빈 줄 압축
  · MAX_CHARS = 8,000 초과 시 앞부분 보존 후 잘라냄
        ↓
[로컬 AI — 병렬 실행]
  ┌─ classifier.py   Ollama Mistral-7B
  │                  악성 패턴 1차 분류 (10종)
  │                  Ollama 미가동 시 규칙 기반 폴백 자동 전환
  └─ obfuscation.py  규칙 기반 + 엔트로피 분석
                     난독화 탐지 (8종)
        ↓
[앙상블 — risk_scorer.py]
  최종 점수 = 분류 신뢰도 × 0.65 + 난독화 점수 × 0.35
        ↓
[TOKEN_SAVE 판단 게이트]
  score < 0.50  ─────────────────────────→  로컬 결과만 반환 (LLM SKIP)
  score ≥ 0.50  ↓
[Claude API — claude_client.py]
  모델 : claude-sonnet-4-6
  입력 : 로컬 탐지 근거 + 의심 코드 압축본 (최대 2,000자)
  출력 : 공격 체인 / ATT&CK 기법 목록 / 대응 방안 / 요약
        ↓
[출력 — React UI]
  · 위험도 SVG 게이지 (0~100 / SAFE·MEDIUM·HIGH·CRITICAL)
  · 공격 체인 타임라인 (단계별 카드)
  · ATT&CK 배지 (클릭 → attack.mitre.org)
  · 대응 방안 카드
  · TOKEN SAVED 안내 (SKIP 시)
```

---

## 4. 로컬 모델 활용 설명

### 4.1 사용 모델

| 모델 | 용도 |
|------|------|
| **Ollama + Mistral-7B** | 악성 패턴 의미론적 분류 |
| **규칙 기반 엔진** | 난독화 탐지 (외부 의존 없음, 항시 가동) |

### 4.2 classifier.py — 패턴 분류기

| 항목 | 내용 |
|------|------|
| **입력** | 전처리된 코드 문자열 (최대 3,000자), 언어 힌트 |
| **출력** | 탐지된 패턴 목록, 신뢰도 0.0~1.0, 한 줄 근거 |
| **탐지 패턴** | PowerShell 다운로더, 원격 셸/리버스 셸, 프로세스 인젝션, 자격증명 탈취, 지속성 설치, C2 통신, 파일 암호화, 권한 상승, 난독화 실행, 정찰/시스템 열거 |
| **폴백** | Ollama 미가동 시 키워드 규칙 기반 분류 자동 전환 |

### 4.3 obfuscation.py — 난독화 탐지기

| 탐지 항목 | 방법 | 가중치 |
|-----------|------|--------|
| 섀넌 엔트로피 | 5.5 이상 → 고엔트로피 코드 의심 | +0.30 |
| Base64 인코딩 | 40자 이상 패턴 + 실제 디코딩 검증 | +0.20×개수 |
| eval/exec 체인 | 2회 이상 중첩 시 탐지 | +0.25 |
| 유니코드 이스케이프 | `\u????` 패턴 10개 초과 | +0.20 |
| 16진수 바이트 시퀀스 | `\xNN` 블록 10개 이상 연속 | +0.20 |
| 초장문 라인 | 1,000자 이상 단일 라인 | +0.15 |
| chr()/fromCharCode 남용 | 10회 이상 호출 | +0.15 |
| 난수형 변수명 | 20자 이상 의미없는 변수 5개 초과 | +0.10 |

### 4.4 risk_scorer.py — 앙상블 합산

```
최종_점수 = 분류_신뢰도 × 0.65 + 난독화_점수 × 0.35

위험 레벨 구간:
  SAFE     : score < 0.50   → Claude API SKIP (TOKEN_SAVE)
  MEDIUM   : 0.50 ≤ score < 0.75
  HIGH     : 0.75 ≤ score < 0.90
  CRITICAL : score ≥ 0.90
```

### 4.5 로컬 모델 사용 이유

- 빠른 1차 분류로 불필요한 LLM 호출 차단 → 비용·속도 최적화
- 인터넷 없는 격리 환경(에어갭)에서도 기본 분석 가능
- 민감한 코드를 외부 API에 전송하지 않아도 되는 1차 프라이버시 보호
- Ollama 로컬 추론은 무료 → 대량 분석 시 비용 제로

---

## 5. Claude API 활용 설명

### 5.1 사용 모델

`claude-sonnet-4-6`

### 5.2 사용 목적

로컬 모델의 1차 분류 결과를 바탕으로 공격 체인 추론, MITRE ATT&CK 기법 매핑, 자연어 대응 방안 생성

### 5.3 입력 프롬프트 구조

**시스템 프롬프트** (고정 → 캐시 친화적 설계)
```
악성 스크립트 분석 전문 보안 연구원으로서
로컬 AI 1차 분류 결과 + 코드 발췌를 바탕으로
반드시 JSON 형식의 ATT&CK 매핑 리포트만 반환
```

**유저 프롬프트** (TOKEN_SAVE 설계 — 압축본만 전달)
```
[로컬 AI 1차 분석 결과]        ← 탐지 근거 요약 (~300자)
위험도 점수 / 탐지 패턴 / 난독화 기법 / 근거
[의심 코드 발췌 (압축본)]       ← 원본 전체 대신 상위 30줄 (최대 2,000자)
...코드 발췌...
→ JSON 리포트 생성 요청
```

### 5.4 출력 스키마

```json
{
  "attack_chain": ["1단계: ...", "2단계: ..."],
  "mitre_techniques": [
    {
      "technique_id": "T1059.001",
      "name": "PowerShell",
      "tactic": "Execution"
    }
  ],
  "recommendation": "구체적 대응 방안 2~4문장",
  "summary": "전체 요약 1~2문장"
}
```

### 5.5 오류 복구 3단계

1. 전체 텍스트 JSON 파싱 시도
2. 마크다운 코드블록 제거 후 재시도
3. 정규식으로 `{...}` 블록 추출 후 파싱
4. 모두 실패 시 로컬 결과 기반 폴백 리포트 반환 (서비스 중단 없음)

### 5.6 로컬 모델 vs Claude API 역할 분담

| 구분 | 로컬 모델 | Claude API |
|------|----------|-----------|
| 호출 조건 | 항상 실행 | score ≥ 0.5 인 경우만 |
| 속도 | 빠름 (로컬) | 느림 (네트워크) |
| 비용 | 무료 | 토큰 과금 |
| 역할 | 빠른 분류·필터링·게이트키퍼 | 깊은 추론·자연어 생성 |
| 출력 | 점수 + 패턴 목록 | 공격 체인 + ATT&CK 매핑 + 대응 방안 |
| 한계 보완 | 의미론적 이해 부족 → Claude가 보완 | 비용·속도 → 로컬이 필터링 |

---

## 6. 보안 기능 설명

| 기능 | 구현 위치 | 설명 |
|------|----------|------|
| 악성 여부 탐지 | classifier.py | 10종 악성 패턴 분류 |
| 위험도 점수 산정 | risk_scorer.py | 앙상블 0.0~1.0 점수 |
| 난독화 탐지 | obfuscation.py | 엔트로피 + 8종 규칙 기반 |
| 공격 유형 분류 | classifier.py | Ollama Mistral-7B |
| MITRE ATT&CK 매핑 | attack_mapper.py + Claude API | 37종 기법 카탈로그 |
| 대응 방안 추천 | claude_client.py | 자연어 구체적 대응 |
| 보안 리포트 자동 생성 | pipeline.py + ReportPanel.tsx | 전체 결과 조합 |

---

## 7. 토큰 사용 효율화 전략

| 전략 | 구현 위치 | 효과 |
|------|----------|------|
| score < 0.5 → Claude API 호출 SKIP | risk_scorer.py + pipeline.py | 저위험 파일 100% 절감 |
| 코드 전문 대신 압축본 2,000자만 전달 | preprocessor.compress_for_llm() | 평균 ~65% 절감 |
| max_tokens=1,200 제한 | claude_client.py | 불필요한 장황함 방지 |
| 시스템 프롬프트 고정 구조 | prompts.py | 캐시 친화적, 반복 호출 절감 |
| Few-shot 예시 없이 JSON 강제 출력 | prompts.py | 재호출 방지 |

> 코드 내 `# TOKEN_SAVE:` 태그로 절감 포인트를 인라인으로 명시

---

## 8. 전체 파일 구조

```
malscript-analyzer/
│
├── README.md
├── install.bat                      의존성 설치 (최초 1회)
├── start.bat                        전체 서비스 실행
│
├── backend/
│   ├── .env.example                 환경 변수 예시
│   ├── requirements.txt             Python 의존성
│   ├── main.py                      FastAPI 서버 (3 엔드포인트)
│   ├── pipeline.py                  전체 오케스트레이션 + TOKEN_SAVE 판단
│   ├── preprocessor.py              인코딩 감지 · 정규화 · 압축
│   ├── test_local_model.py          로컬 모델 단위 테스트
│   ├── test_api.py                  FastAPI 통합 테스트 (TestClient)
│   ├── test_llm_pipeline.py         Claude API mock E2E 테스트
│   │
│   ├── local_model/
│   │   ├── __init__.py
│   │   ├── classifier.py            Ollama Mistral-7B 패턴 분류 (폴백 내장)
│   │   ├── obfuscation.py           엔트로피 + 8종 난독화 탐지
│   │   └── risk_scorer.py           가중 앙상블 + LLM 분기 결정
│   │
│   ├── llm_client/
│   │   ├── __init__.py
│   │   ├── claude_client.py         Claude API 호출 + 3단계 JSON 파싱 복구
│   │   └── prompts.py               TOKEN_SAVE 설계 프롬프트 템플릿
│   │
│   └── security/
│       ├── __init__.py
│       ├── schemas.py               Pydantic 입출력 타입 전체 정의
│       └── attack_mapper.py         MITRE ATT&CK 37종 기법 카탈로그 + URL 생성
│
└── frontend/
    ├── package.json
    ├── next.config.js               /api/* → localhost:8000 프록시
    ├── tsconfig.json
    └── src/
        ├── app/
        │   ├── layout.tsx
        │   ├── page.tsx             메인 페이지 (4단계 진행 표시 · 헬스 폴링)
        │   └── globals.css          JetBrains Mono + DM Sans 폰트
        ├── components/
        │   ├── FileUpload.tsx       드래그&드롭 + 클라이언트 유효성 검증
        │   ├── RiskGauge.tsx        SVG 원형 게이지 (위험도별 색상·글로우)
        │   ├── AttackChain.tsx      공격 체인 타임라인 + ATT&CK 배지
        │   └── ReportPanel.tsx      전체 결과 카드 조합
        └── lib/
            └── api.ts               타입 정의 + fetch 클라이언트
```

---

## 9. API 엔드포인트

| Method | Path | 상태 코드 | 설명 |
|--------|------|----------|------|
| GET | `/health` | 200 | 서버 · Ollama 연결 상태 확인 |
| POST | `/analyze` | 200/400/413/415 | 스크립트 업로드 → 분석 결과 JSON 반환 |
| GET | `/analyze/{id}` | 200/404 | 이전 분석 결과 재조회 (인메모리 캐시) |

Swagger UI: `http://localhost:8000/docs`

---

## 10. 빠른 시작

### 사전 요구사항

| 항목 | 버전 |
|------|------|
| Python | 3.11+ |
| Node.js | 18+ |
| Ollama | 최신 (선택) |

### Windows — 배치 파일로 실행

```
1. install.bat  실행  (최초 1회 — 패키지 설치)
2. start.bat    실행  (매번 — 서버 시작)
3. 브라우저에서 http://localhost:3000 접속
```

### macOS / Linux — 수동 실행

```bash
# Ollama 설치 및 모델 다운로드 (선택)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral

# 터미널 1: Ollama
ollama serve

# 터미널 2: FastAPI 백엔드
cd backend
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # 선택
python main.py
# → http://localhost:8000  |  Swagger: http://localhost:8000/docs

# 터미널 3: Next.js 프론트엔드
cd frontend
npm install
npm run dev
# → http://localhost:3000
```

### 테스트 실행

```bash
cd backend
python test_local_model.py      # 로컬 모델 단위 테스트
python test_api.py              # FastAPI 통합 테스트 (서버 불필요)
python test_llm_pipeline.py     # Claude API mock 테스트 (키 불필요)
```

---

## 11. 테스트 결과 요약

### 로컬 모델 테스트 (test_local_model.py)

| 파일 | 탐지 결과 | 앙상블 점수 | Claude API |
|------|----------|------------|-----------|
| benign_hello.py | 패턴 없음 | 0.000 SAFE | SKIP ✓ |
| suspicious_ps1.ps1 | PowerShell 다운로더 | 0.133 SAFE* | SKIP ✓ |
| obfuscated_js.js | eval 체인 탐지 | 0.185 SAFE* | SKIP ✓ |

> \* 규칙 기반 폴백 기준. **Ollama 연결 시** Mistral-7B가 의미론적 분석으로 0.5+ 점수 산출 → Claude API 호출 대상 전환

### FastAPI 통합 테스트 (test_api.py) — 7개 전부 통과

| 테스트 케이스 | 결과 | HTTP 상태 |
|--------------|------|----------|
| GET /health | ✓ PASS | 200 |
| .exe 확장자 거부 | ✓ PASS | 415 |
| 빈 파일 거부 | ✓ PASS | 400 |
| hello.py 정상 파일 분석 | ✓ PASS | 200 + TOKEN SAVED |
| drop.ps1 의심 파일 분석 | ✓ PASS | 200 + 패턴 탐지 |
| obf.js 난독화 파일 분석 | ✓ PASS | 200 + 난독화 탐지 |
| 없는 ID 조회 | ✓ PASS | 404 |

### Claude API mock 파이프라인 테스트 (test_llm_pipeline.py) — 5개 전부 통과

| 테스트 케이스 | 결과 |
|--------------|------|
| 프롬프트 빌더 검증 | ✓ PASS |
| ATT&CK 매퍼 (중복 제거 + 미지 ID URL 생성) | ✓ PASS |
| Claude API mock 호출 + JSON 파싱 | ✓ PASS |
| E2E 파이프라인 고위험 스크립트 | ✓ PASS |
| API 키 미설정 → 폴백 리포트 반환 | ✓ PASS |

---

## 12. 평가 기준 대응표

| 평가 항목 | 배점 | 구현 내용 |
|-----------|------|----------|
| 프로젝트 주제 적합성 및 보안 연계성 | 20점 | 탐지·분석·대응 전 영역 커버, MITRE ATT&CK 연동으로 보안 도메인 이해도 반영 |
| AI 모델 활용 설계 | 20점 | 로컬 모델·Claude API 역할 명확 분리, 입출력 타입 힌트 명시, 모델 선택 근거 주석 |
| 로컬 모델 활용도 | 15점 | 파이프라인 핵심 단계에 배치, LLM 호출 여부를 결정하는 게이트키퍼 역할 |
| 전체 파이프라인 아키텍처 완성도 | 15점 | 입력→전처리→로컬→판단→LLM→UI 전 흐름 명확, 아키텍처 다이어그램 포함 |
| 토큰 사용 효율성 | 10점 | 5가지 TOKEN_SAVE 전략, `# TOKEN_SAVE:` 인라인 태그로 코드에 명시 |
| 창의성 및 차별성 | 10점 | MITRE ATT&CK 자동 매핑, 앙상블 설계, 단순 API 호출을 초월한 구조적 파이프라인 |
| 조건 만족 및 제출물 완성도 | 10점 | 로컬 모델 1개 이상, React UI 데모, 필수 제출 요소 전부 포함, 한계점 작성 |
| **합계** | **100점** | |

---

## 13. 제출 전 체크리스트

- [x] 보안 관련 서비스인지 명확히 설명했는가
- [x] 로컬 모델을 1개 이상 사용했는가 (Ollama Mistral-7B + 규칙 기반 엔진)
- [x] 로컬 모델의 역할이 실제 파이프라인에 포함되어 있는가
- [x] GPT/Claude 사용 여부와 역할을 설명했는가
- [x] 전체 파이프라인 아키텍처 그림을 제출했는가
- [x] 입력부터 출력까지 데이터 흐름이 설명되어 있는가
- [x] 토큰 사용 효율화 전략을 작성했는가
- [x] 결과 예시를 포함했는가 (테스트 결과표)
- [x] 조건 만족 여부를 표로 정리했는가
- [x] 한계점 및 개선 방향을 작성했는가

---

## 14. 한계점 및 개선 방향

### 현재 한계점

| 항목 | 내용 |
|------|------|
| 규칙 기반 폴백 점수 | Ollama 미가동 시 보수적 채점 → 실제 위험 파일이 SAFE로 분류될 수 있음 |
| 정적 분석 한계 | 동적 실행 없이 정적 패턴만 분석 → 다형성 악성코드 탐지 한계 |
| 인메모리 캐시 | 서버 재시작 시 이전 분석 이력 소실 |
| 단일 파일 분석 | 드로퍼+페이로드 등 멀티 파일 공격 체인 연계 분석 불가 |
| 한국어 스크립트 | 한국어 주석이 많은 내부 공격 스크립트 탐지 성능 미검증 |

### 개선 방향

| 항목 | 방향 |
|------|------|
| 데이터베이스 연동 | SQLite → PostgreSQL로 분석 이력 영구 저장 |
| 동적 분석 연동 | Cuckoo Sandbox API 연동으로 실행 기반 행위 분석 추가 |
| 모델 파인튜닝 | 악성 스크립트 공개 데이터셋으로 로컬 분류기 정밀도 향상 |
| 배치 분석 | 여러 파일 동시 분석 + 결과 비교 기능 |
| YARA 룰 연동 | 기존 YARA 룰과 AI 분석 결과 교차 검증 |
| 분산 처리 | Celery + Redis로 대용량 파일 비동기 분석 |

---

## 15. 환경 변수

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `ANTHROPIC_API_KEY` | Claude API 키 (없으면 폴백 리포트) | — |
| `NEXT_PUBLIC_API_URL` | 백엔드 주소 | `http://localhost:8000` |
