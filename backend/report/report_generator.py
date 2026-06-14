# backend/report/report_generator.py
"""
한국어 PDF 보고서 생성기
폰트 우선순위: 번들 NanumGothic > Windows 맑은고딕/굴림 > Linux DroidSansFallback
"""
from __future__ import annotations
import io, os, logging
from datetime import datetime
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

logger = logging.getLogger(__name__)

# ── 폰트 등록 ──────────────────────────────────────────────────────────────
_FONT_REGISTERED = False
_FONT_NAME = "KorFont"
_FONT_NAME_B = "KorFontB"   # 굵게 (없으면 일반체 fallback)


def _register_korean_font() -> None:
    global _FONT_REGISTERED, _FONT_NAME, _FONT_NAME_B
    if _FONT_REGISTERED:
        return

    _BASE = os.path.dirname(os.path.dirname(__file__))  # backend/

    candidates = [
        # 번들 폰트 (프로젝트 내)
        (os.path.join(_BASE, "fonts", "NanumGothic.ttf"), None),
        (os.path.join(_BASE, "fonts", "NanumGothic-Regular.ttf"), None),
        # Windows 시스템 폰트
        (r"C:\Windows\Fonts\malgun.ttf",   r"C:\Windows\Fonts\malgunbd.ttf"),
        (r"C:\Windows\Fonts\gulim.ttc",    None),
        (r"C:\Windows\Fonts\batang.ttc",   None),
        # macOS
        ("/System/Library/Fonts/AppleGothic.ttf", None),
        # Linux / Docker 환경
        ("/usr/share/fonts/truetype/nanum/NanumGothic.ttf", "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf"),
        ("/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf", None),
        ("/usr/share/fonts/truetype/droid/DroidSansFallback.ttf", None),
    ]

    for reg_path, bold_path in candidates:
        if os.path.exists(reg_path):
            try:
                pdfmetrics.registerFont(TTFont(_FONT_NAME, reg_path))
                if bold_path and os.path.exists(bold_path):
                    pdfmetrics.registerFont(TTFont(_FONT_NAME_B, bold_path))
                else:
                    _FONT_NAME_B = _FONT_NAME  # fallback: 굵게 없으면 일반체
                _FONT_REGISTERED = True
                logger.info(f"[report] 한국어 폰트 등록: {reg_path}")
                return
            except Exception as e:
                logger.warning(f"[report] 폰트 등록 실패 ({reg_path}): {e}")
                continue

    # 한국어 폰트를 찾지 못한 경우: ReportLab 내장 Helvetica로 폴백
    # 한글이 올바르게 렌더링되지 않을 수 있으나 PDF 생성 자체는 성공함
    # 권장: backend/fonts/NanumGothic.ttf 추가
    #       https://fonts.google.com/specimen/Nanum+Gothic
    _FONT_NAME = "Helvetica"
    _FONT_NAME_B = "Helvetica-Bold"
    _FONT_REGISTERED = True
    logger.warning(
        "[report] 한국어 폰트를 찾지 못했습니다. "
        "Helvetica 폴백 사용 중 — 한글이 깨질 수 있습니다. "
        "backend/fonts/NanumGothic.ttf 를 추가하면 한글이 올바르게 표시됩니다."
    )


# ── 스타일 팩토리 ──────────────────────────────────────────────────────────
def _styles():
    _register_korean_font()
    F, FB = _FONT_NAME, _FONT_NAME_B
    return {
        "title":    ParagraphStyle("title",    fontName=FB, fontSize=20, leading=28, textColor=colors.HexColor("#0f172a"), alignment=TA_CENTER, spaceAfter=4),
        "subtitle": ParagraphStyle("subtitle", fontName=F,  fontSize=11, leading=16, textColor=colors.HexColor("#475569"), alignment=TA_CENTER, spaceAfter=2),
        "h1":       ParagraphStyle("h1",       fontName=FB, fontSize=14, leading=20, textColor=colors.HexColor("#0ea5e9"), spaceBefore=12, spaceAfter=4),
        "h2":       ParagraphStyle("h2",       fontName=FB, fontSize=11, leading=16, textColor=colors.HexColor("#1e293b"), spaceBefore=8, spaceAfter=3),
        "body":     ParagraphStyle("body",     fontName=F,  fontSize=9.5, leading=15, textColor=colors.HexColor("#334155"), spaceAfter=3),
        "code":     ParagraphStyle("code",     fontName=F,  fontSize=8.5, leading=13, textColor=colors.HexColor("#0f172a"), backColor=colors.HexColor("#f1f5f9"), leftIndent=6, rightIndent=6, spaceAfter=3),
        "label":    ParagraphStyle("label",    fontName=FB, fontSize=9,   leading=13, textColor=colors.HexColor("#0ea5e9")),
        "small":    ParagraphStyle("small",    fontName=F,  fontSize=8,   leading=12, textColor=colors.HexColor("#64748b")),
        "right":    ParagraphStyle("right",    fontName=F,  fontSize=8.5, leading=13, textColor=colors.HexColor("#94a3b8"), alignment=TA_RIGHT),
    }


def _risk_color(level: str) -> colors.HexColor:
    return {
        "critical": colors.HexColor("#ef4444"),
        "high":     colors.HexColor("#f97316"),
        "medium":   colors.HexColor("#f59e0b"),
        "low":      colors.HexColor("#22c55e"),
        "safe":     colors.HexColor("#22c55e"),
    }.get(level.lower(), colors.HexColor("#94a3b8"))


def _hr(story, st):
    story.append(Spacer(1, 2*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 3*mm))


def _section(story, st, num: int, title: str):
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(f"{num}. {title}", st["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0ea5e9")))
    story.append(Spacer(1, 3*mm))


def _kv_table(story, st, rows: list[tuple[str, str]]):
    data = [[Paragraph(k, st["label"]), Paragraph(v, st["body"])] for k, v in rows]
    t = Table(data, colWidths=[45*mm, None])
    t.setStyle(TableStyle([
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("LINEBELOW",   (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
    ]))
    story.append(t)
    story.append(Spacer(1, 3*mm))


# ── 메인 생성 함수 ─────────────────────────────────────────────────────────
def generate_report(
    result,
    scenario=None,
    sim_events: Optional[list] = None,
    sim_summary: Optional[dict] = None,
) -> bytes:
    """
    분석 결과(AnalysisResult), 시나리오(AttackScenario), 시뮬레이션 이벤트를
    받아 한국어 PDF 바이트열을 반환한다.
    """
    _register_korean_font()
    st = _styles()
    buf = io.BytesIO()

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=22*mm, bottomMargin=20*mm,
        title="악성 스크립트 분석 보고서",
        author="MalScript Analyzer",
        subject=f"분석 대상: {result.filename}",
    )

    story = []
    now_str = datetime.now().strftime("%Y년 %m월 %d일 %H:%M")

    # ── 표지 ──────────────────────────────────────────────────────────────
    story.append(Spacer(1, 20*mm))
    story.append(Paragraph("악성 스크립트 분석 보고서", st["title"]))
    story.append(Spacer(1, 3*mm))
    story.append(HRFlowable(width="60%", thickness=2, color=colors.HexColor("#0ea5e9"), hAlign="CENTER"))
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph(f"대상 파일: {result.filename}", st["subtitle"]))
    story.append(Paragraph(f"생성 일시: {now_str}", st["subtitle"]))
    story.append(Spacer(1, 6*mm))

    # 위험도 배지 (표)
    risk_lv  = result.local.risk_level.upper()
    rc = _risk_color(result.local.risk_level)
    badge = Table(
        [[Paragraph(f"위험 등급: {risk_lv}", ParagraphStyle("b", fontName=_FONT_NAME_B, fontSize=13, textColor=colors.white, alignment=TA_CENTER))]],
        colWidths=[60*mm],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(0,0), rc),
        ("ROUNDEDCORNERS", (0,0),(0,0), [4]),
        ("TOPPADDING",   (0,0),(0,0), 6),
        ("BOTTOMPADDING",(0,0),(0,0), 6),
        ("ALIGN",        (0,0),(0,0), "CENTER"),
    ]))
    story.append(badge)
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph(f"위험 점수: {result.local.risk_score:.3f} / 1.000", st["subtitle"]))
    story.append(PageBreak())

    sec = 1

    # ── 1. 분석 개요 ──────────────────────────────────────────────────────
    _section(story, st, sec, "분석 개요"); sec += 1
    _kv_table(story, st, [
        ("파일명",       result.filename),
        ("파일 크기",    f"{result.file_size_bytes:,} bytes"),
        ("스크립트 언어", result.lang_hint.upper()),
        ("줄 수",        f"{result.line_count:,} 줄"),
        ("내용 잘림",    "예" if result.truncated else "아니오"),
        ("처리 시간",    f"{result.processing_time_ms:,} ms"),
        ("LLM 분석",     "생략됨 (저위험)" if result.llm_skipped else "수행됨 (Claude API)"),
        ("보고서 생성",  now_str),
    ])

    # ── 2. 위험 지표 ──────────────────────────────────────────────────────
    _section(story, st, sec, "탐지된 위험 지표"); sec += 1

    if result.local.pattern_labels:
        story.append(Paragraph("탐지 패턴", st["h2"]))
        for p in result.local.pattern_labels:
            story.append(Paragraph(f"• {p}", st["body"]))
        story.append(Spacer(1, 2*mm))

    if result.local.obfuscation_techniques:
        story.append(Paragraph("난독화 기법", st["h2"]))
        for o in result.local.obfuscation_techniques:
            story.append(Paragraph(f"• {o}", st["body"]))
        story.append(Spacer(1, 2*mm))

    if result.local.evidence:
        story.append(Paragraph("증거 코드 스니펫", st["h2"]))
        for e in result.local.evidence[:5]:
            story.append(Paragraph(str(e)[:200], st["code"]))
        story.append(Spacer(1, 2*mm))

    _kv_table(story, st, [
        ("위험 점수",    f"{result.local.risk_score:.4f}"),
        ("위험 등급",    risk_lv),
        ("난독화 점수",  f"{result.local.obfuscation_score:.4f}"),
        ("엔트로피",     f"{result.local.entropy:.4f}"),
    ])

    # ── 3. LLM 분석 (있는 경우) ───────────────────────────────────────────
    if result.llm and not result.llm_skipped:
        _section(story, st, sec, "Claude AI 심층 분석"); sec += 1

        if result.llm.summary:
            story.append(Paragraph("요약", st["h2"]))
            story.append(Paragraph(result.llm.summary, st["body"]))
            story.append(Spacer(1, 2*mm))

        if result.llm.mitre_techniques:
            story.append(Paragraph("MITRE ATT&CK 기법", st["h2"]))
            hdr = [Paragraph(h, st["label"]) for h in ["기법 ID", "기법명", "전술"]]
            rows = [hdr] + [
                [Paragraph(t.technique_id, st["body"]),
                 Paragraph(t.name, st["body"]),
                 Paragraph(t.tactic, st["body"])]
                for t in result.llm.mitre_techniques
            ]
            tbl = Table(rows, colWidths=[28*mm, None, 35*mm])
            tbl.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR",    (0,0),(-1,0), colors.white),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8fafc"),colors.white]),
                ("GRID",         (0,0),(-1,-1), 0.3, colors.HexColor("#e2e8f0")),
                ("VALIGN",       (0,0),(-1,-1), "TOP"),
                ("LEFTPADDING",  (0,0),(-1,-1), 4),
                ("TOPPADDING",   (0,0),(-1,-1), 3),
                ("BOTTOMPADDING",(0,0),(-1,-1), 3),
            ]))
            story.append(tbl)
            story.append(Spacer(1, 3*mm))

        if result.llm.attack_chain:
            story.append(Paragraph("공격 체인", st["h2"]))
            for i, step in enumerate(result.llm.attack_chain, 1):
                story.append(Paragraph(f"{i}. {step}", st["body"]))
            story.append(Spacer(1, 2*mm))

        if result.llm.recommendation:
            story.append(Paragraph("대응 권고사항", st["h2"]))
            story.append(Paragraph(result.llm.recommendation, st["body"]))

    # ── 4. 취약점 분석 ────────────────────────────────────────────────────
    if result.vulnerabilities and result.vulnerabilities.vulnerabilities:
        _section(story, st, sec, "취약점 분석 (CWE)"); sec += 1
        vuln_list = result.vulnerabilities.vulnerabilities
        _kv_table(story, st, [
            ("최고 심각도", result.vulnerabilities.highest_severity),
            ("취약점 수",   str(len(vuln_list))),
            ("영향 유형",   ", ".join(result.vulnerabilities.impact_types)),
        ])
        hdr = [Paragraph(h, st["label"]) for h in ["CWE ID","취약점명","심각도","CVSS","영향"]]
        rows = [hdr] + [
            [Paragraph(v.cwe_id, st["body"]),
             Paragraph(v.cwe_name[:30], st["body"]),
             Paragraph(v.severity, st["body"]),
             Paragraph(f"{v.cvss_estimate:.1f}", st["body"]),
             Paragraph(v.impact_type, st["body"])]
            for v in vuln_list
        ]
        tbl = Table(rows, colWidths=[22*mm, None, 18*mm, 14*mm, 22*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR",    (0,0),(-1,0), colors.white),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8fafc"),colors.white]),
            ("GRID",         (0,0),(-1,-1), 0.3, colors.HexColor("#e2e8f0")),
            ("VALIGN",       (0,0),(-1,-1), "TOP"),
            ("LEFTPADDING",  (0,0),(-1,-1), 3),
            ("TOPPADDING",   (0,0),(-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
        ]))
        story.append(tbl)

    # ── 5. 공격 시나리오 ──────────────────────────────────────────────────
    if scenario:
        story.append(PageBreak())
        _section(story, st, sec, "공격 시나리오"); sec += 1
        _kv_table(story, st, [
            ("시나리오명",    scenario.title),
            ("난이도",        scenario.difficulty),
            ("단계 수",       str(len(scenario.steps))),
            ("시나리오 ID",   scenario.scenario_id),
        ])
        story.append(Paragraph("개요", st["h2"]))
        story.append(Paragraph(scenario.description, st["body"]))
        story.append(Spacer(1, 3*mm))

        story.append(Paragraph("공격 단계", st["h2"]))
        for s in scenario.steps:
            story.append(Paragraph(
                f"단계 {s.step_number}: {s.title}"
                + (f"  [{s.mitre_technique}]" if s.mitre_technique else ""),
                ParagraphStyle("sh2", fontName=_FONT_NAME_B, fontSize=10, leading=15,
                               textColor=colors.HexColor("#0ea5e9"), spaceBefore=5, spaceAfter=2)
            ))
            story.append(Paragraph(s.description, st["body"]))
            if s.command:
                story.append(Paragraph(f"$ {s.command}", st["code"]))
            if s.expected_outcome:
                story.append(Paragraph(f"예상 결과: {s.expected_outcome}", st["small"]))
            story.append(Spacer(1, 2*mm))

        if scenario.defenses:
            story.append(Paragraph("방어 대책", st["h2"]))
            for d in scenario.defenses:
                story.append(Paragraph(f"• {d}", st["body"]))

    # ── 6. 시뮬레이션 결과 ────────────────────────────────────────────────
    if sim_events and sim_summary:
        story.append(PageBreak())
        _section(story, st, sec, "시뮬레이션 실행 결과"); sec += 1

        total  = sim_summary.get("total_steps", 0)
        ok     = sim_summary.get("success_count", 0)
        fail   = sim_summary.get("failed_count", 0)
        lab_id = sim_summary.get("lab_id", "dry-run")

        _kv_table(story, st, [
            ("총 단계",   str(total)),
            ("성공",      str(ok)),
            ("차단(방어)", str(fail)),
            ("환경",      lab_id),
            ("결과 요약",  f"{'공격 전부 성공 (방어 미감지)' if fail==0 else f'{ok}단계 성공 / {fail}단계 방어에 차단됨'}"),
        ])

        story.append(Paragraph("이벤트 로그", st["h2"]))
        ev_types = {"step_done":"✓", "step_failed":"✗", "defense_triggered":"⚠", "step_error":"?"}
        for ev in sim_events:
            et = ev.get("event_type","")
            if et in ("log",) and not ev.get("message",""):
                continue
            icon = ev_types.get(et, "·")
            step_tag = f"[{ev.get('step',0)}]  " if ev.get("step") else ""
            msg  = str(ev.get("message",""))[:120]
            color_map = {
                "step_done":"#22c55e","step_failed":"#ef4444",
                "defense_triggered":"#f97316","step_error":"#78716c",
                "complete":"#a78bfa",
            }
            tc = color_map.get(et, "#475569")
            story.append(Paragraph(
                f"{icon} {step_tag}{msg}",
                ParagraphStyle("ev", fontName=_FONT_NAME, fontSize=8.5, leading=13,
                               textColor=colors.HexColor(tc), spaceAfter=1)
            ))

    # ── 7. 결론 및 권고사항 ───────────────────────────────────────────────
    _section(story, st, sec, "결론 및 권고사항"); sec += 1
    risk_ko = {"safe":"안전","low":"낮음","medium":"중간","high":"높음","critical":"심각"}
    story.append(Paragraph(
        f"분석된 파일 <b>{result.filename}</b>은 위험 등급 <b>{risk_ko.get(result.local.risk_level,'?')}</b>"
        f"(점수: {result.local.risk_score:.3f})으로 평가되었습니다.",
        st["body"]
    ))
    story.append(Spacer(1, 2*mm))

    recs = []
    if result.local.risk_score >= 0.8:
        recs.append("즉각적인 격리 및 포렌식 조사를 권고합니다.")
        recs.append("해당 파일의 실행 이력을 전체 환경에서 검토하십시오.")
    elif result.local.risk_score >= 0.5:
        recs.append("보안 팀에 검토를 요청하고 실행을 차단하십시오.")
        recs.append("동일 해시 파일이 다른 시스템에 존재하는지 확인하십시오.")
    else:
        recs.append("낮은 위험도이나 불필요하면 삭제를 권고합니다.")
    if result.local.obfuscation_score > 0.4:
        recs.append("높은 난독화 점수가 탐지되었습니다. 샌드박스 동적 분석을 권고합니다.")
    if result.llm and result.llm.recommendation:
        recs.append(result.llm.recommendation)

    for r in recs:
        story.append(Paragraph(f"• {r}", st["body"]))

    story.append(Spacer(1, 5*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        f"본 보고서는 MalScript Analyzer에 의해 자동 생성되었습니다.  |  {now_str}",
        st["right"]
    ))

    doc.build(story)
    return buf.getvalue()
