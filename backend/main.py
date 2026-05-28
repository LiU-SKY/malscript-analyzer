# backend/main.py
from __future__ import annotations
import logging
import uuid
from typing import Annotated

import ollama as ollama_client
from fastapi import FastAPI, File, UploadFile, HTTPException, Path
from fastapi.middleware.cors import CORSMiddleware

from pipeline import run_pipeline
from security.schemas import AnalyzeResponse, HealthResponse, AnalysisResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="MalScript Analyzer API",
    description="멀티스테이지 악성 스크립트 분석 플랫폼 (로컬 AI + Claude API)",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_result_cache: dict[str, AnalysisResult] = {}
ALLOWED_EXTENSIONS = {".ps1", ".js", ".py", ".vbs", ".bat", ".sh", ".ts"}
MAX_FILE_SIZE_MB = 2


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    ollama_ok = False
    model_name = "mistral (미연결)"
    try:
        models = ollama_client.list()
        names = [m["name"] for m in models.get("models", [])]
        ollama_ok = any("mistral" in n for n in names)
        model_name = next((n for n in names if "mistral" in n), "없음")
    except Exception:
        pass
    return HealthResponse(status="ok", ollama_available=ollama_ok, model_loaded=model_name)


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_file(
    file: Annotated[UploadFile, File(description="분석할 스크립트 파일")],
) -> AnalyzeResponse:
    filename = file.filename or "unknown"
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"지원하지 않는 확장자: {ext}. 허용: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    raw_bytes = await file.read()

    if len(raw_bytes) > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"파일 크기 초과 (최대 {MAX_FILE_SIZE_MB}MB)")
    if len(raw_bytes) == 0:
        raise HTTPException(status_code=400, detail="빈 파일입니다.")

    logger.info(f"[/analyze] 요청 | file={filename} size={len(raw_bytes)}B")

    try:
        result = run_pipeline(filename, raw_bytes)
    except Exception as e:
        logger.error(f"[/analyze] 파이프라인 오류: {e}", exc_info=True)
        return AnalyzeResponse(success=False, error=str(e))

    result_id = str(uuid.uuid4())[:8]
    _result_cache[result_id] = result
    logger.info(
        f"[/analyze] 완료 | id={result_id} score={result.local.risk_score:.3f} "
        f"llm_skipped={result.llm_skipped} time={result.processing_time_ms}ms"
    )
    return AnalyzeResponse(success=True, result=result)


@app.get("/analyze/{result_id}", response_model=AnalyzeResponse, tags=["Analysis"])
async def get_result(
    result_id: Annotated[str, Path(description="이전 분석 결과 ID")],
) -> AnalyzeResponse:
    result = _result_cache.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="결과를 찾을 수 없습니다.")
    return AnalyzeResponse(success=True, result=result)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
