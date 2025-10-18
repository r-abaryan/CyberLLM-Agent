#!/usr/bin/env python3
"""
Cyber Threat Assessment API

FastAPI wrapper for the LangChain-based agent in cyber_agent.py.
Exposes a POST /assess endpoint that accepts { threat, context } and returns
the structured assessment with guardrails and RAG.

Run:
  uvicorn cyber_api:app --host 0.0.0.0 --port 8000 --workers 1
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

from cyber_agent import (
    build_llm,
    build_chain,
    load_kb_documents,
    retrieve_context,
    assess_threat,
)


class AssessRequest(BaseModel):
    threat: str
    context: Optional[str] = ""


class AssessResponse(BaseModel):
    assessment: str


def create_app(model_path: str = "./cyberllm_sft_model", device: str = "auto", kb_path: str = "./knowledge_base") -> FastAPI:
    app = FastAPI(title="Cyber Threat Assessment API", version="1.0.0")

    llm = build_llm(model_path=model_path, device=device)
    chain = build_chain(llm)
    kb_docs = load_kb_documents(kb_path)

    @app.post("/assess", response_model=AssessResponse)
    def assess(req: AssessRequest):
        retrieved = retrieve_context(req.threat, req.context or "", kb_docs)
        out = assess_threat(chain, req.threat, req.context or "", retrieved)
        return AssessResponse(assessment=out)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()


