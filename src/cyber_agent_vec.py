#!/usr/bin/env python3
"""
Cyber Threat Assessment Agent with Vector RAG

Wraps the local fine-tuned model with LangChain and vector-based RAG for
enhanced threat assessment using semantic similarity search.

Usage:
  python src/cyber_agent_vec.py --threat "Suspicious PowerShell downloads from unknown IPs"
  python src/cyber_agent_vec.py  # starts interactive CLI
"""

import argparse
import os
import sys
from typing import List, Tuple, Optional, Dict
import datetime
import pathlib
import json

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline

# LangChain core
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_huggingface import HuggingFacePipeline

# Vector RAG
from rag.vector_rag import create_vector_rag, VectorRAG

# IOC extraction
from utils.ioc_utils import extract_iocs, format_iocs_json, iocs_to_text


REQUIRED_SECTIONS = [
    "Summary",
    "Severity",
    "Immediate Actions",
    "Recovery",
    "Preventive Measures",
]

def get_required_sections(simple: bool) -> List[str]:
    return REQUIRED_SECTIONS


def build_llm(model_path: str = "./output/cyberllm_sft_model", device: str = "auto") -> HuggingFacePipeline:
    """Create a LangChain LLM from the local fine-tuned model via HF pipeline."""
    tokenizer = AutoTokenizer.from_pretrained(model_path, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    torch_dtype = torch.float16 if torch.cuda.is_available() else torch.float32
    device_map = device

    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        torch_dtype=torch_dtype,
        device_map=device_map,
    )

    generate_kwargs = dict(
        max_new_tokens=512,
        temperature=0.7,
        top_p=0.9,
        repetition_penalty=1.1,
        eos_token_id=tokenizer.eos_token_id,
        pad_token_id=tokenizer.eos_token_id,
    )

    pipe = pipeline(
        task="text-generation",
        model=model,
        tokenizer=tokenizer,
        return_full_text=False,
        **generate_kwargs,
    )

    return HuggingFacePipeline(pipeline=pipe)


def build_chain(llm: HuggingFacePipeline, *, simple: bool = False):
    """Create a LangChain with rubric, RAG context, and structured sections."""
    severity_rubric = (
        "Severity rubric (choose one and justify):\n"
        "- Low: Contained, minimal business impact, easy mitigation.\n"
        "- Medium: Limited spread or data exposure, moderate remediation effort.\n"
        "- High: Active compromise likely, material impact or sensitive data risk.\n"
        "- Critical: Widespread compromise, major impact, immediate executive escalation."
    )

    system = (
        "You are a senior cybersecurity incident responder."
        " Assess the threat and produce a concise, actionable plan."
        f" {severity_rubric}"
        "\nAlways output these sections with clear headings exactly as written:"
        f" {', '.join(get_required_sections(simple))}."
        " Use numbered steps for actions. Keep guidance specific and tool-agnostic when possible."
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system),
        ("human", "Threat description: {threat}\n\nEnvironment/context: {context}\n\nRelevant knowledge (retrieved):\n{retrieved}"),
    ])

    parser = StrOutputParser()
    return prompt | llm | parser


def ensure_sections(text: str, *, simple: bool = False) -> str:
    """Best-effort cleanup without adding placeholders."""
    return (text or "").strip()


def assess_threat(chain, threat: str, context: str = "", retrieved: str = "", *, simple: bool = False) -> str:
    out = chain.invoke({"threat": threat.strip(), "context": context.strip(), "retrieved": retrieved})
    return ensure_sections(out, simple=simple)


def render_html_report(assessment: str, title: str = "Cyber Threat Assessment", *, simple: bool = False, iocs: Optional[Dict[str, List[str]]] = None) -> str:
    """Render a lightweight HTML report from the plain-text assessment."""
    import html

    # Parse into sections and bullets for action visualizations
    def split_sections(text: str) -> dict:
        sections: dict = {}
        current: Optional[str] = None
        for raw in text.splitlines():
            line = raw.strip("\n")
            if not line:
                if current is not None:
                    sections.setdefault(current, []).append("")
                continue
            if any(line.startswith(h + ":") or line == h for h in get_required_sections(simple)):
                current = line.replace(":", "").strip()
                sections.setdefault(current, [])
                continue
            if current is None:
                current = "Summary"
                sections.setdefault(current, [])
            sections[current].append(line)
        return sections

    def extract_bullets(lines: List[str]) -> List[str]:
        items: List[str] = []
        for l in lines:
            s = l.strip()
            if s.startswith("- "):
                items.append(s[2:].strip())
        return items

    sections = split_sections(assessment)

    action_section_names = ["Immediate Actions", "Recovery", "Preventive Measures"]
    actions_map = {name: extract_bullets(sections.get(name, [])) for name in action_section_names}

    # Basic formatting: convert section headers to <h2>, bullet lines to <li>
    lines = assessment.splitlines()
    html_parts: List[str] = []
    html_parts.append("<div class=\"report\">")
    current_list_open = False

    def close_list():
        nonlocal current_list_open
        if current_list_open:
            html_parts.append("</ul>")
            current_list_open = False

    for raw in lines:
        line = raw.strip("\n")
        if not line:
            close_list()
            html_parts.append("<br/>")
            continue
        if any(line.startswith(h + ":") or line == h for h in get_required_sections(simple)):
            close_list()
            header = line.replace(":", "").strip()
            html_parts.append(f"<h2>{html.escape(header)}</h2>")
            continue
        if line.startswith("- "):
            if not current_list_open:
                html_parts.append("<ul>")
                current_list_open = True
            html_parts.append(f"<li>{html.escape(line[2:])}</li>")
            continue
        # Default paragraph
        close_list()
        html_parts.append(f"<p>{html.escape(line)}</p>")

    close_list()
    html_parts.append("</div>")

    # Add IOC section if available
    ioc_section = ""
    if iocs:
        has_iocs = any(iocs.get(k) for k in ["ips", "domains", "hashes", "paths", "users"])
        if has_iocs:
            ioc_parts = ["<div class=\"ioc-section\"><h2>Indicators of Compromise (IOCs)</h2>"]
            ioc_parts.append("<pre class=\"ioc-json\">")
            ioc_parts.append(html.escape(format_iocs_json(iocs)))
            ioc_parts.append("</pre></div>")
            ioc_section = "".join(ioc_parts)

    # Steps visualization
    def render_steps() -> str:
        steps = actions_map.get("Immediate Actions", [])
        if not steps:
            return ""
        parts: List[str] = []
        parts.append("<div class=\"viz\"><h2>Immediate Actions - Steps</h2>")
        parts.append("<ol class=\"steps\">")
        for idx, s in enumerate(steps, 1):
            parts.append(f"<li><span class=\"badge\">{idx}</span> {html.escape(s)}</li>")
        parts.append("</ol></div>")
        return "".join(parts)

    def render_flow_svg() -> str:
        """Render a simple left-to-right flow: Immediate Actions -> Recovery -> Preventive Measures."""
        # Basic layout params
        col_width = 240
        row_height = 48
        node_w = 200
        node_h = 34
        padding_x = 30
        padding_y = 20

        columns = [
            ("Immediate Actions", actions_map.get("Immediate Actions", []) or ["None"]),
            ("Recovery", actions_map.get("Recovery", []) or ["None"]),
            ("Preventive Measures", actions_map.get("Preventive Measures", []) or ["None"]),
        ]

        # compute canvas size
        num_cols = len(columns)
        max_rows = max(len(items) for _, items in columns)
        width = padding_x * 2 + num_cols * col_width
        height = padding_y * 2 + max_rows * row_height + 80

        def node_x(col_idx: int) -> int:
            return padding_x + col_idx * col_width + (col_width - node_w) // 2

        def node_y(row_idx: int) -> int:
            return padding_y + row_idx * row_height

        svg_parts: List[str] = []
        # Responsive SVG: use viewBox and CSS width:100%; height:auto;
        svg_parts.append(f"<svg class=\"flow\" viewBox=\"0 0 {width} {height}\" preserveAspectRatio=\"xMidYMid meet\" xmlns=\"http://www.w3.org/2000/svg\">")
        svg_parts.append("<defs><marker id=arrow markerWidth=10 markerHeight=7 refX=10 refY=3.5 orient=auto>")
        svg_parts.append("<polygon points=\"0 0, 10 3.5, 0 7\" fill=\"#8ab4f8\"/></marker></defs>")

        # Draw nodes and titles
        for c_idx, (title_txt, items) in enumerate(columns):
            # Column title
            svg_parts.append(f"<text x=\"{node_x(c_idx)+node_w/2}\" y=\"{padding_y-6}\" fill=\"#8ab4f8\" font-size=\"14\" text-anchor=\"middle\">{html.escape(title_txt)}</text>")
            for r_idx, item in enumerate(items):
                x = node_x(c_idx)
                y = node_y(r_idx)
                svg_parts.append(f"<rect x=\"{x}\" y=\"{y}\" rx=\"6\" ry=\"6\" width=\"{node_w}\" height=\"{node_h}\" fill=\"#0b1219\" stroke=\"#2a3b4d\"/>")
                svg_parts.append(f"<text x=\"{x+10}\" y=\"{y+22}\" fill=\"#e6edf3\" font-size=\"12\">{html.escape(item[:60])}</text>")

        # Draw connectors between columns for first rows
        for c_idx in range(len(columns)-1):
            left_count = len(columns[c_idx][1])
            right_count = len(columns[c_idx+1][1])
            rows = min(left_count, right_count, 4)  # limit lines for readability
            for r_idx in range(rows):
                x1 = node_x(c_idx) + node_w
                y1 = node_y(r_idx) + node_h/2
                x2 = node_x(c_idx+1)
                y2 = node_y(min(r_idx, len(columns[c_idx+1][1])-1)) + node_h/2
                svg_parts.append(f"<line x1=\"{x1}\" y1=\"{y1}\" x2=\"{x2}\" y2=\"{y2}\" stroke=\"#8ab4f8\" stroke-width=\"1.5\" marker-end=\"url(#arrow)\"/>")

        svg_parts.append("</svg>")
        return "".join(svg_parts)

    # Place flow diagram before the textual report/summary; simplify visuals if requested
    visualizations = render_steps() if simple else (render_flow_svg() + render_steps())

    styles = (
        "<style>body{font-family:Inter,Segoe UI,Arial,sans-serif;background:#0b0f14;color:#e6edf3;"
        "padding:24px;} .container{max-width:920px;margin:0 auto;} h1{font-size:24px;margin:0 0 12px;}"
        "h2{font-size:18px;margin:20px 0 8px;color:#8ab4f8;} p,li{line-height:1.55;} ul{margin:6px 0 14px 20px;}"
        ".meta{color:#9aa4ad;font-size:12px;margin-bottom:18px;} .report{background:#11161d;border:1px solid #1f2a35;"
        "border-radius:8px;padding:18px;margin-bottom:18px;} .pending{color:#caa26a;} .viz{background:#0f141b;"
        "border:1px solid #1f2a35;border-radius:8px;padding:16px;margin-top:18px;} details{margin:6px 0;}"
        ".muted{color:#9aa4ad;} .steps{counter-reset:step;margin-left:0;padding-left:0;} .steps li{list-style:none;"
        "margin:10px 0;padding:10px;border-left:3px solid #2a3b4d;background:#0b1219;border-radius:4px;}"
        ".badge{display:inline-block;min-width:20px;padding:2px 6px;margin-right:8px;border-radius:999px;"
        "background:#8ab4f8;color:#0b0f14;font-weight:600;text-align:center;}"
        " .flow{display:block;width:100%;max-width:100%;height:auto;margin:0 0 18px 0;}"
        " .ioc-section{background:#0f141b;border:1px solid #1f2a35;border-radius:8px;padding:16px;margin-top:18px;}"
        " .ioc-json{background:#0b1219;border:1px solid #2a3b4d;border-radius:4px;padding:12px;overflow-x:auto;"
        "font-family:Consolas,Monaco,monospace;font-size:12px;line-height:1.4;color:#e6edf3;}"
        "</style>"
    )

    head = f"<head><meta charset=\"utf-8\"/><title>{html.escape(title)}</title>{styles}</head>"
    header = f"<h1>{html.escape(title)}</h1><div class=\"meta\">Generated by Cyber Agent with Vector RAG</div>"
    body = f"<div class=\"container\">{header}{visualizations}{''.join(html_parts)}{ioc_section}</div>"
    return f"<html>{head}<body>{body}</body></html>"


def save_html_if_requested(assessment: str, save_path: Optional[str], title: str = "Cyber Threat Assessment", *, simple: bool = False, iocs: Optional[Dict[str, List[str]]] = None) -> Optional[str]:
    """If save_path is provided, write an HTML report to a file."""
    if not save_path:
        return None
    html = render_html_report(assessment, title=title, simple=simple, iocs=iocs)
    path = pathlib.Path(save_path)
    if path.suffix.lower() != ".html":
        # Treat as directory
        path.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(ch for ch in title if ch.isalnum() or ch in ("-", "_", " ")).strip().replace(" ", "_")
        path = path / f"assessment_{safe_title}_{ts}.html"
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return str(path)


def save_iocs_if_requested(iocs: Dict[str, List[str]], save_path: Optional[str], title: str = "iocs") -> Optional[str]:
    """Save IOCs to JSON file if requested."""
    if not save_path or not iocs:
        return None
    
    has_iocs = any(iocs.get(k) for k in ["ips", "domains", "hashes", "paths", "users"])
    if not has_iocs:
        return None
    
    path = pathlib.Path(save_path)
    if path.suffix.lower() != ".json":
        # Treat as directory
        path.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(ch for ch in title if ch.isalnum() or ch in ("-", "_", " ")).strip().replace(" ", "_")
        path = path / f"iocs_{safe_title}_{ts}.json"
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    
    path.write_text(format_iocs_json(iocs), encoding="utf-8")
    return str(path)


def log_feedback(feedback_log: str, threat: str, assessment: str, feedback: str = "", rating: Optional[int] = None):
    """Append feedback entry to JSONL log."""
    if not feedback_log:
        return
    
    log_path = pathlib.Path(feedback_log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "threat": threat,
        "assessment": assessment,
        "feedback": feedback,
        "rating": rating
    }
    
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def interactive_loop(chain, vector_rag: VectorRAG, save_html: Optional[str] = None, *, simple: bool = False, enable_ioc: bool = False, save_iocs: Optional[str] = None, feedback_log: Optional[str] = None):
    print("Cyber Threat Assessment Agent with Vector RAG")
    if enable_ioc:
        print("IOC extraction enabled")
    if feedback_log:
        print(f"Feedback logging to: {feedback_log}")
    print("Type 'exit' to quit.\n")
    while True:
        try:
            threat = input("Threat> ").strip()
            if not threat:
                continue
            if threat.lower() in {"exit", "quit"}:
                break
            context = input("Context (optional)> ").strip()
            print("\nAssessing with vector RAG...\n")
            retrieved = vector_rag.retrieve_context(threat, context)
            result = assess_threat(chain, threat, context, retrieved, simple=simple)
            print(result)
            
            # Extract IOCs if enabled
            iocs = None
            if enable_ioc:
                iocs = extract_iocs(result)
                if any(iocs.get(k) for k in ["ips", "domains", "hashes", "paths", "users"]):
                    print("\n--- IOCs Extracted ---")
                    print(iocs_to_text(iocs))
                    
                    # Save IOCs if requested
                    ioc_saved = save_iocs_if_requested(iocs, save_iocs, title=(threat[:40] or "iocs"))
                    if ioc_saved:
                        print(f"Saved IOCs to: {ioc_saved}")
            
            # Save HTML report
            saved = save_html_if_requested(result, save_html, title=(threat[:80] or "Assessment"), simple=simple, iocs=iocs)
            if saved:
                print(f"\nSaved HTML report to: {saved}")
            
            # Prompt for feedback if logging enabled
            if feedback_log:
                fb = input("\nFeedback (optional, press Enter to skip)> ").strip()
                rating_input = input("Rating 1-5 (optional, press Enter to skip)> ").strip()
                rating = int(rating_input) if rating_input.isdigit() and 1 <= int(rating_input) <= 5 else None
                log_feedback(feedback_log, threat, result, fb, rating)
                print("Feedback logged.")
            
            print("\n---\n")
        except (EOFError, KeyboardInterrupt):
            print()
            break


def parse_args(argv: List[str]):
    parser = argparse.ArgumentParser(description="Cyber Threat Assessment Agent with Vector RAG")
    parser.add_argument("--threat", type=str, default="", help="Threat description to assess")
    parser.add_argument("--context", type=str, default="", help="Optional environment/context")
    parser.add_argument("--model_path", type=str, default="./output/cyberllm_sft_model", help="Path to local model")
    parser.add_argument("--device", type=str, default="auto", help="Device map for model loading (e.g., 'auto')")
    parser.add_argument("--kb_path", type=str, default="./HF_Space/knowledge_base", help="Path to local KB (.md/.txt files)")
    parser.add_argument("--save_html", type=str, default="", help="Path to save HTML report (file or directory)")
    parser.add_argument("--simple", action="store_true", help="Simplified sections: Severity, Immediate Actions, Recovery, Preventive Measures")
    parser.add_argument("--vector_model", type=str, default="all-MiniLM-L6-v2", help="Sentence transformer model for vector RAG")
    parser.add_argument("--enable_ioc", action="store_true", help="Extract IOCs (Indicators of Compromise) from assessment")
    parser.add_argument("--save_iocs", type=str, default="", help="Path to save IOC JSON (file or directory)")
    parser.add_argument("--feedback_log", type=str, default="", help="Path to JSONL file for logging feedback")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    
    print("Loading fine-tuned model...")
    llm = build_llm(model_path=args.model_path, device=args.device)
    chain = build_chain(llm, simple=args.simple)
    
    print("Initializing vector RAG...")
    vector_rag = create_vector_rag(kb_path=args.kb_path, model_name=args.vector_model)

    if args.threat:
        print("Retrieving relevant context...")
        retrieved = vector_rag.retrieve_context(args.threat, args.context)
        output = assess_threat(chain, args.threat, args.context, retrieved, simple=args.simple)
        print(output)
        
        # Extract IOCs if enabled
        iocs = None
        if args.enable_ioc:
            iocs = extract_iocs(output)
            if any(iocs.get(k) for k in ["ips", "domains", "hashes", "paths", "users"]):
                print("\n--- IOCs Extracted ---")
                print(iocs_to_text(iocs))
                
                # Save IOCs if requested
                ioc_saved = save_iocs_if_requested(iocs, args.save_iocs or None, title=(args.threat[:40] or "iocs"))
                if ioc_saved:
                    print(f"Saved IOCs to: {ioc_saved}")
        
        # Save HTML report
        saved = save_html_if_requested(output, args.save_html or None, title=(args.threat[:80] or "Assessment"), simple=args.simple, iocs=iocs)
        if saved:
            print(f"\nSaved HTML report to: {saved}")
        
        # Log feedback if requested (non-interactive, can be extended later)
        if args.feedback_log:
            log_feedback(args.feedback_log, args.threat, output)
            print(f"Assessment logged to: {args.feedback_log}")
    else:
        interactive_loop(
            chain, 
            vector_rag, 
            save_html=(args.save_html or None), 
            simple=args.simple,
            enable_ioc=args.enable_ioc,
            save_iocs=(args.save_iocs or None),
            feedback_log=(args.feedback_log or None)
        )


if __name__ == "__main__":
    main()
