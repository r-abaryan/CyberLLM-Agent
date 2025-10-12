"""
Gradio UI for Cyber Threat Assessment (HF Space)

Standalone app that uses a fine-tuned cybersecurity LLM to assess threats
and provide structured incident response recommendations.
"""

import os
from typing import List, Tuple, Optional

import gradio as gr
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_huggingface import HuggingFacePipeline


# Configuration
MODEL_PATH = "abaryan/CyberXP_Agent_Llama_3.2_1B"
# MODEL_PATH = "./cyberllm_sft_model"

REQUIRED_SECTIONS_SIMPLE = [
    "Severity",
    "Immediate Actions",
    "Recovery",
    "Preventive Measures",
]


def build_llm(model_path: str = MODEL_PATH) -> HuggingFacePipeline:
    """Load and configure the fine-tuned cybersecurity model."""
    tokenizer = AutoTokenizer.from_pretrained(model_path, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
        device_map="auto",
    )

    pipe = pipeline(
        task="text-generation",
        model=model,
        tokenizer=tokenizer,
        return_full_text=False,
        max_new_tokens=512,
        temperature=0.7,
        top_p=0.9,
        repetition_penalty=1.1,
        eos_token_id=tokenizer.eos_token_id,
        pad_token_id=tokenizer.eos_token_id,
    )

    return HuggingFacePipeline(pipeline=pipe)


def build_chain(llm: HuggingFacePipeline):
    """Create LangChain prompt chain with few-shot example."""
    severity_rubric = (
        "Severity rubric:\n"
        "- Low: Contained, minimal business impact\n"
        "- Medium: Limited spread, moderate remediation effort\n"
        "- High: Active compromise likely, material impact\n"
        "- Critical: Widespread compromise, immediate escalation needed"
    )

    system_prompt = (
        "You are a senior cybersecurity incident responder. "
        "Assess threats and produce concise, actionable plans.\n\n"
        f"{severity_rubric}\n\n"
        f"Always output these sections: {', '.join(REQUIRED_SECTIONS_SIMPLE)}.\n"
        "Use bullet points (starting with '-') for action items."
    )
    
    # Few-shot example for consistent formatting
    example_assessment = """Severity
Medium - Limited scope but requires prompt containment.

Immediate Actions
- Isolate affected workstation from network
- Collect PowerShell logs and command history
- Review file modifications and network connections
- Scan downloaded files with antivirus
- Check for lateral movement indicators

Recovery
- Wipe and reimage the affected system
- Reset credentials for affected accounts
- Verify no persistence mechanisms remain
- Restore data from clean backup

Preventive Measures
- Enable PowerShell logging and monitoring
- Implement application whitelisting
- Deploy endpoint detection and response (EDR)
- Conduct security awareness training"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Threat: Suspicious executable downloaded\n\nContext: Corporate network, Windows 10"),
        ("assistant", example_assessment),
        ("human", "Threat: {threat}\n\nContext: {context}"),
    ])

    return prompt | llm | StrOutputParser()


def render_html_report(assessment: str, title: str = "Threat Assessment") -> str:
    """Convert plain text assessment to styled HTML with flow diagram."""
    import html
    
    # Parse sections
    def parse_sections(text: str) -> dict:
        sections = {}
        current_section = None
        
        section_names = {
            'severity': 'Severity',
            'immediate actions': 'Immediate Actions',
            'actions': 'Immediate Actions',
            'recovery': 'Recovery',
            'preventive measures': 'Preventive Measures',
            'prevention': 'Preventive Measures',
        }
        
        for line in text.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Check if line is a section heading
            line_lower = line.lower().rstrip(':')
            if line_lower in section_names:
                current_section = section_names[line_lower]
                sections[current_section] = []
            elif current_section:
                sections[current_section].append(line)
        
        return sections
    
    # Extract bullet points for visualization
    def extract_bullets(lines: List[str]) -> List[str]:
        bullets = []
        for line in lines:
            if line.startswith('- '):
                bullets.append(line[2:].strip())
            elif line.startswith('• '):
                bullets.append(line[2:].strip())
            elif len(line) > 2 and line[0].isdigit() and line[1:3] in ('. ', ') '):
                bullets.append(line[3:].strip())
        return bullets
    
    sections = parse_sections(assessment)
    actions_map = {name: extract_bullets(sections.get(name, [])) for name in REQUIRED_SECTIONS_SIMPLE[1:]}
    
    # Build HTML content
    html_parts = ['<div class="report">']
    
    for line in assessment.split('\n'):
        line = line.strip()
        if not line:
            html_parts.append('<br/>')
            continue
        
        # Check if section heading
        if any(line.lower().startswith(s.lower()) for s in REQUIRED_SECTIONS_SIMPLE):
            html_parts.append(f'<h2>{html.escape(line.rstrip(":"))}</h2>')
        elif line.startswith('- '):
            html_parts.append(f'<li>{html.escape(line[2:])}</li>')
        else:
            html_parts.append(f'<p>{html.escape(line)}</p>')
    
    html_parts.append('</div>')
    
    # Simple flow diagram
    flow_svg = render_flow_diagram(actions_map)
    
    # Styles
    styles = """
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0b0f14; color: #e6edf3; padding: 24px; }
        .container { max-width: 920px; margin: 0 auto; }
        h1 { font-size: 24px; margin: 0 0 12px; }
        h2 { font-size: 18px; margin: 20px 0 8px; color: #8ab4f8; }
        p, li { line-height: 1.6; }
        li { margin-left: 20px; }
        .meta { color: #9aa4ad; font-size: 12px; margin-bottom: 18px; }
        .report { background: #11161d; border: 1px solid #1f2a35; border-radius: 8px; padding: 18px; margin-bottom: 18px; }
        .flow { display: block; width: 100%; height: auto; margin: 0 0 18px 0; }
    </style>
    """
    
    header = f'<h1>{html.escape(title)}</h1><div class="meta">Generated by Cyber Threat Assessment Agent</div>'
    body = f'<div class="container">{header}{flow_svg}{"".join(html_parts)}</div>'
    
    return f'<html><head><meta charset="utf-8"/><title>{html.escape(title)}</title>{styles}</head><body>{body}</body></html>'


def render_flow_diagram(actions_map: dict) -> str:
    """Create SVG flow diagram of incident response stages."""
    import html
    
    col_width, row_height = 240, 48
    node_w, node_h = 200, 34
    padding_x, padding_y = 30, 20
    
    columns = [
        ("Assess", ["Assess threat context"]),
        ("Gather Info", ["Collect logs, IOCs, scope"]),
        ("Immediate Actions", actions_map.get("Immediate Actions", []) or ["None"]),
        ("Recovery", actions_map.get("Recovery", []) or ["None"]),
        ("Preventive Measures", actions_map.get("Preventive Measures", []) or ["None"]),
    ]
    
    num_cols = len(columns)
    max_rows = max(len(items) for _, items in columns)
    width = padding_x * 2 + num_cols * col_width
    height = padding_y * 2 + max_rows * row_height + 80
    
    def node_x(col_idx: int) -> int:
        return padding_x + col_idx * col_width + (col_width - node_w) // 2
    
    def node_y(row_idx: int) -> int:
        return padding_y + row_idx * row_height
    
    svg_parts = [f'<svg class="flow" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">']
    svg_parts.append('<defs><marker id="arrow" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">')
    svg_parts.append('<polygon points="0 0, 10 3.5, 0 7" fill="#8ab4f8"/></marker></defs>')
    
    # Draw nodes
    for c_idx, (title, items) in enumerate(columns):
        # Column title
        svg_parts.append(f'<text x="{node_x(c_idx)+node_w/2}" y="{padding_y-6}" fill="#8ab4f8" font-size="14" text-anchor="middle">{html.escape(title)}</text>')
        
        # Nodes
        for r_idx, item in enumerate(items):
            x, y = node_x(c_idx), node_y(r_idx)
            display_text = item[:40] + "..." if len(item) > 40 else item
            svg_parts.append(f'<rect x="{x}" y="{y}" rx="6" ry="6" width="{node_w}" height="{node_h}" fill="#0b1219" stroke="#2a3b4d"/>')
            svg_parts.append(f'<text x="{x+10}" y="{y+22}" fill="#e6edf3" font-size="11">{html.escape(display_text)}</text>')
    
    # Draw connecting arrows
    for c_idx in range(len(columns)-1):
        left_count = len(columns[c_idx][1])
        right_count = len(columns[c_idx+1][1])
        rows = min(left_count, right_count, 4)
        
        for r_idx in range(rows):
            x1 = node_x(c_idx) + node_w
            y1 = node_y(r_idx) + node_h/2
            x2 = node_x(c_idx+1)
            y2 = node_y(min(r_idx, right_count-1)) + node_h/2
            svg_parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#8ab4f8" stroke-width="1.5" marker-end="url(#arrow)"/>')
    
    svg_parts.append('</svg>')
    return ''.join(svg_parts)


# Initialize model and chain
print("Loading cybersecurity model...")
llm = build_llm()
chain = build_chain(llm)
print("Model loaded successfully!")


def assess_threat(threat: str, context: str) -> Tuple[str, str]:
    """Run threat assessment and return text + HTML."""
    if not threat.strip():
        return "Please provide a threat description.", "<p>No assessment generated.</p>"
    
    # Run assessment
    result = chain.invoke({
        "threat": threat.strip(),
        "context": context.strip() or "No additional context provided"
    })
    
    # Generate HTML report
    html_report = render_html_report(result.strip(), title=threat[:60] or "Threat Assessment")
    
    return result.strip(), html_report


# Gradio UI
with gr.Blocks(title="Cyber Threat Assessment", theme=gr.themes.Soft(primary_hue="blue")) as demo:
    gr.Markdown("# 🛡️ Cyber Threat Assessment Agent")
    gr.Markdown("Describe a cybersecurity threat to receive a structured assessment with severity analysis and actionable recommendations.")
    
    with gr.Row():
        threat_input = gr.Textbox(
            label="Threat Description",
            lines=5,
            placeholder="Example: Instagram account compromised, unauthorized login from unknown IP address..."
        )
        context_input = gr.Textbox(
            label="Context / Environment",
            lines=5,
            placeholder="Example: Personal account, Windows 10, received password reset emails, suspicious activity from Eastern Europe..."
        )
    
    assess_btn = gr.Button("Assess Threat", variant="primary", size="lg")
    
    html_output = gr.HTML(label="Assessment Report")
    text_output = gr.Textbox(label="Raw Assessment Text", lines=20)
    
    assess_btn.click(
        fn=assess_threat,
        inputs=[threat_input, context_input],
        outputs=[text_output, html_output]
    )
    
    # Examples
    gr.Examples(
        examples=[
            ["Instagram account hacked with unauthorized logins", "Personal account, multiple password reset emails received"],
            ["Suspicious PowerShell script execution detected", "Corporate Windows 10 workstation, EDR alert triggered"],
            ["Phishing email with malicious attachment received", "Office 365 environment, attachment not yet opened"],
        ],
        inputs=[threat_input, context_input]
    )


if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
