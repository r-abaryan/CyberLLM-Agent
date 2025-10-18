"""
Collaborative Multi-Agent Gradio Interface
Triage + Analysis agents work together in a pipeline
"""

import os
import sys
from typing import Tuple, Optional, Dict, List
import json
import datetime
import pathlib

import gradio as gr
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from langchain_huggingface import HuggingFacePipeline
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from rag.vector_rag import create_vector_rag
from utils.ioc_utils import extract_iocs, format_iocs_json, iocs_to_text
from agents import CustomAgent, AgentManager


# Configuration
MODEL_PATH = "abaryan/CyberXP_Agent_Llama_3.2_1B"

REQUIRED_SECTIONS = [
    "Severity",
    "Immediate Actions",
    "Recovery",
    "Preventive Measures",
]


def build_llm(model_path: str = MODEL_PATH) -> HuggingFacePipeline:
    """Load and configure the fine-tuned model"""
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


def build_chain(llm: HuggingFacePipeline, stage: str = "triage"):
    """Create LangChain prompt chain with few-shot example for specific stage."""
    severity_rubric = (
        "Severity rubric:\n"
        "- Low: Contained, minimal business impact\n"
        "- Medium: Limited spread, moderate remediation effort\n"
        "- High: Active compromise likely, material impact\n"
        "- Critical: Widespread compromise, immediate escalation needed"
    )

    if stage == "triage":
        system_prompt = (
            "You are a senior cybersecurity incident responder performing TRIAGE. "
            "Focus on RAPID assessment and IMMEDIATE containment.\n\n"
            f"{severity_rubric}\n\n"
            f"Always output these sections: {', '.join(REQUIRED_SECTIONS)}.\n"
            "For Immediate Actions: ONLY urgent first-response (isolate, block, disable). NO patching, NO analysis.\n"
            "For Recovery: ONLY brief initial steps (backup, snapshot). NO restoration, NO validation.\n"
            "For Preventive Measures: ONLY quick wins (enable logging, emergency patches). NO long-term policies.\n"
            "AVOID REDUNDANCY: Each action appears in ONE section only. Be concise. Max 3-4 items per section."
        )
    else:  # analysis
        system_prompt = (
            "You are a senior cybersecurity incident responder performing ANALYSIS. "
            "Focus on DETAILED investigation and RECOVERY planning.\n\n"
            f"{severity_rubric}\n\n"
            f"Always output these sections: {', '.join(REQUIRED_SECTIONS)}.\n"
            "For Immediate Actions: ONLY investigation (collect logs, analyze IOCs, document timeline). NO isolation, NO blocking.\n"
            "For Recovery: ONLY restoration and validation (wipe/reimage, restore data, verify integrity). NO prevention.\n"
            "For Preventive Measures: ONLY long-term improvements (policy changes, architecture, training). NO immediate fixes.\n"
            "AVOID REDUNDANCY: Each action appears in ONE section only. Be thorough. Max 5 items per section."
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


# Initialize system
print("Loading model...")
llm = build_llm()
print("Model loaded!")

print("Building assessment chains...")
triage_chain = build_chain(llm, stage="triage")
analysis_chain = build_chain(llm, stage="analysis")
print("Chains built!")

print("Initializing Vector RAG...")
vector_rag = create_vector_rag(kb_path="./knowledge_base", model_name="all-MiniLM-L6-v2")
print("Vector RAG ready!")

print("Initializing agent manager...")
agent_manager = AgentManager(storage_dir="custom_agents")
print("Agent manager ready!")


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
        svg_parts.append(f'<text x="{node_x(c_idx)+node_w/2}" y="{padding_y-6}" fill="#8ab4f8" font-size="14" text-anchor="middle">{html.escape(title)}</text>')
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


def render_stage_html(stage_title: str, assessment: str, stage_num: int, iocs: Optional[Dict[str, List[str]]] = None) -> str:
    """Render a single stage output as structured HTML (no SVG)."""
    import html
    
    # Build HTML content with proper list handling
    html_parts = ['<div class="report">']
    in_list = False
    
    for line in assessment.split('\n'):
        line = line.strip()
        if not line:
            if in_list:
                html_parts.append('</ul>')
                in_list = False
            html_parts.append('<br/>')
            continue
        
        # Check if it's a section header
        if any(line.lower().startswith(s.lower()) for s in REQUIRED_SECTIONS):
            if in_list:
                html_parts.append('</ul>')
                in_list = False
            html_parts.append(f'<h2>{html.escape(line.rstrip(":"))}</h2>')
        # Check if it's a bullet point
        elif line.startswith('- '):
            if not in_list:
                html_parts.append('<ul>')
                in_list = True
            html_parts.append(f'<li>{html.escape(line[2:])}</li>')
        else:
            if in_list:
                html_parts.append('</ul>')
                in_list = False
            html_parts.append(f'<p>{html.escape(line)}</p>')
    
    if in_list:
        html_parts.append('</ul>')
    
    html_parts.append('</div>')
    
    # IOC section (only for analysis stage)
    ioc_section = ""
    if iocs and any(iocs.get(k) for k in ["ips", "domains", "hashes", "paths", "users"]):
        ioc_json = format_iocs_json(iocs)
        ioc_section = f'<div class="ioc-section"><h2>Indicators of Compromise</h2><pre class="ioc-json">{html.escape(ioc_json)}</pre></div>'
    
    styles = """<style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0b0f14; color: #e6edf3; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        .stage-badge { display: inline-block; background: #1f2a35; padding: 4px 10px; border-radius: 4px; 
                       font-size: 11px; color: #9aa4ad; margin-bottom: 8px; font-weight: 500; }
        h1 { font-size: 20px; margin: 0 0 12px; color: #e6edf3; font-weight: 600; }
        h2 { font-size: 16px; margin: 16px 0 8px 0; color: #8ab4f8; font-weight: 600; }
        p, li { line-height: 1.6; font-size: 14px; }
        li { margin-left: 20px; }
        .report { background: #11161d; border: 1px solid #1f2a35; border-radius: 6px; padding: 16px; margin-bottom: 16px; }
        .ioc-section { background: #0f141b; border: 1px solid #1f2a35; border-radius: 6px; padding: 14px; margin-top: 16px; }
        .ioc-json { background: #0b1219; border: 1px solid #2a3b4d; border-radius: 4px; padding: 10px; overflow-x: auto; 
                    font-family: Consolas, Monaco, monospace; font-size: 12px; line-height: 1.4; color: #e6edf3; }
    </style>"""
    
    stage_badge = f'<div class="stage-badge">Stage {stage_num}</div>'
    header = f'{stage_badge}<h1>{html.escape(stage_title)}</h1>'
    body = f'<div class="container">{header}{"".join(html_parts)}{ioc_section}</div>'
    
    return f'<html><head><meta charset="utf-8"/><title>{html.escape(stage_title)}</title>{styles}</head><body>{body}</body></html>'


def render_combined_html(triage_output: str, analysis_output: str, threat: str, iocs: dict = None) -> str:
    """Render combined report with both stages in structured HTML with SVG flow diagram."""
    import html
    
    # Parse sections from analysis for SVG flow diagram
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
                
            line_lower = line.lower().rstrip(':')
            if line_lower in section_names:
                current_section = section_names[line_lower]
                sections[current_section] = []
            elif current_section:
                sections[current_section].append(line)
        
        return sections
    
    def extract_bullets(lines: List[str]) -> List[str]:
        bullets = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('- '):
                bullets.append(stripped[2:].strip())
            elif stripped.startswith('• '):
                bullets.append(stripped[2:].strip())
            elif stripped.startswith('* '):
                bullets.append(stripped[2:].strip())
            elif len(stripped) > 2 and stripped[0].isdigit() and stripped[1:3] in ('. ', ') '):
                bullets.append(stripped[3:].strip())
            elif stripped and not any(stripped.lower().startswith(s.lower()) for s in REQUIRED_SECTIONS):
                # If it's just text content under a section (not a header), treat it as a bullet
                bullets.append(stripped)
        return bullets
    
    # Build HTML for each stage
    def build_stage_html(output: str, stage_name: str) -> str:
        html_parts = []
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                html_parts.append('<br/>')
                continue
            
            if any(line.lower().startswith(s.lower()) for s in REQUIRED_SECTIONS):
                html_parts.append(f'<h2>{html.escape(line.rstrip(":"))}</h2>')
            elif line.startswith('- '):
                html_parts.append(f'<li>{html.escape(line[2:])}</li>')
            else:
                html_parts.append(f'<p>{html.escape(line)}</p>')
        return ''.join(html_parts)
    
    # Parse BOTH outputs for flow diagram to get all action items
    triage_sections = parse_sections(triage_output)
    analysis_sections = parse_sections(analysis_output)
    
    # Combine bullets from both stages for a comprehensive flow diagram
    actions_map = {}
    for name in REQUIRED_SECTIONS[1:]:
        triage_bullets = extract_bullets(triage_sections.get(name, []))
        analysis_bullets = extract_bullets(analysis_sections.get(name, []))
        # Combine and deduplicate
        combined = triage_bullets + [b for b in analysis_bullets if b not in triage_bullets]
        actions_map[name] = combined[:5]  # Limit to 5 items for clean SVG
    
    # Generate SVG flow diagram
    flow_svg = render_flow_diagram(actions_map)
    
    triage_content = build_stage_html(triage_output, "Stage 1")
    analysis_content = build_stage_html(analysis_output, "Stage 2")
    
    # IOCs
    ioc_section = ""
    if iocs and any(iocs.get(k) for k in ["ips", "domains", "hashes", "paths", "users"]):
        ioc_json = format_iocs_json(iocs)
        ioc_section = f'<div class="ioc-section"><h2>Extracted IOCs</h2><pre class="ioc-json">{html.escape(ioc_json)}</pre></div>'
    
    styles = """<style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0b0f14; color: #e6edf3; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { font-size: 22px; margin: 0 0 6px; color: #e6edf3; font-weight: 600; }
        .meta { color: #9aa4ad; font-size: 11px; margin-bottom: 20px; }
        .flow { display: block; width: 100%; height: auto; margin: 0 0 20px 0; }
        .stage-container { margin-bottom: 20px; background: #11161d; border: 1px solid #1f2a35; border-radius: 6px; padding: 16px; }
        .stage-header { font-size: 16px; font-weight: 600; color: #8ab4f8; margin-bottom: 12px; 
                        padding-bottom: 8px; border-bottom: 1px solid #1f2a35; }
        h2 { font-size: 15px; margin: 16px 0 8px 0; color: #8ab4f8; font-weight: 600; }
        p, li { line-height: 1.6; font-size: 14px; }
        li { margin-left: 20px; }
        .ioc-section { background: #0f141b; border: 1px solid #1f2a35; border-radius: 6px; padding: 14px; margin-top: 20px; }
        .ioc-json { background: #0b1219; border: 1px solid #2a3b4d; border-radius: 4px; padding: 10px; overflow-x: auto; 
                    font-family: Consolas, Monaco, monospace; font-size: 12px; line-height: 1.4; color: #e6edf3; margin: 8px 0 0 0; }
    </style>"""
    
    header = f'<h1>Collaborative Threat Assessment</h1><div class="meta">Two-Stage Pipeline: Triage → Analysis</div>'
    
    stage1 = f'<div class="stage-container"><div class="stage-header">Stage 1: Triage & Containment</div>{triage_content}</div>'
    stage2 = f'<div class="stage-container"><div class="stage-header">Stage 2: Analysis & Recovery</div>{analysis_content}</div>'
    
    body = f'<div class="container">{header}{flow_svg}{stage1}{stage2}{ioc_section}</div>'
    
    return f'<html><head><meta charset="utf-8"/><title>Collaborative Assessment</title>{styles}</head><body>{body}</body></html>'


def collaborative_assessment(threat: str, context: str, custom_agents: List[str], enable_ioc: bool = True) -> Tuple[str, str, str, str, str]:
    """
    Run collaborative multi-agent assessment using structured chains or custom agents
    Returns: triage_html, analysis_html, combined_html, iocs, status
    """
    if not threat.strip():
        empty = "<p>Please provide a threat description.</p>"
        return empty, empty, empty, "", "Ready"
    
    # Retrieve knowledge
    retrieved_context = vector_rag.retrieve_context(threat, context)
    full_context = f"{context.strip() or 'No additional context provided'}\n\nRelevant Knowledge:\n{retrieved_context}"
    
    # Run built-in Triage + Analysis first
    triage_output = triage_chain.invoke({
        "threat": threat.strip(),
        "context": full_context
    })
    
    analysis_output = analysis_chain.invoke({
        "threat": threat.strip(),
        "context": full_context
    })
    
    # Check if custom agents are also selected
    if custom_agents and len(custom_agents) > 0:
        # Run custom agents in addition to built-in
        custom_outputs = []
        
        for custom_agent_name in custom_agents:
            agent = agent_manager.load_agent(custom_agent_name, llm=llm)
            if agent:
                result_dict = agent.process(threat.strip(), context=full_context)
                custom_output = result_dict.get("assessment", "")
                custom_outputs.append({
                    "name": custom_agent_name,
                    "output": custom_output
                })
            else:
                custom_outputs.append({
                    "name": custom_agent_name,
                    "output": f"Error: Could not load agent '{custom_agent_name}'"
                })
        
        # Build combined output with built-in + custom agents
        combined_text = triage_output + "\n\n" + analysis_output
        for custom in custom_outputs:
            combined_text += "\n\n" + custom["output"]
        
        # Extract IOCs from all outputs
        iocs = None
        ioc_text = ""
        if enable_ioc:
            iocs = extract_iocs(combined_text)
            if any(iocs.get(k) for k in ["ips", "domains", "hashes", "paths", "users"]):
                ioc_text = iocs_to_text(iocs)
        
        # Render HTML reports with custom agents appended
        combined_html = render_combined_html(triage_output, analysis_output, threat, iocs)
        
        # Add custom agent outputs to combined view
        custom_agent_html = """
        <div style='margin-top: 50px; padding-top: 30px; border-top: 4px solid #ffa500;'>
            <h1 style='color: #ffa500; text-align: center; margin-bottom: 30px;'>
                📊 Custom Agent Assessments
            </h1>
        """
        
        for idx, custom in enumerate(custom_outputs):
            custom_agent_html += f"""
            <div class='report' style='margin-top: 25px; border-left: 5px solid #ffa500; padding: 20px; background: #1a1f26; border-radius: 8px;'>
                <h2 style='color: #ffa500; font-size: 22px; margin-bottom: 15px;'>
                    🤖 Custom Agent {idx + 1}: {custom['name']}
                </h2>
                <pre style='white-space: pre-wrap; font-size: 14px; line-height: 1.6;'>{custom['output']}</pre>
            </div>
            """
        
        custom_agent_html += "</div>"
        
        # Insert custom agents before closing tags
        combined_html = combined_html.replace("</body></html>", f"{custom_agent_html}</body></html>")
        
        triage_html = render_stage_html("Triage & Containment", triage_output, 1, None)
        analysis_html = render_stage_html("Analysis & Recovery", analysis_output, 2, iocs)
        
        status = f"Triage + Analysis + Custom Agents: {', '.join([c['name'] for c in custom_outputs])} ({2 + len(custom_outputs)} agents)"
        
        return triage_html, analysis_html, combined_html, ioc_text, status
    
    # No custom agents - use standard Triage + Analysis output (already computed above)
    
    # Extract IOCs
    iocs = None
    ioc_text = ""
    if enable_ioc:
        iocs = extract_iocs(analysis_output)
        if any(iocs.get(k) for k in ["ips", "domains", "hashes", "paths", "users"]):
            ioc_text = iocs_to_text(iocs)
    
    # Render HTML reports with SVG
    combined_html = render_combined_html(triage_output, analysis_output, threat, iocs)
    triage_html = render_stage_html("Triage & Containment", triage_output, 1, None)
    analysis_html = render_stage_html("Analysis & Recovery", analysis_output, 2, iocs)
    
    status = "Assessment Complete: Triage + Analysis"
    
    return triage_html, analysis_html, combined_html, ioc_text, status


def create_custom_agent_handler(name: str, role: str, prompt: str) -> Tuple[str, gr.update]:
    """Create a custom agent"""
    try:
        if not name or not role or not prompt:
            return "⚠️ Please fill in all fields", gr.update()
        
        if agent_manager.agent_exists(name):
            return f"⚠️ Agent '{name}' already exists", gr.update()
        
        agent = CustomAgent(
            name=name.strip(),
            role=role.strip(),
            system_prompt=prompt.strip(),
            llm=llm
        )
        
        success = agent_manager.save_agent(agent)
        if success:
            # Refresh dropdown with new agent list
            updated_choices = [agent["name"] for agent in agent_manager.list_agents()]
            return f"✅ Agent '{name}' created successfully!", gr.update(choices=updated_choices)
        else:
            return "❌ Failed to save agent", gr.update()
    
    except ValueError as e:
        return f"❌ Validation error: {str(e)}", gr.update()
    except Exception as e:
        return f"❌ Error: {str(e)}", gr.update()


def log_feedback(threat: str, assessment: str, feedback: str, rating: Optional[int] = None):
    """Log feedback to JSONL"""
    feedback_dir = pathlib.Path("./feedback_logs")
    feedback_dir.mkdir(exist_ok=True)
    log_file = feedback_dir / "feedback_collaborative.jsonl"
    
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "threat": threat,
        "assessment": assessment,
        "feedback": feedback,
        "rating": rating,
        "mode": "collaborative"
    }
    
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def submit_feedback(threat: str, assessment: str, feedback: str, rating: Optional[float] = None) -> str:
    """Handle feedback submission"""
    if not feedback.strip() and rating is None:
        return "Please provide feedback or a rating."
    
    rating_int = int(rating) if rating else None
    log_feedback(threat, assessment, feedback.strip(), rating_int)
    
    return "Thank you! Feedback recorded."


# Gradio Interface
with gr.Blocks(title="Collaborative Multi-Agent Assessment", theme=gr.themes.Soft(primary_hue="blue")) as demo:
    gr.Markdown("# Collaborative Multi-Agent Threat Assessment")
    gr.Markdown("Two specialized agents work together: **Triage** assesses severity and containment, then **Analysis** provides deep investigation and recovery steps.")
    
    # State
    current_threat = gr.State("")
    current_assessment = gr.State("")
    
    with gr.Row():
        threat_input = gr.Textbox(
            label="Threat Description",
            lines=5,
            placeholder="Example: Ransomware detected encrypting files on file server"
        )
        context_input = gr.Textbox(
            label="Context / Environment",
            lines=5,
            placeholder="Example: Production environment, 50 workstations affected"
        )
    
    with gr.Row():
        with gr.Column(scale=1):
            enable_ioc = gr.Checkbox(label="Extract IOCs", value=True)
        with gr.Column(scale=3):
            custom_agent_selector = gr.Dropdown(
                choices=[agent["name"] for agent in agent_manager.list_agents()],
                value=[],
                label="Custom Agents (Multi-Select)",
                info="Select one or more custom agents to run in sequence, or leave blank for built-in Triage + Analysis",
                multiselect=True,
                interactive=True
            )
    
    with gr.Row():
        assess_btn = gr.Button("Run Assessment", variant="primary", size="lg")
    
    status_text = gr.Markdown("**Status:** Ready")
    
    with gr.Tabs():
        with gr.Tab("Combined Report"):
            combined_output = gr.HTML(
                label="Full Assessment (Both Agents)"
            )
        
        with gr.Tab("Stage 1: Triage"):
            triage_output = gr.HTML(
                label="Triage & Containment Agent"
            )
        
        with gr.Tab("Stage 2: Analysis"):
            analysis_output = gr.HTML(
                label="Analysis & Recovery Agent"
            )
        
        with gr.Tab("Extracted IOCs"):
            ioc_output = gr.Textbox(
                label="Indicators of Compromise",
                lines=12,
                placeholder="IOCs will appear here..."
            )
    
    # Custom Agent Creation
    gr.Markdown("---")
    gr.Markdown("### Create Custom Agent")
    gr.Markdown("Create a specialized agent with custom behavior and focus areas.")
    
    with gr.Row():
        custom_agent_name = gr.Textbox(
            label="Agent Name",
            placeholder="e.g., Ransomware Specialist",
            scale=2
        )
        custom_agent_role = gr.Textbox(
            label="Role/Specialty",
            placeholder="e.g., Expert in ransomware analysis",
            scale=3
        )
    
    custom_agent_prompt = gr.Textbox(
        label="System Prompt",
        placeholder="Define agent behavior, focus areas, and output structure...",
        lines=4,
        max_lines=8
    )
    
    with gr.Row():
        create_agent_btn = gr.Button("Create Agent", variant="secondary")
        custom_agent_status = gr.Markdown("")
    
    # Feedback
    gr.Markdown("---")
    gr.Markdown("### Provide Feedback")
    
    with gr.Row():
        with gr.Column(scale=3):
            feedback_input = gr.Textbox(
                label="Comments",
                lines=3,
                placeholder="Example: Great collaboration between agents. Triage was fast, analysis was thorough."
            )
        with gr.Column(scale=1):
            rating_input = gr.Slider(
                label="Rating",
                minimum=1,
                maximum=5,
                step=1,
                value=3,
                info="1 = Poor, 5 = Excellent"
            )
    
    feedback_btn = gr.Button("Submit Feedback", variant="secondary")
    feedback_status = gr.Markdown("")
    
    # Handlers
    def show_loading():
        """Show loading state"""
        loading_html = """<div style='text-align: center; padding: 40px; color: #9aa4ad;'>
            <div style='font-size: 16px; margin-bottom: 8px;'>⏳ Processing...</div>
            <div style='font-size: 12px;'>Running collaborative assessment pipeline</div>
        </div>"""
        return loading_html, loading_html, loading_html, "", "**Status:** Running collaborative assessment..."
    
    def assess_and_store(threat: str, context: str, custom_agents: List[str], enable_ioc_flag: bool):
        if not threat.strip():
            empty_html = "<p style='color: #9aa4ad;'>Please provide a threat description to begin assessment.</p>"
            return empty_html, empty_html, empty_html, "", "**Status:** Ready", "", ""
        
        triage, analysis, combined, iocs, status = collaborative_assessment(threat, context, custom_agents, enable_ioc_flag)
        status_msg = f"**Status:** {status}"
        return triage, analysis, combined, iocs, status_msg, threat, combined
    
    # Click events with loading state
    assess_btn.click(
        fn=show_loading,
        inputs=[],
        outputs=[triage_output, analysis_output, combined_output, ioc_output, status_text]
    ).then(
        fn=assess_and_store,
        inputs=[threat_input, context_input, custom_agent_selector, enable_ioc],
        outputs=[triage_output, analysis_output, combined_output, ioc_output, status_text, current_threat, current_assessment]
    )
    
    # Custom agent creation handler
    create_agent_btn.click(
        fn=create_custom_agent_handler,
        inputs=[custom_agent_name, custom_agent_role, custom_agent_prompt],
        outputs=[custom_agent_status, custom_agent_selector]
    )
    
    feedback_btn.click(
        fn=submit_feedback,
        inputs=[current_threat, current_assessment, feedback_input, rating_input],
        outputs=[feedback_status]
    )
    
    # Examples
    gr.Markdown("---")
    gr.Markdown("### Example Scenarios")
    gr.Examples(
        examples=[
            ["Ransomware encrypting files on production server", "Windows Server 2019, SQL database affected"],
            ["Phishing campaign targeting executives", "Office 365 environment, 20 users clicked links"],
            ["Data exfiltration via unauthorized SSH tunnel", "Linux servers, outbound traffic spike detected"],
            ["Suspicious PowerShell execution on domain controller", "Active Directory environment, multiple failed logins"],
            ["Malware connecting to known C2 server", "Endpoint detection alert, corporate workstation"],
        ],
        inputs=[threat_input, context_input]
    )


if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7861)

