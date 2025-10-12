# Cybersecurity SFT Fine-tuning

Direct SFT training on the `AlicanKiraz0/Cybersecurity-Dataset-v1` dataset.

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run SFT fine-tuning:**
   ```bash
   python cyberllm_sft.py
   ```

## Model Configuration

-   **Base Model**: `Qwen/Qwen2.5-0.5B-Instruct`
-   **Training Method**: Supervised Fine-tuning (SFT) with SFTTrainer
-   **Dataset**: `AlicanKiraz0/Cybersecurity-Dataset-v1` (Real cybersecurity Q&A)
-   **Format**: Instruction + Response (high-quality cybersecurity content)
-   **Training**: 7 epochs, learning rate 3e-5, batch size 12

## Dataset Information

The `AlicanKiraz0/Cybersecurity-Dataset-v1` dataset contains:
- High-quality cybersecurity Q&A pairs
- Expert-level explanations
- Comprehensive coverage of security topics
- Professional instruction-response format
- Thousands of examples for robust training

## Output

- **Model**: `./cyberllm_sft_model`
- **Training Logs**: Console output with progress
- **Checkpoints**: Saved every 1000 steps

## Cyber Threat Assessment Agent (LangChain)

Run an incident-response style assessment using your fine-tuned local model.

1. Install/update dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. CLI usage (one-off):
   ```bash
   python cyber_agent.py --threat "Suspicious PowerShell downloads from unknown IPs" --context "Windows domain, EDR present"
   ```

3. Interactive mode:
   ```bash
   python cyber_agent.py
   ```

Options:
- `--model_path` (default `./cyberllm_sft_model`)
- `--device` (default `auto`)
- `--kb_path` (default `./knowledge_base`) points to local `.md`/`.txt` files used for retrieval

### Severity rubric (built-in)
The agent ranks severity using a simple, repeatable rubric and explains why:
- Low: contained, minimal business impact, easy mitigation
- Medium: limited spread or exposure, moderate remediation effort
- High: likely compromise or sensitive data risk, material impact
- Critical: widespread compromise or major impact; immediate escalation

This makes outputs consistent across analysts and easier to automate.

### Guardrails for complete outputs
Outputs are structured with the same section headers every time:
`Summary`, `Severity`, `Indicators`, `Immediate Actions`, `Containment`, `Eradication`, `Recovery`, `Preventive Measures`.
If any section would be missing, the agent appends a small placeholder so you can spot gaps quickly.

### Lightweight Retrieval-Augmented Generation (RAG)
You can drop security notes, playbooks, or standards into `./knowledge_base` (Markdown or text). The agent retrieves the most relevant snippets and injects them into the prompt as context. No external services required.

How it works with your current model:
- The model remains the decision-maker. RAG simply provides additional, domain-relevant text next to your threat description.
- A keyword/Jaccard retriever selects a few high-signal passages. These are shown to the model as "Relevant knowledge (retrieved)" so it can ground recommendations without changing the model weights.
- This improves specificity (e.g., org standards, tool names, network segments) while keeping everything fully local.

Suggested uses for the KB:
- Internal severity definitions, escalation matrices
- Network maps or naming conventions
- EDR/AV policy notes, blocked lists, allowlists
- Incident playbooks and communication templates

### REST API (FastAPI)
Serve the agent as an API for tools, dashboards, or automation.

Run the server:
```bash
uvicorn cyber_api:app --host 0.0.0.0 --port 8000 --workers 1
```

Health check:
```bash
curl http://localhost:8000/health
```

Assess a threat:
```bash
curl -s -X POST http://localhost:8000/assess \
  -H "Content-Type: application/json" \
  -d '{
    "threat": "Exfiltration via HTTPS to rare domain",
    "context": "Linux servers; outbound proxy"
  }'
```

The response includes the structured assessment with severity, actions, and preventive measures.

### HTML Report (optional)
Generate a styled HTML report from the assessment for sharing.

Python usage:
```python
from cyber_agent import render_html_report
html = render_html_report(assessment_text, title="Threat Assessment - Case 001")
with open("assessment.html", "w", encoding="utf-8") as f:
    f.write(html)
```

CLI auto-save during assessment:
```bash
python cyber_agent.py --threat "Suspicious PowerShell download" \
  --context "Windows estate; Defender enabled" \
  --kb_path "./knowledge_base" \
  --save_html "./reports" 
```

The HTML includes:
- Linear Steps view for `Immediate Actions` with numbered badges.
- Flow Diagram: inline SVG showing left-to-right sequence (Assess → Gather Info → Immediate Actions) and branches (Containment, Eradication, Recovery, Preventive Measures).

Notes:
- Uses `langchain-huggingface` integration (no deprecation warning).
- Optional: `--public_kb` includes `knowledge_base/PUBLIC_KB.md` into retrieval for added grounding.

& C:/Users/rasou/miniconda3/python.exe d:/AI-ML/CyberXP/cyber_agent.py --threat "Instagram account get hacked" --context "Multiple unkown email"  --kb_path "./knowledge_base" --public_kb --simple --save_html "./reports"