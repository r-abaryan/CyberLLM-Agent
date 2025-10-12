# Cybersecurity SFT Fine-tuning

Direct SFT training on the provided dataset from kaggle of Huggingface using Llama-3.2-1B-Instruct.

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run SFT fine-tuning:
   ```bash
   python cyberllm_sft.py
   ```

## Model Configuration

- **Base Model**: Meta/Llama-3.2-1B-Instruct
- **Training Method**: Supervised Fine-tuning (SFT) with SFTTrainer
- **Dataset**: Provided local dataset or alternatives
- **Training**: 7 epochs, learning rate 3e-5, batch size 12 [adjust the parameters accordingly]


## Output

- **Model**: ./cyberllm_sft_model
- **Training Logs**: Console output with progress
- **Checkpoints**: Saved every 1000 steps

## Cyber Threat Assessment Agent

Run incident-response style assessments using your fine-tuned model.

### CLI Usage

One-off assessment:
```bash
python cyber_agent.py --threat "Suspicious PowerShell downloads from unknown IPs" --context "Windows domain, EDR present"
```

Interactive mode:
```bash
python cyber_agent.py
```

### Options

- `--model_path` (default ./cyberllm_sft_model)
- `--device` (default auto)
- `--kb_path` (default ./knowledge_base) points to local .md/.txt files used for retrieval
- `--public_kb` includes knowledge_base/PUBLIC_KB.md into retrieval
- `--simple` uses simplified sections: Severity, Immediate Actions, Recovery, Preventive Measures
- `--save_html` saves HTML report to specified path

### Severity Rubric

Built-in severity levels with consistent rationale:
- Low: contained, minimal business impact, easy mitigation
- Medium: limited spread or exposure, moderate remediation effort
- High: likely compromise or sensitive data risk, material impact
- Critical: widespread compromise or major impact; immediate escalation

### Retrieval-Augmented Generation (RAG)

Drop security notes, playbooks, or standards into ./knowledge_base (Markdown or text). The agent retrieves relevant snippets and injects them as context.

How it works:
- Model remains the decision-maker
- Keyword/Jaccard retriever selects high-signal passages
- Retrieved content shown as "Relevant knowledge" for grounding
- Improves specificity while keeping everything local

### REST API

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

### HTML Reports

Generate styled HTML reports from assessments.

CLI auto-save:
```bash
python cyber_agent.py --threat "Suspicious PowerShell download" \
  --context "Windows estate; Defender enabled" \
  --kb_path "./knowledge_base" \
  --save_html "./reports"
```

HTML includes:
- Linear Steps view for Immediate Actions with numbered badges
- Flow Diagram: inline SVG showing left-to-right sequence

### Hugging Face Spaces

Deploy to HF Spaces using the Gradio app in HF_Space/ folder.

Files needed:
- gradio_app.py (UI)
- requirements.txt (includes gradio, langchain-huggingface, transformers)
- knowledge_base/ folder
- cyberllm_sft_model/ or model repo reference

Steps:
1. Create new Gradio Space under your HF account
2. Upload gradio_app.py, requirements.txt, and knowledge_base/
3. Set MODEL_PATH in gradio_app.py to your model repo or local path
4. Space auto-builds and serves at port 7860

## Technical Notes

- Uses langchain-huggingface integration (no deprecation warnings)
- Structured outputs with consistent section headers
- Local RAG with keyword/Jaccard retrieval
- HTML visualization with SVG flow diagrams
- FastAPI endpoint for integration