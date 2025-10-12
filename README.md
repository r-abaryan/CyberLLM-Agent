# CyberXP Agent: Streamlined Cyber Threat Assessment Powered by LLaMA & Retrieval-Augmented Generation (RAG)

Direct SFT training on the provided dataset from kaggle or Huggingface using Llama-3.2-1B-Instruct.

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

### Vector-based Retrieval-Augmented Generation (RAG)

Drop security notes, playbooks, or standards into ./knowledge_base (Markdown or text). The agent uses semantic similarity search to retrieve relevant context.

How it works:
- Model remains the decision-maker
- Sentence transformers encode documents and queries into embeddings
- Cosine similarity finds semantically relevant passages
- Retrieved content shown as "Relevant knowledge" for grounding
- Much better context matching than keyword search

### Vector RAG Features

- **Semantic Search**: Uses sentence transformers for meaning-based retrieval
- **Similarity Scoring**: Shows confidence scores for retrieved documents
- **Configurable Thresholds**: Adjust minimum similarity and number of results
- **Multiple Models**: Support for different sentence transformer models
- **Dynamic Updates**: Add new documents without full re-encoding

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

## Available Features

### Current Implementation
- **Fine-tuned Model**: Llama-3.2-1B-Instruct specialized for cybersecurity
- **CLI Agent**: Command-line interface for threat assessment
- **Interactive Mode**: Conversational threat analysis
- **Vector RAG**: Semantic similarity search over knowledge base
- **HTML Reports**: Styled assessment reports with visualizations
- **REST API**: FastAPI endpoint for integration
- **HF Spaces**: Gradio web interface deployment
- **Severity Rubric**: Consistent threat classification
- **Structured Outputs**: Standardized response format

## Roadmap: From Fine-tuning to Agentic AI

### Phase 1: Foundation (Current)
1. **Model Fine-tuning**: Llama-3.2-1B-Instruct → Cybersecurity specialist
2. **Basic Agent**: LangChain wrapper with structured prompting
3. **Knowledge Integration**: RAG with local playbooks and procedures
4. **Output Generation**: HTML reports with visualizations

### Phase 2: Multi-Agent Architecture (Planned)
5. **Specialized Agents**: Triage, Analysis, Containment, Forensics
6. **Agent Orchestration**: Communication protocols and routing
7. **Decision Trees**: Automated agent selection and coordination
8. **Feedback Loops**: Continuous learning from analyst input

### Phase 3: Production Integration (Future)
9. **External Connectors**: SIEM/SOAR integration (Splunk, QRadar)
10. **Threat Intelligence**: Real-time feeds (VirusTotal, OTX, MISP)
11. **Automated Response**: Containment and isolation procedures
12. **Multi-modal Analysis**: Logs, network traffic, file samples
13. **Behavioral Profiling**: User/entity anomaly detection
14. **Compliance Reporting**: Audit trails and regulatory compliance
15. **Continuous Learning**: Model retraining on new threats

## Technical Notes

- Uses langchain-huggingface integration (no deprecation warnings)
- Structured outputs with consistent section headers
- Local RAG with keyword/Jaccard retrieval
- HTML visualization with SVG flow diagrams
- FastAPI endpoint for integration