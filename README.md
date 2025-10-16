# CyberXP Agent: Streamlined Cyber Threat Assessment Powered by LLaMA & Retrieval-Augmented Generation (RAG)

Direct SFT training on cybersecurity datasets using Llama-3.2-1B-Instruct with vector-based RAG for enhanced threat assessment.
**Trained model and limited demo of agent-environment can be found & tested via below links:
* [Model: https://huggingface.co/abaryan/CyberXP_Agent_Llama_3.2_1B]
* [HF-Space: https://huggingface.co/spaces/abaryan/CyberXP_AGENT_Llama_3.2]

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run SFT fine-tuning:
   ```bash
   python src/cyberllm_sft.py
   ```

3. Use the agent:
   ```bash
   # Normal RAG (keyword-based)
   python src/cyber_agent.py --threat "Suspicious PowerShell downloads" --context "Windows domain"
   
   # Vector RAG (semantic similarity)
   python src/cyber_agent_vec.py --threat "Suspicious PowerShell downloads" --context "Windows domain"
   ```

### Options

- `--model_path` (default ./cyberllm_sft_model)
- `--device` (default auto)
- `--kb_path` (default ./knowledge_base) points to local .md/.txt files used for retrieval
- `--public_kb` includes knowledge_base/PUBLIC_KB.md into retrieval
- `--simple` uses simplified sections: Severity, Immediate Actions, Recovery, Preventive Measures
- `--save_html` saves HTML report to specified path
- `--enable_ioc` extracts Indicators of Compromise (IOCs) from assessment
- `--save_iocs` saves extracted IOCs to JSON file
- `--feedback_log` logs assessments with user feedback to JSONL file

<img width="3028" height="1472" alt="IOC + Feedback" src="https://github.com/user-attachments/assets/752c856c-735d-4128-92c6-b733708e4247" />
## Available Features

### Current Implementation
- **Fine-tuned Model**: Llama-3.2-1B-Instruct specialized for cybersecurity
- **CLI Agent**: Command-line interface for threat assessment
- **Interactive Mode**: Conversational threat analysis
- **Vector RAG**: Semantic similarity search over knowledge base
- **HTML Reports**: Styled assessment reports with visualizations
- **IOC Extraction**: Automated extraction of IPs, domains, hashes, paths, users
- **Feedback Logging**: Collect user feedback for continuous improvement
- **REST API**: FastAPI endpoint for integration
- **HF Spaces**: Gradio web interface deployment
- **Severity Rubric**: Consistent threat classification
- **Structured Outputs**: Standardized response format

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
- IOC Section: Extracted indicators displayed as formatted JSON (when enabled)

### IOC Extraction & Feedback

Extract Indicators of Compromise and log user feedback for model improvement.

Enable IOC extraction:
```bash
python src/cyber_agent_vec.py --threat "Malware detected on endpoint" \
  --context "Windows 10 workstation" \
  --enable_ioc \
  --save_iocs "./iocs"
```

Log feedback for continuous improvement:
```bash
python src/cyber_agent_vec.py --feedback_log "./logs/feedback.jsonl"
```

IOC extraction identifies:
- IP addresses (IPv4)
- Domain names
- File hashes (MD5, SHA1, SHA256)
- File paths (Windows and Unix)
- Usernames

Feedback logging captures:
- Assessment timestamp
- Threat description and context
- Model output
- User feedback and rating (1-5)

### Hugging Face Spaces

Deploy to HF Spaces using the Gradio app in HF_Space/ folder with full IOC extraction and feedback capabilities.

Features:
- Tabbed interface: Assessment Report, Raw Text, Extracted IOCs
- Real-time IOC extraction with toggle
- Feedback submission with rating (1-5) and comments
- Logs stored in feedback_logs/feedback.jsonl
- Example scenarios for quick testing

Steps:
1. Create new Gradio Space under your HF account
2. Upload gradio_app.py, requirements.txt, knowledge_base/, and src/ folder
3. Set MODEL_PATH in gradio_app.py to your model repo or local path
4. Space auto-builds and serves at port 7860

## Roadmap: From Fine-tuning to Agentic AI

### Phase 1: Foundation (Current)
1. **Model Fine-tuning**: Llama-3.2-1B-Instruct → Cybersecurity specialist
2. **Basic Agent**: LangChain wrapper with structured prompting
3. **Knowledge Integration**: RAG with local playbooks and procedures
4. **Output Generation**: HTML reports with visualizations

### Phase 2: Multi-Agent Architecture (Planned)
5. **IOC Extraction & Feedback**: ✓ Automated indicator extraction with user feedback collection
6. **Specialized Agents**: Triage, Analysis, Containment, Forensics
7. **Agent Orchestration**: Communication protocols and routing
8. **Decision Trees**: Automated agent selection and coordination

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
- Vector RAG with semantic similarity search
- HTML visualization with SVG flow diagrams
- FastAPI endpoint for integration
