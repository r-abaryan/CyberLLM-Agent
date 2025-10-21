# CyberXP: AI-Powered Cyber Threat Assessment

Multi-agent cybersecurity assessment system using fine-tuned LLaMA 3.2 with RAG, IOC extraction, and SIEM integration.

**🚀 Live Demo**: [Hugging Face Space](https://huggingface.co/spaces/abaryan/CyberXP_AGENT_Llama_3.2)  
**🤖 Model**: [abaryan/CyberXP_Agent_Llama_3.2_1B](https://huggingface.co/abaryan/CyberXP_Agent_Llama_3.2_1B)

---

<img width="3028" height="1472" alt="IOC + Feedback" src="https://github.com/user-attachments/assets/752c856c-735d-4128-92c6-b733708e4247" />


```bash
# Install dependencies
pip install -r requirements.txt

# Run web interface
cd HF_Space
python gradio_app.py
```

Access at http://localhost:7860

---

## Features

### Core Capabilities
- **Fine-tuned Model** - Llama-3.2-1B specialized for cybersecurity
- **Multi-Agent System** - Triage & Analysis agents with smart routing
- **Custom Agents** - Create specialized agents with custom prompts
- **Vector RAG** - Semantic search over security knowledge base
- **IOC Extraction** - Auto-extract IPs, domains, hashes, paths, users
- **Multiple Export Formats** - JSON, CSV, STIX 2.1
- **SIEM Integration** - Splunk & Microsoft Sentinel connectors
- **HTML Reports** - Styled reports with SVG flow diagrams
- **Feedback System** - User ratings for continuous improvement

### Interfaces
- **Gradio Web UI** - Single agent + collaborative modes
- **CLI** - Command-line automation
- **REST API** - FastAPI endpoint for integrations
- **Cloud Ready** - Deployed to Hugging Face Spaces

---

## Usage

### Web Interface
```bash
cd HF_Space
python gradio_app.py
```

### Command Line
```bash
# Basic assessment
python src/cyber_agent_vec.py \
  --threat "Suspicious PowerShell downloads" \
  --context "Windows domain"

# With IOC extraction
python src/cyber_agent_vec.py \
  --threat "Ransomware on file server" \
  --enable_ioc \
  --save_html "./reports"

# With feedback logging
python src/cyber_agent_vec.py \
  --threat "Data exfiltration detected" \
  --feedback_log "./logs/feedback.jsonl"
```

### SIEM Integration
```python
from src.integrations import SplunkConnector

# Connect to Splunk
splunk = SplunkConnector(
    host="splunk.company.com",
    token="your-token"
)

# Fetch alerts
alerts = splunk.fetch_notable_events(max_results=10)

# Push assessment results
splunk.push_assessment(assessment_data, iocs)
```

### Programmatic Use
```python
from src.agents import AgentRouter

router = AgentRouter(llm=your_model)

result = router.route(
    threat="Ransomware detected on file server",
    context="Production environment",
    agent_type="auto"  # or "triage", "analysis"
)

print(result['output'])
```

---

## Options

### CLI Arguments
- `--model_path` - Path to model (default: ./cyberllm_sft_model)
- `--device` - Device for inference (default: auto)
- `--kb_path` - Knowledge base directory (default: ./knowledge_base)
- `--public_kb` - Include public knowledge base
- `--simple` - Use simplified output sections
- `--save_html` - Save HTML report to path
- `--enable_ioc` - Extract Indicators of Compromise
- `--save_iocs` - Save IOCs to JSON file
- `--feedback_log` - Log feedback to JSONL file

### Configuration
Edit `src/config.py` to enable/disable features:
```python
FEATURES = {
    "multi_agent": True,
    "custom_agents": True,
    "vector_rag": True,
    "ioc_extraction": True,
    "feedback_logging": True,
    "export_json": True,
    "export_csv": True,
    "export_stix": True,
}

INTEGRATIONS = {
    "splunk": False,  # Enable after configuration
    "sentinel": False,
}
```

---

## Agents

### Built-in Agents

**Triage Agent**
- Fast severity assessment
- Immediate containment actions
- Escalation recommendations

**Analysis Agent**
- Deep threat investigation
- IOC extraction and mapping
- Recovery and prevention steps

**Auto Router**
- Keyword-based agent selection
- Manual override supported

### Custom Agents
Create specialized agents via web UI or programmatically:
```python
from src.agents import CustomAgent

agent = CustomAgent(
    name="Ransomware Specialist",
    role="Expert in ransomware incidents",
    system_prompt="You are a ransomware expert...",
    llm=your_model
)
```

---

## Export Formats

### JSON
```bash
python src/exporters/exporter.py --format json
```
API-friendly structured data with metadata

### CSV
```bash
python src/exporters/exporter.py --format csv
```
Spreadsheet-compatible for analysis

### STIX 2.1
```bash
python src/exporters/exporter.py --format stix
```
Standard threat intelligence format for TIP integration

---

## SIEM Integration (New)

### Splunk
```python
from src.integrations import SplunkConnector

splunk = SplunkConnector(
    host="splunk.example.com",
    token="your-splunk-token"
)

# Fetch notable events
events = splunk.fetch_notable_events(max_results=50)

# Push assessment
splunk.push_assessment(assessment, iocs)

# Search IOC context
context = splunk.search_ioc_context("192.168.1.100", "ip")
```

### Microsoft Sentinel
```python
from src.integrations import SentinelConnector

sentinel = SentinelConnector(
    workspace_id="your-workspace-id",
    subscription_id="your-sub-id",
    resource_group="your-rg",
    tenant_id="your-tenant",
    client_id="your-client-id",
    client_secret="your-secret"
)

# Get high-severity incidents
incidents = sentinel.get_incidents(severity="High")

# Update incident with assessment
sentinel.update_incident(
    incident_id="incident-123",
    comment="CyberXP Assessment: Critical - Immediate action required"
)

# Create threat indicator
sentinel.create_threat_indicator(
    ioc_value="malicious.com",
    ioc_type="domain-name",
    confidence=90
)
```

---

## Development Stages

### ✅ Stage 1: Foundation
- Model fine-tuning
- Basic agent with RAG
- HTML report generation

### ✅ Stage 2: Multi-Agent System  
- Triage & Analysis agents
- Custom agent framework
- IOC extraction & export
- Feedback collection
- Collaborative mode

### 🚀 Stage 3: Enterprise Integration (Current)
- ✅ Splunk connector
- ✅ Microsoft Sentinel connector
- 🔄 VirusTotal API integration
- 🔄 Webhook notifications (Slack, Teams)
- 📋 Automated response playbooks
- 📋 Compliance report templates

---

## Project Structure

```
CyberXP/
├── src/
│   ├── agents/              # Multi-agent system
│   ├── integrations/        # SIEM/SOAR connectors (NEW)
│   ├── exporters/           # JSON/CSV/STIX export
│   ├── rag/                 # Vector RAG
│   ├── utils/               # IOC extraction
│   └── config.py            # Configuration
├── HF_Space/
│   ├── gradio_app.py        # Single agent UI
│   └── gradio_collaborative.py  # Multi-agent pipeline
├── knowledge_base/          # Security playbooks
├── custom_agents/           # User-created agents
└── feedback_logs/           # User feedback
```

---

## Technical Details

- **Model**: Llama-3.2-1B-Instruct fine-tuned on cybersecurity data
- **Framework**: LangChain for LLM orchestration
- **RAG**: Sentence-transformers + FAISS for semantic search
- **UI**: Gradio for web interface
- **API**: FastAPI for REST endpoints
- **Export**: JSON, CSV, STIX 2.1 standard formats
- **Response Time**: 2-5 seconds (LLM-dominated)
- **Deployment**: Local, cloud, or containerized

---

## Citation

If you use this work, please cite:

```bibtex
@software{CyberXP,
  title={CyberXP: AI-Powered Cyber Threat Assessment with Multi-Agent Architecture},
  author={Abaryan},
  year={2025},
  url={https://github.com/r-abaryan/CyberLLM-Agent}
}
```

---

**Version**: 2.0  
**License**: MIT  
**Status**: Production Ready
