# CyberXP: AI-Powered Cyber Threat Assessment

A Multi-Agent Cybersecurity Assessment System with RAG, IOC Extraction, SIEM, and User-Defined Agents.

*🚀 Live Demo*: [Hugging Face Space](https://huggingface.co/spaces/abaryan/CyberXP_AGENT_Llama_3.2)  
*🤖 Model*: [abaryan/CyberXP_Agent_Llama_3.2_1B](https://huggingface.co/abaryan/CyberXP_Agent_Llama_3.2_1B)  
*📜 Published Paper*: [TechRxiv](https://doi.org/10.36227/techrxiv.176297583.39945193/v2)
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
- **WebHook Notifier** - Automated notification (Slack, Teams, Discord)
### Interfaces
- **Gradio Web UI** - Single agent + collaborative modes
- **CLI** - Command-line automation
- **REST API** - FastAPI endpoint for integrations
- **Cloud Ready** - Deployed to Hugging Face Spaces

---

## Quick Start

### Web Interface
```bash
cd HF_Space
python gradio_app.py
```

### Command Line
```bash
python src/cyber_agent_vec.py \
  --threat "Ransomware on file server" \
  --enable_ioc \
  --save_html "./reports"
```

---

## Usage

### SIEM Integration
```python
from src.integrations import SplunkConnector, SentinelConnector, VirusTotalConnector

# Splunk - Fetch alerts & push assessments
splunk = SplunkConnector(host="splunk.company.com", token="your-token")
alerts = splunk.fetch_notable_events(max_results=10)
splunk.push_assessment(assessment_data, iocs)

# Sentinel - Incident management
sentinel = SentinelConnector(workspace_id="...", client_id="...", client_secret="...")
incidents = sentinel.get_incidents(severity="High")
sentinel.update_incident("incident-123", "CyberXP Assessment: Critical")

# VirusTotal - IOC enrichment (FREE tier available)
vt = VirusTotalConnector(api_key="your-key")
enriched = vt.bulk_enrich_iocs(iocs)
```

### Webhook Notifications (Optional)
```python
# Optional: Set environment variables to enable
# export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/URL"
# export TEAMS_WEBHOOK_URL="https://your-domain.webhook.office.com/..."

from src.integrations.webhook_notifier import send_alert

# Send alert (only if webhooks configured)
send_alert(
    threat="Critical vulnerability detected",
    iocs=["192.168.1.100", "malicious.exe"],
    assessment="Immediate containment required",
    severity="high"
)
# If no webhooks configured → silently skipped (optional feature)
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

### JSON/ CSV/ STIX
Spreadsheet-compatible for analysis

```bash
python src/exporters/exporter.py --format json/csv/stix
```
API-friendly structured data with metadata
Standard threat intelligence format for TIP integration

---

### VirusTotal (FREE Tier Available)
```python
from src.integrations import VirusTotalConnector

vt = VirusTotalConnector(
    api_key="your-free-api-key",
    rate_limit=4  # Free: 4 req/min
)

# Enrich extracted IOCs
iocs = {
    "ips": ["192.168.1.100"],
    "domains": ["suspicious.com"],
    "hashes": ["abc123..."]
}

enriched = vt.bulk_enrich_iocs(iocs)

# Get summary
for ip_data in enriched['ips']:
    print(vt.get_summary(ip_data))
    # Output: "🚨 Malicious 192.168.1.100: 15/90 engines flagged"
```

---

## Development Status

### ✅ Stage 1: Foundation
- Model fine-tuning, basic agent with RAG, HTML reports

### ✅ Stage 2: Multi-Agent System  
- Triage & Analysis agents
- Custom agent framework
- IOC extraction & export
- Feedback collection
- Collaborative mode

### ✅ Stage 3: Enterprise Integration (Current)
- ✅ Splunk connector - Fetch alerts & push assessments
- ✅ Microsoft Sentinel connector - Incident management
- ✅ VirusTotal API - IOC reputation lookup (FREE tier available)
- ✅ Webhook notifications (Slack, Teams, Discord) - Optional
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
- **Integration**: SEIM, SPLUNK
- **WebHook**: WeboHook Notification
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
