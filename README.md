# CyberXP: AI-Powered Cyber Threat Assessment

A Multi-Agent Cybersecurity Assessment System with RAG, IOC Extraction, SIEM, and User-Defined Agents.

Live Demo: [Hugging Face Space](https://huggingface.co/spaces/abaryan/CyberXP_AGENT_Llama_3.2)  
Model: [abaryan/CyberXP_Agent_Llama_3.2_1B](https://huggingface.co/abaryan/CyberXP_Agent_Llama_3.2_1B)  
Published Paper: [TechRxiv](https://doi.org/10.36227/techrxiv.176297583.39945193/v2)
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
