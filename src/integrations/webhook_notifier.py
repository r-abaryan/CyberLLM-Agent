"""
Webhook Notification System
Sends alerts to Slack, Microsoft Teams, Discord, etc.
OPTIONAL - Only works if webhook URLs are configured
"""

import os
import requests
import json
from typing import Dict, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class WebhookNotifier:
    """Universal webhook notification system"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = 5  # 5 seconds timeout
        
    def send_to_slack(self, webhook_url: str, threat: str, iocs: List[str], 
                     assessment: str, severity: str = "medium") -> bool:
        """
        Send threat assessment to Slack webhook
        
        Args:
            webhook_url: Slack incoming webhook URL
            threat: Threat description
            iocs: List of IOCs
            assessment: Threat assessment text
            severity: low/medium/high/critical
            
        Returns:
            True if sent successfully
        """
        # Color mapping
        color_map = {
            "low": "#36a64f",      # Green
            "medium": "#ffaa00",    # Orange
            "high": "#ff6b00",      # Dark Orange
            "critical": "#ff0000"   # Red
        }
        
        # Format IOCs
        ioc_text = "\n".join(f"• {ioc}" for ioc in iocs[:10])  # Limit to 10
        if len(iocs) > 10:
            ioc_text += f"\n• ... and {len(iocs) - 10} more"
        
        # Build Slack message
        payload = {
            "text": "🚨 CyberXP Threat Assessment",
            "attachments": [{
                "color": color_map.get(severity, "#36a64f"),
                "title": f"Threat: {threat[:80]}",
                "fields": [
                    {
                        "title": "Severity",
                        "value": severity.upper(),
                        "short": True
                    },
                    {
                        "title": "IOCs Detected",
                        "value": f"{len(iocs)} indicators",
                        "short": True
                    },
                    {
                        "title": "Indicators of Compromise",
                        "value": ioc_text,
                        "short": False
                    },
                    {
                        "title": "Assessment",
                        "value": assessment[:500],  # Truncate if too long
                        "short": False
                    }
                ],
                "footer": "CyberXP Security Agent",
                "ts": int(datetime.now().timestamp())
            }]
        }
        
        try:
            response = self.session.post(webhook_url, json=payload)
            response.raise_for_status()
            logger.info(f"Alert sent to Slack successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send to Slack: {e}")
            return False
    
    def send_to_teams(self, webhook_url: str, threat: str, iocs: List[str],
                     assessment: str, severity: str = "medium") -> bool:
        """
        Send threat assessment to Microsoft Teams webhook
        
        Args:
            webhook_url: Teams incoming webhook URL
            threat: Threat description
            iocs: List of IOCs
            assessment: Threat assessment text
            severity: low/medium/high/critical
        """
        # Severity theme color
        theme_colors = {
            "low": "success",
            "medium": "warning",
            "high": "attention",
            "critical": "error"
        }
        
        # Build Teams adaptive card
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_colors.get(severity, "info"),
            "summary": f"CyberXP Threat Assessment: {threat[:50]}",
            "sections": [{
                "activityTitle": "🚨 CyberXP Threat Assessment",
                "activitySubtitle": f"Severity: {severity.upper()}",
                "facts": [
                    {
                        "name": "Threat",
                        "value": threat[:100]
                    },
                    {
                        "name": "IOCs Detected",
                        "value": str(len(iocs))
                    },
                    {
                        "name": "Timestamp",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                ],
                "text": assessment[:1000],  # Truncate
                "markdown": True
            }]
        }
        
        # Add IOCs section
        if iocs:
            ioc_list = "\n".join(f"- {ioc}" for ioc in iocs[:20])
            payload["sections"].append({
                "title": "Indicators of Compromise",
                "text": ioc_list,
                "markdown": True
            })
        
        try:
            response = self.session.post(webhook_url, json=payload)
            response.raise_for_status()
            logger.info(f"Alert sent to Teams successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send to Teams: {e}")
            return False
    
    def send_to_discord(self, webhook_url: str, threat: str, iocs: List[str],
                       assessment: str, severity: str = "medium") -> bool:
        """
        Send threat assessment to Discord webhook
        
        Args:
            webhook_url: Discord webhook URL
            threat: Threat description
            iocs: List of IOCs
            assessment: Threat assessment text
            severity: low/medium/high/critical
        """
        # Emoji mapping
        emoji_map = {
            "low": "🟢",
            "medium": "🟠",
            "high": "🔴",
            "critical": "🚨"
        }
        
        # Color codes
        color_map = {
            "low": 0x00ff00,      # Green
            "medium": 0xff8800,   # Orange
            "high": 0xff0000,     # Red
            "critical": 0xff0000  # Red
        }
        
        # Format IOCs
        ioc_text = "\n".join(f"`{ioc}`" for ioc in iocs[:15])
        
        # Build Discord embed
        payload = {
            "embeds": [{
                "title": f"{emoji_map.get(severity, '⚠️')} Threat Assessment",
                "description": assessment[:1000],  # Discord limit
                "color": color_map.get(severity, 0x00ff00),
                "fields": [
                    {
                        "name": "🔍 Threat",
                        "value": threat[:100],
                        "inline": False
                    },
                    {
                        "name": "⚡ Severity",
                        "value": severity.upper(),
                        "inline": True
                    },
                    {
                        "name": "📊 IOCs",
                        "value": str(len(iocs)),
                        "inline": True
                    },
                    {
                        "name": "🎯 Indicators",
                        "value": ioc_text if iocs else "None detected",
                        "inline": False
                    }
                ],
                "footer": {
                    "text": "CyberXP Security Agent"
                },
                "timestamp": datetime.now().isoformat()
            }]
        }
        
        try:
            response = self.session.post(webhook_url, json=payload)
            response.raise_for_status()
            logger.info(f"Alert sent to Discord successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send to Discord: {e}")
            return False
    
    def send_to_email(self, smtp_config: Dict, threat: str, iocs: List[str],
                     assessment: str, severity: str = "medium") -> bool:
        """
        Send threat assessment via email (using SMTP)
        
        Args:
            smtp_config: Dict with host, port, user, password, to_email
            threat: Threat description
            iocs: List of IOCs
            assessment: Threat assessment text
            severity: low/medium/high/critical
        """
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = smtp_config.get('user', 'alerts@cyberxp.local')
            msg['To'] = smtp_config.get('to_email', 'admin@cyberxp.local')
            msg['Subject'] = f"🚨 CyberXP Alert: {severity.upper()} - {threat[:50]}"
            
            # Build email body
            body = f"""
CyberXP Threat Assessment

Severity: {severity.upper()}
Threat: {threat}

Indicators of Compromise ({len(iocs)} detected):
{chr(10).join(f'• {ioc}' for ioc in iocs[:20])}

Assessment:
{assessment[:2000]}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(smtp_config['host'], smtp_config.get('port', 587))
            if smtp_config.get('tls', True):
                server.starttls()
            if smtp_config.get('user'):
                server.login(smtp_config['user'], smtp_config['password'])
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Alert sent to email successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def send_custom(self, webhook_url: str, data: Dict) -> bool:
        """
        Send custom JSON to any webhook
        
        Args:
            webhook_url: Any webhook URL
            data: JSON payload
        """
        try:
            response = self.session.post(webhook_url, json=data)
            response.raise_for_status()
            logger.info(f"Custom webhook sent successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send custom webhook: {e}")
            return False


# Global instance
webhook_notifier = WebhookNotifier()


def send_alert(threat: str, iocs: List[str], assessment: str, 
              severity: str = "medium", **kwargs) -> Dict[str, bool]:
    """
    Send alert to all configured webhooks (ONLY if URLs are set)
    
    This function is OPTIONAL - it only works if webhook URLs are configured.
    If no URLs are configured, it silently returns empty results.
    
    Args:
        threat: Threat description
        iocs: List of IOCs
        assessment: Threat assessment
        severity: low/medium/high/critical
        **kwargs: Additional parameters
        
    Returns:
        Dict with status for each service (empty if nothing configured)
    """
    from src.config import config
    
    results = {}
    
    # Check if any webhooks are configured
    slack_url = os.getenv("SLACK_WEBHOOK_URL", config.get_webhook_url("slack") or "")
    teams_url = os.getenv("TEAMS_WEBHOOK_URL", config.get_webhook_url("teams") or "")
    discord_url = os.getenv("DISCORD_WEBHOOK_URL", "")
    
    # If no webhooks configured, return empty (don't fail)
    if not any([slack_url, teams_url, discord_url]):
        logger.debug("No webhooks configured, skipping notifications")
        return results
    
    # Slack
    if slack_url:
        try:
            results['slack'] = webhook_notifier.send_to_slack(
                slack_url, threat, iocs, assessment, severity
            )
        except Exception as e:
            logger.warning(f"Slack notification failed: {e}")
            results['slack'] = False
    
    # Teams
    if teams_url:
        try:
            results['teams'] = webhook_notifier.send_to_teams(
                teams_url, threat, iocs, assessment, severity
            )
        except Exception as e:
            logger.warning(f"Teams notification failed: {e}")
            results['teams'] = False
    
    # Discord (if configured)
    if discord_url:
        try:
            results['discord'] = webhook_notifier.send_to_discord(
                discord_url, threat, iocs, assessment, severity
            )
        except Exception as e:
            logger.warning(f"Discord notification failed: {e}")
            results['discord'] = False
    
    # Email (if configured)
    smtp_config = kwargs.get('smtp_config')
    if smtp_config:
        try:
            results['email'] = webhook_notifier.send_to_email(
                smtp_config, threat, iocs, assessment, severity
            )
        except Exception as e:
            logger.warning(f"Email notification failed: {e}")
            results['email'] = False
    
    return results


if __name__ == "__main__":
    # Test webhook notifications
    print("Testing webhook notifications...")
    
    test_threat = "Suspicious login attempts detected from multiple IPs"
    test_iocs = ["192.168.1.100", "malicious.exe", "fake-domain.com"]
    test_assessment = "Multiple failed login attempts indicate potential brute force attack. Immediate containment recommended."
    
    # Example usage (requires webhook URLs set in environment)
    results = send_alert(
        threat=test_threat,
        iocs=test_iocs,
        assessment=test_assessment,
        severity="high"
    )
    
    print("\nResults:")
    for service, success in results.items():
        status = "✅" if success else "❌"
        print(f"  {service}: {status}")

