"""
Multi-Channel Alert Manager for DDoS Detection
Supports: Telegram, Email, Slack, Webhooks, and custom integrations
"""

import asyncio
import aiohttp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict
import json
import logging
import hashlib
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertDeduplicator:
    """
    Deduplicates alerts to reduce noise
    Prevents alert flooding for similar events
    """
    
    def __init__(self, window_seconds: int = 60, max_alerts: int = 5):
        """
        Args:
            window_seconds: Time window for deduplication
            max_alerts: Max alerts per source in window
        """
        self.window_seconds = window_seconds
        self.max_alerts = max_alerts
        self.alert_cache = defaultdict(list)  # {alert_key: [timestamps]}
    
    def generate_key(self, alert: Dict) -> str:
        """Generate unique key for alert"""
        key_data = f"{alert.get('src_ip', '')}-{alert.get('dst_ip', '')}-{alert.get('attack_type', '')}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def should_send_alert(self, alert: Dict) -> bool:
        """
        Check if alert should be sent (not duplicate)
        
        Returns:
            True if alert should be sent, False if duplicate
        """
        key = self.generate_key(alert)
        now = datetime.now()
        
        # Clean old timestamps
        cutoff = now - timedelta(seconds=self.window_seconds)
        self.alert_cache[key] = [ts for ts in self.alert_cache[key] if ts > cutoff]
        
        # Check if we've exceeded max alerts
        if len(self.alert_cache[key]) >= self.max_alerts:
            logger.info(f"Alert suppressed (dedup): {key}")
            return False
        
        # Add timestamp and allow alert
        self.alert_cache[key].append(now)
        return True
    
    def get_suppressed_count(self, alert: Dict) -> int:
        """Get count of suppressed similar alerts"""
        key = self.generate_key(alert)
        return max(0, len(self.alert_cache.get(key, [])) - 1)


class TelegramAlerter:
    """Send alerts via Telegram Bot"""
    
    def __init__(self, bot_token: str, chat_ids: List[str]):
        """
        Args:
            bot_token: Telegram bot token
            chat_ids: List of chat IDs to send alerts to
        """
        self.bot_token = bot_token
        self.chat_ids = chat_ids
        self.api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    
    async def send_alert(self, alert: Dict):
        """Send alert to Telegram"""
        try:
            message = self._format_message(alert)
            
            async with aiohttp.ClientSession() as session:
                for chat_id in self.chat_ids:
                    payload = {
                        'chat_id': chat_id,
                        'text': message,
                        'parse_mode': 'HTML'
                    }
                    
                    async with session.post(self.api_url, json=payload) as response:
                        if response.status == 200:
                            logger.info(f"Telegram alert sent to {chat_id}")
                        else:
                            logger.error(f"Telegram error: {response.status}")
        
        except Exception as e:
            logger.error(f"Telegram alert failed: {e}")
    
    def _format_message(self, alert: Dict) -> str:
        """Format alert message for Telegram"""
        severity_emoji = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '⚡',
            'low': 'ℹ️'
        }
        
        emoji = severity_emoji.get(alert.get('severity', 'medium'), '⚠️')
        
        message = f"""
{emoji} <b>DDoS ATTACK DETECTED</b> {emoji}

<b>Time:</b> {alert.get('timestamp', 'N/A')}
<b>Source IP:</b> <code>{alert.get('src_ip', 'Unknown')}</code>
<b>Destination IP:</b> <code>{alert.get('dst_ip', 'Unknown')}</code>
<b>Protocol:</b> {alert.get('protocol', 'Unknown')}
<b>Attack Type:</b> {alert.get('attack_type', 'DDoS')}
<b>Detection Stage:</b> {alert.get('detection_stage', 'Unknown')}

<b>Confidence Score:</b> {alert.get('confidence_score', 0):.2%}

<b>Flow Details:</b>
• Duration: {alert.get('flow_duration', 0):,}μs
• Packets: {alert.get('total_packets', 0):,}
• Bytes/sec: {alert.get('flow_bytes_per_sec', 0):,.0f}

<b>Dashboard:</b> {alert.get('dashboard_url', 'N/A')}
"""
        return message.strip()


class EmailAlerter:
    """Send alerts via Email (SMTP)"""
    
    def __init__(
        self,
        smtp_server: str,
        smtp_port: int,
        username: str,
        password: str,
        from_addr: str,
        to_addrs: List[str]
    ):
        """
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP port (usually 587 for TLS)
            username: SMTP username
            password: SMTP password
            from_addr: From email address
            to_addrs: List of recipient email addresses
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs
    
    async def send_alert(self, alert: Dict):
        """Send alert via email"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = self._get_subject(alert)
            msg['From'] = self.from_addr
            msg['To'] = ', '.join(self.to_addrs)
            
            # Plain text version
            text_body = self._format_text(alert)
            # HTML version
            html_body = self._format_html(alert)
            
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            logger.info(f"Email alert sent to {len(self.to_addrs)} recipients")
        
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
    
    def _get_subject(self, alert: Dict) -> str:
        """Generate email subject"""
        severity = alert.get('severity', 'medium').upper()
        src_ip = alert.get('src_ip', 'Unknown')
        return f"[{severity}] DDoS Attack Detected from {src_ip}"
    
    def _format_text(self, alert: Dict) -> str:
        """Format plain text email"""
        return f"""
DDoS ATTACK DETECTED

Time: {alert.get('timestamp', 'N/A')}
Severity: {alert.get('severity', 'medium').upper()}

Source IP: {alert.get('src_ip', 'Unknown')}
Destination IP: {alert.get('dst_ip', 'Unknown')}
Protocol: {alert.get('protocol', 'Unknown')}
Attack Type: {alert.get('attack_type', 'DDoS')}
Detection Stage: {alert.get('detection_stage', 'Unknown')}

Confidence Score: {alert.get('confidence_score', 0):.2%}

Flow Details:
- Duration: {alert.get('flow_duration', 0):,} microseconds
- Packets: {alert.get('total_packets', 0):,}
- Bytes/sec: {alert.get('flow_bytes_per_sec', 0):,.0f}

Dashboard: {alert.get('dashboard_url', 'N/A')}

--
Automated DDoS Detection System
"""
    
    def _format_html(self, alert: Dict) -> str:
        """Format HTML email"""
        severity_colors = {
            'critical': '#d32f2f',
            'high': '#f57c00',
            'medium': '#fbc02d',
            'low': '#388e3c'
        }
        
        color = severity_colors.get(alert.get('severity', 'medium'), '#fbc02d')
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        .alert-box {{ 
            border: 3px solid {color}; 
            border-radius: 10px; 
            padding: 20px; 
            background-color: #f5f5f5; 
        }}
        .header {{ 
            background-color: {color}; 
            color: white; 
            padding: 15px; 
            border-radius: 5px; 
            margin-bottom: 20px;
        }}
        .detail {{ margin: 10px 0; }}
        .label {{ font-weight: bold; }}
        .value {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f0f0f0; }}
    </style>
</head>
<body>
    <div class="alert-box">
        <div class="header">
            <h2>🚨 DDoS ATTACK DETECTED 🚨</h2>
        </div>
        
        <div class="detail">
            <span class="label">Time:</span> 
            <span class="value">{alert.get('timestamp', 'N/A')}</span>
        </div>
        
        <div class="detail">
            <span class="label">Severity:</span> 
            <span class="value" style="color: {color}; font-weight: bold;">
                {alert.get('severity', 'medium').upper()}
            </span>
        </div>
        
        <table>
            <tr>
                <th>Parameter</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Source IP</td>
                <td><code>{alert.get('src_ip', 'Unknown')}</code></td>
            </tr>
            <tr>
                <td>Destination IP</td>
                <td><code>{alert.get('dst_ip', 'Unknown')}</code></td>
            </tr>
            <tr>
                <td>Protocol</td>
                <td>{alert.get('protocol', 'Unknown')}</td>
            </tr>
            <tr>
                <td>Attack Type</td>
                <td>{alert.get('attack_type', 'DDoS')}</td>
            </tr>
            <tr>
                <td>Detection Stage</td>
                <td><b>{alert.get('detection_stage', 'Unknown')}</b></td>
            </tr>
            <tr>
                <td>Confidence Score</td>
                <td><b>{alert.get('confidence_score', 0):.2%}</b></td>
            </tr>
            <tr>
                <td>Ensemble Votes</td>
                <td><b>{alert.get('ensemble_votes', {}).get('total_votes', 0)}/5</b></td>
            </tr>
            <tr>
                <td>Vote Threshold</td>
                <td>{alert.get('ensemble_votes', {}).get('threshold', 'N/A')}</td>
            </tr>
        </table>
        
        <h3>Flow Details</h3>
        <table>
            <tr>
                <td>Duration</td>
                <td>{alert.get('flow_duration', 0):,} μs</td>
            </tr>
            <tr>
                <td>Total Packets</td>
                <td>{alert.get('total_packets', 0):,}</td>
            </tr>
            <tr>
                <td>Bytes per Second</td>
                <td>{alert.get('flow_bytes_per_sec', 0):,.0f}</td>
            </tr>
        </table>
        
        <div style="margin-top: 20px; padding: 15px; background-color: #e3f2fd; border-radius: 5px;">
            <p><b>Dashboard Link:</b> 
            <a href="{alert.get('dashboard_url', '#')}">{alert.get('dashboard_url', 'N/A')}</a></p>
        </div>
        
        <div style="margin-top: 30px; color: #666; font-size: 12px;">
            <p>Automated DDoS Detection System</p>
        </div>
    </div>
</body>
</html>
"""


class SlackAlerter:
    """Send alerts via Slack Webhook"""
    
    def __init__(self, webhook_url: str):
        """
        Args:
            webhook_url: Slack incoming webhook URL
        """
        self.webhook_url = webhook_url
    
    async def send_alert(self, alert: Dict):
        """Send alert to Slack"""
        try:
            payload = self._format_payload(alert)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info("Slack alert sent successfully")
                    else:
                        logger.error(f"Slack error: {response.status}")
        
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
    
    def _format_payload(self, alert: Dict) -> Dict:
        """Format Slack message payload"""
        severity_colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': '#fbc02d',
            'low': 'good'
        }
        
        color = severity_colors.get(alert.get('severity', 'medium'), 'warning')
        
        return {
            "text": "🚨 DDoS Attack Detected",
            "attachments": [
                {
                    "color": color,
                    "title": f"Attack from {alert.get('src_ip', 'Unknown')}",
                    "text": f"*Severity:* {alert.get('severity', 'medium').upper()}",
                    "fields": [
                        {
                            "title": "Source IP",
                            "value": alert.get('src_ip', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Destination IP",
                            "value": alert.get('dst_ip', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Protocol",
                            "value": alert.get('protocol', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Stage",
                            "value": alert.get('detection_stage', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Confidence",
                            "value": f"{alert.get('confidence_score', 0):.2%}",
                            "short": True
                        },
                        {
                            "title": "Votes",
                            "value": f"{alert.get('ensemble_votes', {}).get('total_votes', 0)}/5 (≥{alert.get('ensemble_votes', {}).get('threshold', '?')})",
                            "short": True
                        },
                        {
                            "title": "Packets",
                            "value": f"{alert.get('total_packets', 0):,}",
                            "short": True
                        },
                        {
                            "title": "Bytes/sec",
                            "value": f"{alert.get('flow_bytes_per_sec', 0):,.0f}",
                            "short": True
                        }
                    ],
                    "footer": "DDoS Detection System",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }


class WebhookAlerter:
    """Send alerts via generic HTTP webhook"""
    
    def __init__(self, webhook_url: str, headers: Optional[Dict] = None):
        """
        Args:
            webhook_url: Webhook endpoint URL
            headers: Optional custom headers
        """
        self.webhook_url = webhook_url
        self.headers = headers or {'Content-Type': 'application/json'}
    
    async def send_alert(self, alert: Dict):
        """Send alert to webhook"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=alert,
                    headers=self.headers
                ) as response:
                    if response.status == 200:
                        logger.info("Webhook alert sent successfully")
                    else:
                        logger.error(f"Webhook error: {response.status}")
        
        except Exception as e:
            logger.error(f"Webhook alert failed: {e}")


class AlertManager:
    """
    Centralized alert management system
    Coordinates multiple alert channels with deduplication
    """
    
    def __init__(
        self,
        dedup_window: int = 60,
        max_alerts_per_window: int = 5,
        min_confidence: float = 0.6,
        min_vote_count: Optional[int] = None
    ):
        """
        Args:
            dedup_window: Deduplication window in seconds
            max_alerts_per_window: Max alerts per source in window
            min_confidence: Minimum confidence for alerts
            min_vote_count: Minimum number of model votes required (None = use default from detection)
        """
        self.deduplicator = AlertDeduplicator(dedup_window, max_alerts_per_window)
        self.min_confidence = min_confidence
        self.min_vote_count = min_vote_count
        self.alerters = []
        self.stats = {
            'total_alerts': 0,
            'sent_alerts': 0,
            'suppressed_alerts': 0,
            'low_confidence_skipped': 0,
            'low_votes_skipped': 0
        }
    
    def add_alerter(self, alerter):
        """Add an alert channel"""
        self.alerters.append(alerter)
        logger.info(f"Added alerter: {alerter.__class__.__name__}")
    
    async def send_alert(self, alert: Dict):
        """
        Send alert through all channels

        Args:
            alert: Alert dictionary with detection info
        """
        self.stats['total_alerts'] += 1

        # ============================================
        # 🗳️ VOTING THRESHOLD CHECK
        # ============================================
        # Only send alert if weighted_vote meets the threshold
        ensemble_votes = alert.get('ensemble_votes', {})
        weighted_vote = ensemble_votes.get('weighted_vote', 0)
        vote_threshold = ensemble_votes.get('threshold', 0)

        # Check if votes meet detection threshold
        # Use weighted_vote (not total_votes) for weighted voting system
        if self.min_vote_count is not None and weighted_vote < self.min_vote_count:
            self.stats['low_votes_skipped'] += 1
            logger.info(
                f"Alert skipped (insufficient weighted votes): {weighted_vote}/{self.min_vote_count} "
                f"(detection threshold: {vote_threshold})"
            )
            return

        # Alternative: Only alert if it actually triggered the detector's own threshold
        # This ensures alerts are only sent for detections that passed the voting threshold
        if weighted_vote < vote_threshold:
            self.stats['low_votes_skipped'] += 1
            logger.info(
                f"Alert skipped (below detection threshold): {weighted_vote}/{vote_threshold}"
            )
            return

        # Check confidence threshold
        if alert.get('confidence_score', 0) < self.min_confidence:
            self.stats['low_confidence_skipped'] += 1
            logger.info(f"Alert skipped (low confidence): {alert.get('confidence_score', 0):.2%}")
            return

        # Check deduplication
        if not self.deduplicator.should_send_alert(alert):
            self.stats['suppressed_alerts'] += 1
            logger.info("Alert suppressed (duplicate)")
            return
        
        # Add metadata
        alert['timestamp'] = alert.get('timestamp', datetime.now().isoformat())
        alert['dashboard_url'] = alert.get('dashboard_url', 'http://localhost:8501')
        alert['suppressed_count'] = self.deduplicator.get_suppressed_count(alert)
        
        # Send to all channels
        tasks = [alerter.send_alert(alert) for alerter in self.alerters]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.stats['sent_alerts'] += 1
        logger.info(f"Alert sent through {len(self.alerters)} channels")
    
    def get_stats(self) -> Dict:
        """Get alerting statistics"""
        return self.stats.copy()


# Configuration loader
def load_alert_config(config_file: str = "alerting/alert_config.json") -> AlertManager:
    """
    Load alert configuration from JSON file
    
    Example config:
    {
        "dedup_window": 60,
        "max_alerts_per_window": 5,
        "min_confidence": 0.7,
        "min_vote_count": null,
        "telegram": {
            "enabled": true,
            "bot_token": "YOUR_BOT_TOKEN",
            "chat_ids": ["CHAT_ID1", "CHAT_ID2"]
        },
        "email": {
            "enabled": true,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "username": "your-email@gmail.com",
            "password": "your-password",
            "from_addr": "alerts@yourdomain.com",
            "to_addrs": ["admin@yourdomain.com"]
        },
        "slack": {
            "enabled": true,
            "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        },
        "webhook": {
            "enabled": false,
            "url": "https://your-webhook-endpoint.com/alerts"
        }
    }
    """
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        manager = AlertManager(
            dedup_window=config.get('dedup_window', 60),
            max_alerts_per_window=config.get('max_alerts_per_window', 5),
            min_confidence=config.get('min_confidence', 0.7),
            min_vote_count=config.get('min_vote_count')  # None = use detection threshold
        )
        
        # Add Telegram
        if config.get('telegram', {}).get('enabled'):
            telegram_config = config['telegram']
            manager.add_alerter(TelegramAlerter(
                bot_token=telegram_config['bot_token'],
                chat_ids=telegram_config['chat_ids']
            ))
        
        # Add Email
        if config.get('email', {}).get('enabled'):
            email_config = config['email']
            manager.add_alerter(EmailAlerter(
                smtp_server=email_config['smtp_server'],
                smtp_port=email_config['smtp_port'],
                username=email_config['username'],
                password=email_config['password'],
                from_addr=email_config['from_addr'],
                to_addrs=email_config['to_addrs']
            ))
        
        # Add Slack
        if config.get('slack', {}).get('enabled'):
            slack_config = config['slack']
            manager.add_alerter(SlackAlerter(
                webhook_url=slack_config['webhook_url']
            ))
        
        # Add Webhook
        if config.get('webhook', {}).get('enabled'):
            webhook_config = config['webhook']
            manager.add_alerter(WebhookAlerter(
                webhook_url=webhook_config['url'],
                headers=webhook_config.get('headers')
            ))
        
        logger.info(f"Loaded {len(manager.alerters)} alerters")
        return manager
    
    except FileNotFoundError:
        logger.warning(f"Config file not found: {config_file}")
        return AlertManager()
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return AlertManager()


# Example usage
async def example_usage():
    """Example of how to use the alert system"""
    
    # Create alert manager
    manager = AlertManager(
        dedup_window=60,
        max_alerts_per_window=3,
        min_confidence=0.7
    )
    
    # Add alerters (use environment variables in production)
    if os.getenv('TELEGRAM_BOT_TOKEN'):
        manager.add_alerter(TelegramAlerter(
            bot_token=os.getenv('TELEGRAM_BOT_TOKEN'),
            chat_ids=[os.getenv('TELEGRAM_CHAT_ID')]
        ))
    
    if os.getenv('SLACK_WEBHOOK_URL'):
        manager.add_alerter(SlackAlerter(
            webhook_url=os.getenv('SLACK_WEBHOOK_URL')
        ))
    
    # Sample alert
    alert = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'protocol': 'TCP',
        'attack_type': 'DDoS',
        'confidence_score': 0.95,
        'severity': 'high',
        'flow_duration': 5000,
        'total_packets': 1500,
        'flow_bytes_per_sec': 2000000,
        'ensemble_votes': {
            'random_forest': 1,
            'xgboost': 1,
            'isolation_forest': 1,
            'kmeans': 0,
            'signature': 1,
            'total_votes': 4,
            'threshold': 3
        }
    }
    
    # Send alert
    await manager.send_alert(alert)
    
    # Get statistics
    print(f"Alert stats: {manager.get_stats()}")


if __name__ == "__main__":
    asyncio.run(example_usage())
