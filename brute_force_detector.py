#!/usr/bin/env python3
"""
Brute Force Attack Detector
A security tool that analyzes authentication logs to detect brute force attacks.

Author: Vlad Pădure
Purpose: Cybersecurity internship portfolio project
"""

import re
import json
import random
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import List, Dict, Tuple

@dataclass
class LogEntry:
    """Represents a single authentication log entry"""
    timestamp: datetime
    ip_address: str
    username: str
    status: str  # 'SUCCESS' or 'FAILED'
    port: int
    raw_log: str

@dataclass
class Alert:
    """Represents a security alert"""
    alert_type: str
    severity: str
    ip_address: str
    details: Dict
    timestamp: datetime
    recommendations: List[str]

class LogGenerator:
    """Generates realistic authentication logs for testing"""
    
    def __init__(self):
        self.legitimate_users = ['john', 'admin', 'user', 'service', 'backup']
        self.common_attack_users = ['root', 'administrator', 'admin', 'test', 'guest', 'oracle', 'postgres']
        self.legitimate_ips = ['192.168.1.10', '192.168.1.20', '10.0.0.5', '172.16.0.100']
        self.attack_ips = ['203.0.113.45', '198.51.100.123', '192.0.2.88', '185.220.101.42']
    
    def generate_logs(self, count: int = 1000) -> List[str]:
        """Generate realistic SSH authentication logs"""
        logs = []
        base_time = datetime.now() - timedelta(hours=24)
        
        for i in range(count):
            # 80% legitimate traffic, 20% attacks
            if random.random() < 0.95:
                log_entry = self._generate_legitimate_log(base_time + timedelta(minutes=random.randint(0, 1440)))
            else:
                log_entry = self._generate_attack_log(base_time + timedelta(minutes=random.randint(0, 1440)))
            
            logs.append(log_entry)
        
        # Sort by timestamp
        logs.sort(key=lambda x: self._extract_timestamp(x))
        return logs
    
    def _generate_legitimate_log(self, timestamp: datetime) -> str:
        """Generate a legitimate authentication log"""
        user = random.choice(self.legitimate_users)
        ip = random.choice(self.legitimate_ips)
        port = random.randint(49152, 65535)
        
        # 95% successful logins for legitimate users
        if random.random() < 0.95:
            status = "Accepted password"
        else:
            status = "Failed password"
        
        return f"{timestamp.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000, 9999)}]: {status} for {user} from {ip} port {port} ssh2"
    
    def _generate_attack_log(self, timestamp: datetime) -> str:
        """Generate an attack log (brute force attempt)"""
        user = random.choice(self.common_attack_users)
        ip = random.choice(self.attack_ips)
        port = random.randint(49152, 65535)
        
        # 98% failed logins for attacks
        if random.random() < 0.99:
            status = "Failed password"
        else:
            status = "Accepted password"  # Successful breach!
        
        return f"{timestamp.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000, 9999)}]: {status} for {user} from {ip} port {port} ssh2"
    
    def _extract_timestamp(self, log_line: str) -> datetime:
        """Extract timestamp from log line for sorting"""
        match = re.match(r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})', log_line)
        if match:
            time_str = match.group(1)
            return datetime.strptime(f"{datetime.now().year} {time_str}", "%Y %b %d %H:%M:%S")
        return datetime.now()

class BruteForceDetector:
    """Main detector class for analyzing authentication logs"""
    
    def __init__(self, failed_threshold: int = 5, time_window: int = 10, username_threshold: int = 10):
        """
        Initialize detector with configurable thresholds
        
        Args:
            failed_threshold: Number of failed attempts to trigger alert
            time_window: Time window in minutes for analysis
            username_threshold: Number of different usernames for enumeration detection
        """
        self.failed_threshold = failed_threshold
        self.time_window = time_window
        self.username_threshold = username_threshold
        self.log_entries: List[LogEntry] = []
        self.alerts: List[Alert] = []
    
    def parse_logs(self, log_lines: List[str]) -> None:
        """Parse authentication logs into structured format"""
        self.log_entries = []
        
        for line in log_lines:
            entry = self._parse_log_line(line)
            if entry:
                self.log_entries.append(entry)
        
        # Sort by timestamp
        self.log_entries.sort(key=lambda x: x.timestamp)
        print(f"Parsed {len(self.log_entries)} log entries")
    
    def _parse_log_line(self, line: str) -> LogEntry:
        """Parse a single log line into a LogEntry object"""
        # SSH log pattern: Mon DD HH:MM:SS server sshd[PID]: Status for user from IP port PORT ssh2
        pattern = r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) \w+ sshd\[\d+\]: (Accepted|Failed) password for (\w+) from ([\d.]+) port (\d+)'
        
        match = re.search(pattern, line)
        if not match:
            return None
        
        time_str, status, username, ip_address, port = match.groups()
        
        # Parse timestamp (assume current year)
        timestamp = datetime.strptime(f"{datetime.now().year} {time_str}", "%Y %b %d %H:%M:%S")
        
        return LogEntry(
            timestamp=timestamp,
            ip_address=ip_address,
            username=username,
            status='SUCCESS' if status == 'Accepted' else 'FAILED',
            port=int(port),
            raw_log=line
        )
    
    def detect_attacks(self) -> List[Alert]:
        """Main detection method - analyze logs for attack patterns"""
        self.alerts = []
        
        # Group logs by IP address
        ip_logs = defaultdict(list)
        for entry in self.log_entries:
            ip_logs[entry.ip_address].append(entry)
        
        for ip, logs in ip_logs.items():
            # Sort logs for this IP by timestamp
            logs.sort(key=lambda x: x.timestamp)
            
            # Detect brute force attacks
            self._detect_brute_force(ip, logs)
            
            # Detect username enumeration
            self._detect_username_enumeration(ip, logs)
            
            # Detect successful login after failures
            self._detect_successful_after_failures(ip, logs)
        
        return self.alerts
    
    def _detect_brute_force(self, ip: str, logs: List[LogEntry]) -> None:
        """Detect brute force attacks based on failed login frequency"""
        failed_logs = [log for log in logs if log.status == 'FAILED']
        
        if len(failed_logs) < self.failed_threshold:
            return
        
        # Check for rapid failed attempts within time window
        for i in range(len(failed_logs) - self.failed_threshold + 1):
            window_start = failed_logs[i].timestamp
            window_end = window_start + timedelta(minutes=self.time_window)
            
            window_failures = [
                log for log in failed_logs[i:]
                if window_start <= log.timestamp <= window_end
            ]
            
            if len(window_failures) >= self.failed_threshold:
                # Create alert
                usernames = list(set(log.username for log in window_failures))
                
                alert = Alert(
                    alert_type="BRUTE_FORCE_ATTACK",
                    severity="HIGH" if len(window_failures) > 15 else "MEDIUM",
                    ip_address=ip,
                    details={
                        "failed_attempts": len(window_failures),
                        "time_window_minutes": self.time_window,
                        "targeted_usernames": usernames,
                        "first_attempt": window_start.isoformat(),
                        "last_attempt": window_failures[-1].timestamp.isoformat()
                    },
                    timestamp=datetime.now(),
                    recommendations=[
                        f"Block IP address {ip} immediately",
                        "Investigate compromised accounts for users: " + ", ".join(usernames),
                        "Enable account lockout policies",
                        "Implement rate limiting for authentication"
                    ]
                )
                self.alerts.append(alert)
                break  # Only create one alert per IP
    
    def _detect_username_enumeration(self, ip: str, logs: List[LogEntry]) -> None:
        """Detect username enumeration attacks"""
        usernames = [log.username for log in logs if log.status == 'FAILED']
        unique_usernames = set(usernames)
        
        if len(unique_usernames) >= self.username_threshold:
            alert = Alert(
                alert_type="USERNAME_ENUMERATION",
                severity="MEDIUM",
                ip_address=ip,
                details={
                    "unique_usernames_tried": len(unique_usernames),
                    "total_attempts": len(usernames),
                    "usernames": list(unique_usernames)
                },
                timestamp=datetime.now(),
                recommendations=[
                    f"Block IP address {ip}",
                    "Review user account security",
                    "Implement generic authentication error messages",
                    "Monitor for account lockouts"
                ]
            )
            self.alerts.append(alert)
    
    def _detect_successful_after_failures(self, ip: str, logs: List[LogEntry]) -> None:
        """Detect successful login after multiple failures (potential breach)"""
        failed_count = 0
        
        for log in logs:
            if log.status == 'FAILED':
                failed_count += 1
            elif log.status == 'SUCCESS' and failed_count >= 5:
                alert = Alert(
                    alert_type="SUCCESSFUL_BREACH",
                    severity="CRITICAL",
                    ip_address=ip,
                    details={
                        "failed_attempts_before_success": failed_count,
                        "compromised_username": log.username,
                        "breach_time": log.timestamp.isoformat(),
                        "breach_port": log.port
                    },
                    timestamp=datetime.now(),
                    recommendations=[
                        f"URGENT: Investigate account '{log.username}' immediately",
                        f"Block IP address {ip}",
                        "Force password reset for affected account",
                        "Check for lateral movement",
                        "Review system logs for post-breach activity"
                    ]
                )
                self.alerts.append(alert)
                failed_count = 0  # Reset counter
    
    def generate_report(self) -> Dict:
        """Generate comprehensive security report"""
        total_entries = len(self.log_entries)
        failed_logins = len([log for log in self.log_entries if log.status == 'FAILED'])
        successful_logins = total_entries - failed_logins
        
        # IP statistics
        ip_stats = Counter(log.ip_address for log in self.log_entries)
        suspicious_ips = [ip for ip, count in ip_stats.items() if count > 20]
        
        # Username statistics
        username_stats = Counter(log.username for log in self.log_entries)
        
        report = {
            "analysis_summary": {
                "total_log_entries": total_entries,
                "successful_logins": successful_logins,
                "failed_logins": failed_logins,
                "failure_rate": f"{(failed_logins/total_entries*100):.1f}%" if total_entries > 0 else "0%",
                "unique_ips": len(ip_stats),
                "unique_usernames": len(username_stats)
            },
            "security_alerts": {
                "total_alerts": len(self.alerts),
                "critical_alerts": len([a for a in self.alerts if a.severity == "CRITICAL"]),
                "high_alerts": len([a for a in self.alerts if a.severity == "HIGH"]),
                "medium_alerts": len([a for a in self.alerts if a.severity == "MEDIUM"])
            },
            "top_suspicious_ips": dict(ip_stats.most_common(10)),
            "most_targeted_usernames": dict(username_stats.most_common(10)),
            "alerts": [self._alert_to_dict(alert) for alert in self.alerts],
            "generated_at": datetime.now().isoformat()
        }
        
        return report
    
    def _alert_to_dict(self, alert: Alert) -> Dict:
        """Convert Alert object to dictionary for JSON serialization"""
        return {
            "type": alert.alert_type,
            "severity": alert.severity,
            "ip_address": alert.ip_address,
            "details": alert.details,
            "timestamp": alert.timestamp.isoformat(),
            "recommendations": alert.recommendations
        }

def main():
    """Main function with CLI interface"""
    parser = argparse.ArgumentParser(description="Brute Force Attack Detector")
    parser.add_argument("--generate", action="store_true", help="Generate sample logs for testing")
    parser.add_argument("--logfile", type=str, help="Path to log file to analyze")
    parser.add_argument("--output", type=str, default="security_report.json", help="Output report file")
    parser.add_argument("--failed-threshold", type=int, default=5, help="Failed attempts threshold")
    parser.add_argument("--time-window", type=int, default=10, help="Time window in minutes")
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = BruteForceDetector(
        failed_threshold=args.failed_threshold,
        time_window=args.time_window
    )
    
    # Get log data
    if args.generate:
        print("Generating sample authentication logs...")
        generator = LogGenerator()
        log_lines = generator.generate_logs(1000)
        print(f"Generated {len(log_lines)} log entries")
        
        # Save sample logs for reference
        with open("sample_auth.log", "w") as f:
            f.write("\n".join(log_lines))
        print("Sample logs saved to sample_auth.log")
        
    elif args.logfile:
        print(f"Reading logs from {args.logfile}")
        try:
            with open(args.logfile, "r") as f:
                log_lines = f.readlines()
        except FileNotFoundError:
            print(f"Error: File {args.logfile} not found")
            return
    else:
        print("Generating sample logs for demo (use --logfile to analyze real logs)")
        generator = LogGenerator()
        log_lines = generator.generate_logs(1000)
    
    # Analyze logs
    print("\nAnalyzing authentication logs...")
    detector.parse_logs(log_lines)
    
    print("Detecting attack patterns...")
    alerts = detector.detect_attacks()
    
    # Display results
    print(f"\n🚨 SECURITY ANALYSIS COMPLETE 🚨")
    print(f"Found {len(alerts)} security alerts!")
    
    for alert in sorted(alerts, key=lambda x: x.severity, reverse=True):
        print(f"\n[{alert.severity}] {alert.alert_type}")
        print(f"IP Address: {alert.ip_address}")
        if alert.alert_type == "BRUTE_FORCE_ATTACK":
            print(f"Failed Attempts: {alert.details['failed_attempts']}")
            print(f"Targeted Users: {', '.join(alert.details['targeted_usernames'])}")
        elif alert.alert_type == "SUCCESSFUL_BREACH":
            print(f"⚠️  CRITICAL: Account '{alert.details['compromised_username']}' may be compromised!")
            print(f"Failed attempts before success: {alert.details['failed_attempts_before_success']}")
        
        print("Recommendations:")
        for rec in alert.recommendations[:3]:  # Show top 3 recommendations
            print(f"  • {rec}")
    
    # Generate and save report
    print(f"\nGenerating detailed report...")
    report = detector.generate_report()
    
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"📊 Security report saved to {args.output}")
    print(f"\nSummary:")
    print(f"  Total Log Entries: {report['analysis_summary']['total_log_entries']}")
    print(f"  Failed Login Rate: {report['analysis_summary']['failure_rate']}")
    print(f"  Security Alerts: {report['security_alerts']['total_alerts']}")
    print(f"  Critical Alerts: {report['security_alerts']['critical_alerts']}")

if __name__ == "__main__":
    main()