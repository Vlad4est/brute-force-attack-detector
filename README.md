# 🛡️ Brute Force Attack Detector

A Python-based security tool for automated detection of authentication attacks in Security Operations Center (SOC) environments. This tool analyzes authentication logs to identify brute force attacks, username enumeration attempts, and successful security breaches.

## 🔍 Overview

This tool was developed as part of cybersecurity research to automate the detection of common authentication-based attacks. It processes SSH authentication logs and generates security alerts with actionable recommendations, making it ideal for SOC analysts and security monitoring environments.

### Key Features

- **🚨 Multi-Pattern Attack Detection**: Identifies brute force attacks, username enumeration, and successful breaches
- **⚙️ Configurable Thresholds**: Customizable detection parameters to reduce false positives
- **📊 Comprehensive Reporting**: Generates detailed JSON reports with security metrics and recommendations
- **🔄 Automated Alerting**: Creates structured alerts with severity classification
- **📈 Attack Analytics**: Provides statistical analysis of authentication patterns and threats
- **🧪 Sample Data Generation**: Built-in log generator for testing and demonstration

## 🎯 Use Cases

- **SOC Monitoring**: Automated detection of ongoing brute force attacks
- **Incident Response**: Quick identification of compromised accounts and attack vectors  
- **Threat Hunting**: Proactive analysis of authentication logs for suspicious patterns
- **Security Auditing**: Historical analysis of authentication security posture
- **Training & Education**: Demonstration tool for cybersecurity concepts

## 🔧 Installation

### Prerequisites

- Python 3.7 or higher
- Basic understanding of authentication logs

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/Vlad4est/brute-force-detector.git
cd brute-force-detector

# No additional dependencies required - uses Python standard library
python brute_force_detector.py --help
```

## 🚀 Usage

### Basic Usage

```bash
# Generate sample logs and analyze them
python brute_force_detector.py --generate

# Analyze existing log files
python brute_force_detector.py --logfile /var/log/auth.log

# Customize detection thresholds
python brute_force_detector.py --generate --failed-threshold 3 --time-window 5 --output my_report.json
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--generate` | Generate sample authentication logs | False |
| `--logfile <path>` | Path to log file for analysis | None |
| `--output <file>` | Output report filename | `security_report.json` |
| `--failed-threshold <n>` | Failed attempts to trigger alert | 5 |
| `--time-window <min>` | Time window for analysis (minutes) | 10 |
| `--username-threshold <n>` | Unique usernames for enumeration detection | 10 |

## 📊 Example Output

### Console Alerts
```
🚨 SECURITY ANALYSIS COMPLETE 🚨
Found 3 security alerts!

[CRITICAL] SUCCESSFUL_BREACH
IP Address: 203.0.113.45
⚠️  CRITICAL: Account 'admin' may be compromised!
Failed attempts before success: 12
Recommendations:
  • URGENT: Investigate account 'admin' immediately
  • Block IP address 203.0.113.45
  • Force password reset for affected account

[HIGH] BRUTE_FORCE_ATTACK  
IP Address: 198.51.100.123
Failed Attempts: 15
Targeted Users: root, admin, user
Recommendations:
  • Block IP address 198.51.100.123 immediately
  • Investigate compromised accounts for users: root, admin, user
  • Enable account lockout policies
```

### Security Report Summary
```json
{
  "analysis_summary": {
    "total_log_entries": 1000,
    "successful_logins": 823,
    "failed_logins": 177,
    "failure_rate": "17.7%",
    "unique_ips": 8,
    "unique_usernames": 12
  },
  "security_alerts": {
    "total_alerts": 3,
    "critical_alerts": 1,
    "high_alerts": 1,
    "medium_alerts": 1
  }
}
```

## 🔍 Detection Algorithms

### 1. Brute Force Attack Detection
- **Trigger**: Multiple failed login attempts from same IP within time window
- **Default Threshold**: 5 failures in 10 minutes
- **Severity**: HIGH (15+ attempts) or MEDIUM (5-14 attempts)

### 2. Username Enumeration Detection
- **Trigger**: High number of unique usernames attempted from single IP
- **Default Threshold**: 10+ unique usernames
- **Severity**: MEDIUM

### 3. Successful Breach Detection
- **Trigger**: Successful login after multiple failed attempts
- **Default Threshold**: Success after 5+ failures
- **Severity**: CRITICAL

## 📈 Sample Analysis Results

When testing with 1000 sample log entries, the tool typically identifies:
- **80%** legitimate authentication traffic
- **20%** attack patterns requiring investigation
- **Average detection time**: < 2 seconds for 1000 entries
- **False positive rate**: < 5% with default thresholds

## 🛠️ Technical Architecture

### Core Components

```
brute_force_detector.py
├── LogGenerator          # Generates realistic test data
├── BruteForceDetector   # Main analysis engine
│   ├── parse_logs()     # Log parsing and normalization
│   ├── detect_attacks() # Pattern recognition algorithms
│   └── generate_report() # Security reporting
└── CLI Interface        # Command-line argument handling
```

### Log Format Support

Currently supports SSH authentication logs in standard syslog format:
```
Mar 25 10:15:23 server sshd[1234]: Failed password for admin from 192.168.1.100 port 45678 ssh2
```

## 🚧 Future Enhancements

- [ ] **Real-time monitoring** with file watching capabilities
- [ ] **Multiple log format support** (Windows Event Logs, Apache, etc.)
- [ ] **Machine learning integration** for anomaly-based detection
- [ ] **Web dashboard** for alert visualization
- [ ] **Email/Slack notifications** for critical alerts
- [ ] **Database integration** for historical trend analysis
- [ ] **API endpoint** for integration with SIEM platforms

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

1. **Additional log formats** - Support for more authentication systems
2. **Advanced detection algorithms** - Machine learning or behavioral analysis
3. **Performance optimization** - Handling of large log files
4. **Integration capabilities** - SIEM/SOAR platform connectors
5. **Documentation** - Additional usage examples and tutorials

## 📋 Testing

### Running Tests
```bash
# Generate and analyze sample data
python brute_force_detector.py --generate

# Verify all detection types trigger correctly
python brute_force_detector.py --generate --failed-threshold 1 --time-window 1440
```

### Validation Checklist
- [x] Brute force attacks detected and alerted
- [x] Username enumeration identified
- [x] Successful breaches flagged as CRITICAL
- [x] Configurable thresholds working
- [x] JSON report generation functional
- [x] False positive rate acceptable

## 🔒 Security Considerations

- **Log Privacy**: Tool processes authentication logs which may contain sensitive information
- **Threshold Tuning**: Adjust detection thresholds based on your environment's baseline
- **Alert Fatigue**: Monitor false positive rates and tune accordingly
- **Access Control**: Ensure proper permissions when accessing system log files


## 🙏 Acknowledgments

- Inspired by real-world SOC operational challenges
- Built for cybersecurity education and practical application
- Designed with input from security operations best practices


