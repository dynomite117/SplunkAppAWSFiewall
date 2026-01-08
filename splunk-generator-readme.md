# AWS Firewall Monitoring - Splunk App Generator

A Python script that generates a complete, production-ready Splunk app for monitoring AWS Network Firewall and VPC Flow Logs with comprehensive threat intelligence, compliance reporting, and advanced threat hunting capabilities.

## Overview

This generator creates a fully-configured Splunk app package that can be deployed directly to Splunk Enterprise or Splunk Cloud. The generated app includes dashboards, alerts, field extractions, lookup tables, and compliance mappings ready for immediate use.

## Features

### Generated App Includes

#### 📊 **5 Interactive Dashboards**
1. **AWS Firewall & Flow Logs Dashboard** - Main operational monitoring
2. **Threat Intelligence Dashboard** - Known threat tracking and analysis
3. **Network Traffic Analysis** - Deep network insights and patterns
4. **Compliance & Audit Dashboard** - Multi-framework regulatory compliance
5. **Advanced Threat Analysis** - MITRE ATT&CK and threat hunting

#### 🚨 **16 Automated Alerts**
- **3 Critical Severity**: High alert volume, known threat actors, rule failures
- **5 High Severity**: DDoS patterns, SQL/command injection, connection spikes
- **4 Medium Severity**: Port scanning, data exfiltration, suspicious DNS
- **4 Compliance Reports**: Daily/weekly summaries for regulatory frameworks

#### 🔍 **40+ Custom Field Extractions**
- Network Firewall alerts (basic, rule-specific, packet/flow data)
- HTTP/Application layer (method, URL, user agent, status)
- TLS/SSL information (SNI, version, certificates)
- DNS queries (query name, type, response code)
- TCP layer details (flags, sequence numbers, acknowledgments)
- VPC Flow Logs (14-field format parsing)

#### 📚 **6 Lookup Tables**
1. **Threat Intelligence IPs** - Malicious IP reputation database
2. **AWS Service Ports** - Common AWS service port mappings
3. **Firewall Rule Compliance** - Maps rules to regulatory frameworks
4. **MITRE ATT&CK Mapping** - Links signatures to attack techniques
5. **Cyber Kill Chain** - Attack stage classification
6. **CVE Database** - Vulnerability exploit tracking

#### 🎯 **Compliance Frameworks Supported**
- PCI-DSS (Requirements 1.2, 1.3, 10.6)
- HIPAA (164.312(e)(1), 164.312(a)(1))
- SOC 2 (CC6.6, CC6.7)
- NIST Cybersecurity Framework (PR.AC-5, DE.CM-1)
- CIS Controls (13.1, 13.2)
- ISO 27001 (A.13.1.1, A.13.1.3)

## Requirements

### System Requirements
- Python 3.6 or higher
- Write permissions to create directories and files

### Target Splunk Environment
- Splunk Enterprise 8.0+ or Splunk Cloud
- AWS Add-on for Splunk (for data ingestion)
- AWS CloudWatch Logs or S3 configured as data source

### AWS Prerequisites
- AWS Network Firewall configured and logging enabled
- VPC Flow Logs enabled and configured
- CloudWatch Logs or S3 bucket with appropriate permissions

## Installation

### Step 1: Download the Generator

```bash
# Save the Python script
curl -O https://your-repo/aws_firewall_app_generator.py

# Or clone the repository
git clone https://your-repo/splunk-aws-firewall-generator.git
cd splunk-aws-firewall-generator
```

### Step 2: Run the Generator

```bash
# Run with default settings
python3 aws_firewall_app_generator.py

# Or customize the app name and label
python3 -c "
from aws_firewall_app_generator import create_aws_firewall_app
create_aws_firewall_app(
    app_name='my_custom_firewall_app',
    app_label='My Custom Firewall Monitor'
)
"
```

### Step 3: Review Generated Files

```bash
# Check the generated app structure
tree aws_firewall_monitor/

# Output will show:
aws_firewall_monitor/
├── default/
│   ├── app.conf
│   ├── data/
│   │   └── ui/
│   │       └── views/
│   │           ├── firewall_dashboard.xml
│   │           ├── threat_intelligence.xml
│   │           ├── network_analysis.xml
│   │           ├── compliance_audit.xml
│   │           └── threat_analysis.xml
│   ├── macros.conf
│   ├── props.conf
│   ├── savedsearches.conf
│   └── transforms.conf
├── lookups/
│   ├── attack_killchain.csv
│   ├── aws_service_ports.csv
│   ├── cve_database.csv
│   ├── firewall_rule_compliance.csv
│   ├── mitre_attack_mapping.csv
│   └── threat_intel_ips.csv
├── metadata/
│   └── default.meta
├── local/
├── bin/
├── static/
├── appserver/
└── README.md
```

### Step 4: Deploy to Splunk

```bash
# Copy to Splunk apps directory
sudo cp -r aws_firewall_monitor $SPLUNK_HOME/etc/apps/

# Set proper ownership
sudo chown -R splunk:splunk $SPLUNK_HOME/etc/apps/aws_firewall_monitor

# Restart Splunk
sudo $SPLUNK_HOME/bin/splunk restart
```

## Configuration

### 1. Configure AWS Data Inputs

#### Option A: Using Splunk Add-on for AWS (Recommended)

1. Install the Splunk Add-on for AWS from Splunkbase
2. Configure CloudWatch Logs inputs:

```conf
[aws_cloudwatch://<your_input_name>]
account = <your_aws_account>
region = us-east-1
log_group_name = /aws/networkfirewall/alert
log_stream_name_pattern = *
sourcetype = aws:networkfirewall:alert
index = aws
```

```conf
[aws_cloudwatch://<your_vpc_flow_input>]
account = <your_aws_account>
region = us-east-1
log_group_name = /aws/vpc/flowlogs
log_stream_name_pattern = *
sourcetype = aws:cloudwatchlogs:vpcflow
index = aws
```

#### Option B: Using S3 Input

```conf
[aws_s3://<your_input_name>]
aws_account = <your_aws_account>
bucket_name = <your_bucket>
sourcetype = aws:networkfirewall:alert
index = aws
```

### 2. Update Alert Email Recipients

Edit `$SPLUNK_HOME/etc/apps/aws_firewall_monitor/local/savedsearches.conf`:

```conf
[AWS Firewall - Critical: High Alert Volume]
action.email.to = security-ops@yourcompany.com,soc@yourcompany.com

[AWS Firewall - High: SQL Injection Attempts]
action.email.to = appsec@yourcompany.com,security-ops@yourcompany.com
```

### 3. Customize Alert Thresholds

Adjust thresholds based on your environment size and traffic patterns:

```conf
# Example: Adjust DDoS detection for smaller environments
[AWS Firewall - High: DDoS Attack Pattern]
search = ... | where total_packets > 5000 ...  # Default was 10000

# Example: Adjust data exfiltration threshold
[VPC Flow Logs - Medium: Data Exfiltration Detection]
search = ... | where total_bytes > 21474836480 ...  # Default was 53687091200 (50GB)
```

### 4. Populate Lookup Tables

#### Update Threat Intelligence

Edit `lookups/threat_intel_ips.csv`:

```csv
ip,threat_level,threat_category,last_seen,notes
1.2.3.4,critical,apt,2026-01-07,Known APT28 infrastructure
5.6.7.8,high,scanner,2026-01-06,Mass scanning source
```

#### Map Your Firewall Rules to Compliance

Edit `lookups/firewall_rule_compliance.csv`:

```csv
rule_id,compliance_framework,compliance_requirement,violation_severity,description
your-rule-001,PCI-DSS,Requirement 1.2.1,critical,Blocks unauthorized inbound traffic
your-rule-002,HIPAA,164.312(e)(1),high,Enforces transmission encryption
```

#### Map Signatures to MITRE ATT&CK

Edit `lookups/mitre_attack_mapping.csv`:

```csv
signature,technique_id,technique_name,tactic
Your Custom Signature,T1190,Exploit Public-Facing Application,Initial Access
SQL Injection Attempt,T1190,Exploit Public-Facing Application,Initial Access
```

### 5. Verify Installation

```bash
# Check if app is loaded
$SPLUNK_HOME/bin/splunk list app | grep aws_firewall_monitor

# Verify data is being ingested
# In Splunk Search:
index=aws sourcetype=aws:* | stats count by sourcetype

# Test field extractions
index=aws sourcetype=aws:networkfirewall:alert 
| table _time, src_ip, dest_ip, signature, rule_group_name
| head 10

# Verify lookups are working
| inputlookup threat_intel_ips.csv | head 10
```

## Customization Guide

### Adding Custom Alerts

Create a new file: `$SPLUNK_HOME/etc/apps/aws_firewall_monitor/local/savedsearches.conf`

```conf
[My Custom Alert]
action.email = 1
action.email.to = team@company.com
action.email.subject = Custom Alert Triggered
alert.suppress = 1
alert.suppress.period = 1h
alert.track = 1
cron_schedule = */15 * * * *
description = Custom alert for specific conditions
dispatch.earliest_time = -15m
dispatch.latest_time = now
enableSched = 1
search = `aws_firewall_alerts` your_custom_condition | where threshold
```

### Creating Custom Dashboards

1. Use Splunk Web UI to create a new dashboard
2. Add panels with your custom searches
3. Export the dashboard XML
4. Place in `default/data/ui/views/custom_dashboard.xml`

Or edit existing dashboards:

```xml
<row>
  <panel>
    <title>My Custom Panel</title>
    <table>
      <search>
        <query>`aws_firewall_alerts` | your custom search</query>
        <earliest>-24h</earliest>
        <latest>now</latest>
      </search>
    </table>
  </panel>
</row>
```

### Adding Custom Field Extractions

Edit `local/props.conf`:

```conf
[aws:networkfirewall:alert]
EXTRACT-custom_field = "custom_field":\s*"(?<custom_field>[^"]+)"
```

### Modifying Search Macros

Edit `local/macros.conf`:

```conf
[aws_firewall_alerts]
definition = index=YOUR_INDEX sourcetype=aws:networkfirewall:alert

[custom_time_range]
definition = earliest=-2h latest=now
iseval = 0
```

## Usage Examples

### Security Investigation Queries

#### Investigate Suspicious IP Activity

```spl
`aws_firewall_alerts` src_ip="1.2.3.4" 
| table _time, dest_ip, dest_port, signature, action, rule_group_name, http_url
| sort -_time
```

#### Track Lateral Movement

```spl
`vpc_flow_logs` dstport IN (445,135,139,3389,5985,5986) 
| stats dc(dstaddr) as unique_targets, sum(bytes) as total_bytes, count as connections by srcaddr 
| where unique_targets > 5
| eval total_mb=round(total_bytes/1024/1024, 2)
| sort -unique_targets
```

#### Find Exploitation Attempts for Specific CVE

```spl
`aws_firewall_alerts` signature="*CVE-2024-*" 
| rex field=signature "CVE-(?<cve_id>\d{4}-\d+)"
| lookup cve_database cve_id OUTPUT cvss_score, severity, description
| stats count as attempts, values(dest_ip) as targets, values(http_url) as urls by src_ip, cve_id, cvss_score
| sort -cvss_score, -attempts
```

### Compliance Queries

#### PCI-DSS Requirement 10.6 - Review Logs Daily

```spl
`aws_firewall_alerts` 
| lookup firewall_rule_compliance rule_id OUTPUT compliance_framework, compliance_requirement 
| where compliance_framework="PCI-DSS" AND compliance_requirement LIKE "%10.6%"
| stats count as events, dc(src_ip) as unique_sources, values(action) as actions by rule_group_name, signature
| sort -events
```

#### HIPAA Transmission Security Audit

```spl
`aws_firewall_alerts` 
| lookup firewall_rule_compliance rule_id OUTPUT compliance_framework 
| where compliance_framework="HIPAA"
| eval encryption_compliant=if(tls_version IN ("TLSv1.2","TLSv1.3"), "Yes", "No")
| stats count by encryption_compliant, tls_version, src_ip, dest_ip
```

### Threat Hunting Queries

#### Detect C2 Beaconing Behavior

```spl
`vpc_flow_logs` 
| bin _time span=1m 
| stats count, avg(bytes) as avg_bytes, stdev(bytes) as bytes_stdev by _time, srcaddr, dstaddr, dstport 
| eventstats avg(avg_bytes) as overall_avg, stdev(avg_bytes) as overall_stdev by srcaddr, dstaddr 
| where bytes_stdev < 50 AND count > 30 AND overall_stdev < 100
| stats count as beacon_count, values(_time) as beacon_times by srcaddr, dstaddr, dstport
```

#### Find DNS Tunneling

```spl
`aws_firewall_alerts` dns_query=* 
| eval query_length=len(dns_query)
| eval entropy=0
| where query_length > 50 OR entropy > 3.5
| stats count, values(dns_query) as suspicious_queries, dc(dns_query) as unique_queries by src_ip
| where count > 10
| sort -count
```

#### Identify Cryptomining Activity

```spl
`vpc_flow_logs` (dstport=3333 OR dstport=4444 OR dstport=5555 OR dstport=7777 OR dstport=8888 OR dstport=9999) 
| stats sum(bytes) as total_mining_traffic, count as connections, dc(dstaddr) as unique_pools, values(dstaddr) as mining_pools by srcaddr 
| eval traffic_gb=round(total_mining_traffic/1024/1024/1024, 2) 
| where connections > 100 OR traffic_gb > 1
| sort -traffic_gb
```

## Troubleshooting

### No Data Appearing in Dashboards

**Check data ingestion:**

```spl
index=_internal source=*metrics.log group=per_sourcetype_thruput 
| where series LIKE "aws:%" 
| timechart sum(kbps) by series
```

**Verify sourcetype:**

```spl
index=aws | stats count by sourcetype
```

**Check for parsing errors:**

```spl
index=_internal source=*splunkd.log ERROR 
| search aws_firewall_monitor OR "aws:networkfirewall" OR "aws:cloudwatchlogs:vpcflow"
```

### Field Extractions Not Working

**Test field extractions:**

```spl
index=aws sourcetype=aws:networkfirewall:alert 
| head 1 
| fieldsummary
```

**Check props.conf syntax:**

```bash
$SPLUNK_HOME/bin/splunk btool props list aws:networkfirewall:alert --debug
```

### Alerts Not Triggering

**Manually run alert search:**

```spl
# Copy search from savedsearches.conf and run manually
`aws_firewall_alerts` | stats count | where count > 500
```

**Check scheduler logs:**

```bash
tail -f $SPLUNK_HOME/var/log/splunk/scheduler.log | grep -i "aws firewall"
```

**Verify email server configuration:**

```bash
$SPLUNK_HOME/bin/splunk list monitor | grep email
```

### Lookups Not Working

**Test lookup manually:**

```spl
| inputlookup threat_intel_ips.csv 
| head 10
```

**Verify lookup definition:**

```spl
| rest /services/data/transforms/lookups 
| search title="threat_intel_ips"
| table title, filename
```

**Check file permissions:**

```bash
ls -la $SPLUNK_HOME/etc/apps/aws_firewall_monitor/lookups/
```

## Performance Optimization

### Index Configuration

For high-volume environments, configure dedicated indexes:

```conf
# indexes.conf
[aws_firewall]
homePath = $SPLUNK_DB/aws_firewall/db
coldPath = $SPLUNK_DB/aws_firewall/colddb
thawedPath = $SPLUNK_DB/aws_firewall/thaweddb
maxDataSize = auto_high_volume
frozenTimePeriodInSecs = 2592000  # 30 days
maxHotBuckets = 10
maxHotSpanSecs = 7200

[aws_vpc_flow]
homePath = $SPLUNK_DB/aws_vpc_flow/db
coldPath = $SPLUNK_DB/aws_vpc_flow/colddb
thawedPath = $SPLUNK_DB/aws_vpc_flow/thaweddb
maxDataSize = auto_high_volume
frozenTimePeriodInSecs = 1296000  # 15 days
maxHotBuckets = 6
maxHotSpanSecs = 3600
```

### Data Model Acceleration

Consider accelerating searches with data models for frequently-run queries:

```conf
# datamodels.conf
[AWS_Firewall_Data_Model]
acceleration = 1
acceleration.earliest_time = -7d
acceleration.max_time = 604800
```

### Summary Indexing

For expensive searches run frequently:

```conf
[summary - firewall daily stats]
cron_schedule = 5 0 * * *
enableSched = 1
dispatch.earliest_time = -1d@d
dispatch.latest_time = @d
search = `aws_firewall_alerts` | stats count by signature, action | collect index=summary_aws_firewall
```

## Maintenance

### Regular Tasks

| Frequency | Task | Command/Action |
|-----------|------|----------------|
| Daily | Review critical alerts | Check email and Splunk alerts |
| Daily | Verify data ingestion | `index=aws \| stats count by sourcetype` |
| Weekly | Update threat intelligence | Update `threat_intel_ips.csv` |
| Weekly | Review alert effectiveness | Check false positive rate |
| Monthly | Tune alert thresholds | Adjust based on environment changes |
| Monthly | Review compliance reports | Verify regulatory requirements met |
| Quarterly | Update compliance mappings | Add new rules to `firewall_rule_compliance.csv` |
| Quarterly | Review dashboard usage | Optimize slow panels |
| Annually | Archive old data | Adjust retention policies |

### Backup Procedures

```bash
# Backup entire app
tar -czf aws_firewall_monitor_backup_$(date +%Y%m%d).tar.gz \
    $SPLUNK_HOME/etc/apps/aws_firewall_monitor/

# Backup just configurations
tar -czf aws_firewall_config_$(date +%Y%m%d).tar.gz \
    $SPLUNK_HOME/etc/apps/aws_firewall_monitor/default/ \
    $SPLUNK_HOME/etc/apps/aws_firewall_monitor/local/

# Backup just lookups
tar -czf aws_firewall_lookups_$(date +%Y%m%d).tar.gz \
    $SPLUNK_HOME/etc/apps/aws_firewall_monitor/lookups/
```

### Updating the App

```bash
# Generate new version
python3 aws_firewall_app_generator.py

# Backup current version
mv $SPLUNK_HOME/etc/apps/aws_firewall_monitor \
   $SPLUNK_HOME/etc/apps/aws_firewall_monitor.backup

# Deploy new version
cp -r aws_firewall_monitor $SPLUNK_HOME/etc/apps/

# Restore custom configurations
cp $SPLUNK_HOME/etc/apps/aws_firewall_monitor.backup/local/* \
   $SPLUNK_HOME/etc/apps/aws_firewall_monitor/local/

# Restore custom lookups
cp $SPLUNK_HOME/etc/apps/aws_firewall_monitor.backup/lookups/* \
   $SPLUNK_HOME/etc/apps/aws_firewall_monitor/lookups/

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

## Advanced Features

### Integration with External Threat Feeds

Create a scheduled script to update threat intelligence:

```python
#!/usr/bin/env python3
import requests
import csv

# Fetch threat feed
response = requests.get('https://your-threat-feed.com/ips.json')
threat_data = response.json()

# Update lookup
with open('/opt/splunk/etc/apps/aws_firewall_monitor/lookups/threat_intel_ips.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerow(['ip', 'threat_level', 'threat_category', 'last_seen', 'notes'])
    for item in threat_data:
        writer.writerow([item['ip'], item['level'], item['category'], item['date'], item['description']])
```

### Automated Response with Splunk SOAR

Configure alert actions to trigger SOAR playbooks for automated response.

### Custom Visualizations

Add custom D3.js or third-party visualizations for enhanced dashboard capabilities.

## Support & Resources

### Documentation
- [AWS Network Firewall Documentation](https://docs.aws.amazon.com/network-firewall/)
- [VPC Flow Logs Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)
- [Splunk Add-on for AWS](https://splunkbase.splunk.com/app/1876/)

### Security Frameworks
- [MITRE ATT&CK](https://attack.mitre.org/)
- [PCI Security Standards](https://www.pcisecuritystandards.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)

### Community
- [Splunk Answers](https://community.splunk.com/)
- [Splunk Ideas](https://ideas.splunk.com/)
- [r/Splunk](https://www.reddit.com/r/Splunk/)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

[Specify your license here - e.g., MIT, Apache 2.0, etc.]

## Changelog

### Version 1.0.0 (2026-01-07)
- Initial release
- 5 dashboards (Firewall, Threat Intel, Network Analysis, Compliance, Threat Analysis)
- 16 tiered alerts (Critical, High, Medium, Reports)
- 40+ custom field extractions
- 6 lookup tables with threat intelligence and compliance mappings
- Support for 6 compliance frameworks
- MITRE ATT&CK integration
- Cyber kill chain mapping

## Authors

- Your Name/Organization
- Security Operations Team

## Acknowledgments

- AWS for Network Firewall and VPC Flow Logs
- Splunk community for best practices
- MITRE Corporation for ATT&CK framework
- Security teams who provided feedback

---

**Note**: This generator creates a foundational Splunk app. Customize thresholds, lookups, and configurations based on your specific environment and security requirements.