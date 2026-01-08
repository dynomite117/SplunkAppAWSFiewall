#!/usr/bin/env python3
"""
AWS Firewall Monitoring Splunk App Generator
Creates a Splunk app for AWS Network Firewall alerts and VPC Flow Logs
"""

import os
from pathlib import Path

def create_aws_firewall_app(app_name="aws_firewall_monitor", app_label="AWS Firewall Monitor"):
    """Create a complete Splunk app for AWS firewall monitoring"""
    
    # Create base directory
    base_dir = Path(app_name)
    
    # Directory structure
    dirs = [
        base_dir / "default",
        base_dir / "metadata",
        base_dir / "local",
        base_dir / "lookups",
        base_dir / "bin",
        base_dir / "static",
        base_dir / "appserver" / "static",
    ]
    
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    
    # app.conf - App configuration
    app_conf = f"""[install]
is_configured = 0

[ui]
is_visible = 1
label = {app_label}

[launcher]
author = Security Operations
description = AWS Network Firewall and VPC Flow Logs monitoring, alerting, and analysis
version = 1.0.0
"""
    
    # default.meta - Permissions
    default_meta = """[]
access = read : [ * ], write : [ admin, power ]
export = system
"""
    
    # savedsearches.conf - Saved searches and alerts
    savedsearches_conf = """# CRITICAL SEVERITY ALERTS (Immediate Response Required)

[AWS Firewall - Critical: High Alert Volume]
action.email = 1
action.email.to = security-ops@example.com
action.email.subject = CRITICAL: High AWS Firewall Alert Volume Detected
action.email.priority = 1
alert.suppress = 1
alert.suppress.period = 15m
alert.track = 1
alert.threshold = 500
cron_schedule = */5 * * * *
description = CRITICAL: Alert when firewall generates more than 500 alerts in 5 minutes
dispatch.earliest_time = -5m
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert | stats count | where count > 500

[AWS Firewall - Critical: Blocked Traffic from Known Bad IPs]
action.email = 1
action.email.to = security-ops@example.com,soc@example.com
action.email.subject = CRITICAL: Traffic Blocked from Known Threat Actors
action.email.priority = 1
alert.suppress = 1
alert.suppress.period = 30m
alert.track = 1
cron_schedule = */10 * * * *
description = CRITICAL: Alert when traffic is blocked from critical threat intelligence IPs
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert action=DROP | lookup threat_intel_ips ip as src_ip OUTPUT threat_level | where threat_level="critical" | stats count, values(dest_ip) as targets, values(signature) as attack_types by src_ip | where count > 5

[AWS Firewall - Critical: Rule Group Failures]
action.email = 1
action.email.to = security-ops@example.com,network-ops@example.com
action.email.subject = CRITICAL: Firewall Rule Group Not Triggering
alert.suppress = 1
alert.suppress.period = 1h
alert.track = 1
cron_schedule = */30 * * * *
description = CRITICAL: Alert when critical rule groups show no activity (may indicate misconfiguration)
dispatch.earliest_time = -30m
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert | stats count by rule_group_name | append [| makeresults | eval rule_group_name="critical-threats" | eval expected=1] | append [| makeresults | eval rule_group_name="malware-prevention" | eval expected=1] | stats sum(count) as activity_count, max(expected) as is_critical by rule_group_name | where is_critical=1 AND activity_count=0

# HIGH SEVERITY ALERTS

[VPC Flow Logs - High: Rejected Connection Spike]
action.email = 1
action.email.to = network-ops@example.com,security-ops@example.com
action.email.subject = HIGH: Spike in VPC Flow Log Rejections
alert.suppress = 1
alert.suppress.period = 30m
alert.track = 1
cron_schedule = */15 * * * *
description = HIGH: Alert when rejected connections exceed 3 standard deviations from baseline
dispatch.earliest_time = -15m
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:cloudwatchlogs:vpcflow action=REJECT | timechart span=5m count | trendline sma2(count) as trend | eval deviation=abs(count-trend) | stats avg(deviation) as avg_dev, stdev(deviation) as stdev_dev, latest(count) as latest_count | eval threshold=avg_dev+(3*stdev_dev) | where latest_count > threshold

[AWS Firewall - High: DDoS Attack Pattern]
action.email = 1
action.email.to = security-ops@example.com
action.email.subject = HIGH: Potential DDoS Attack Detected
alert.suppress = 1
alert.suppress.period = 30m
alert.track = 1
cron_schedule = */10 * * * *
description = HIGH: Detect DDoS patterns (high packet rate, low payload from single source)
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert | stats sum(packet_count) as total_packets, sum(byte_count) as total_bytes, dc(dest_ip) as unique_targets by src_ip | eval avg_packet_size=total_bytes/total_packets | where total_packets > 10000 AND avg_packet_size < 100 AND unique_targets > 5

[AWS Firewall - High: SQL Injection Attempts]
action.email = 1
action.email.to = security-ops@example.com,app-security@example.com
action.email.subject = HIGH: SQL Injection Attack Attempts
alert.suppress = 1
alert.suppress.period = 1h
alert.track = 1
alert.threshold = 10
cron_schedule = */15 * * * *
description = HIGH: Alert on SQL injection signature matches
dispatch.earliest_time = -15m
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert (signature="*SQL*Injection*" OR signature="*SQLi*" OR alert_category="SQL Injection") | stats count, values(dest_ip) as targeted_servers, values(http_url) as attempted_urls by src_ip | where count > 10

[AWS Firewall - High: Command Injection Attempts]
action.email = 1
action.email.to = security-ops@example.com,app-security@example.com
action.email.subject = HIGH: Command Injection Attack Attempts
alert.suppress = 1
alert.suppress.period = 1h
alert.track = 1
alert.threshold = 5
cron_schedule = */15 * * * *
description = HIGH: Alert on command injection attempts
dispatch.earliest_time = -15m
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert (signature="*Command*Injection*" OR signature="*RCE*" OR alert_category="Remote Code Execution") | stats count, values(dest_ip) as targets, values(http_url) as urls by src_ip | where count > 5

# MEDIUM SEVERITY ALERTS

[AWS Firewall - Medium: Suspicious Outbound Connections]
action.email = 1
action.email.to = security-ops@example.com
action.email.subject = MEDIUM: Suspicious Outbound Connections Detected
alert.suppress = 1
alert.suppress.period = 2h
alert.track = 1
cron_schedule = */20 * * * *
description = MEDIUM: Alert on outbound connections to non-standard ports from internal resources
dispatch.earliest_time = -20m
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert direction=outbound | search NOT (dest_port=80 OR dest_port=443 OR dest_port=22 OR dest_port=3389 OR dest_port=53) | stats count, values(dest_port) as ports, dc(dest_ip) as unique_destinations by src_ip | where count > 20

[VPC Flow Logs - Medium: Port Scanning Detection]
action.email = 1
action.email.to = security-ops@example.com
action.email.subject = MEDIUM: Potential Port Scan Detected
alert.suppress = 1
alert.suppress.period = 2h
alert.track = 1
cron_schedule = */30 * * * *
description = MEDIUM: Detect potential port scanning activity (same source hitting multiple ports)
dispatch.earliest_time = -30m
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:cloudwatchlogs:vpcflow | stats dc(dstport) as unique_ports, values(dstport) as ports_accessed, count as attempts by srcaddr, dstaddr | where unique_ports > 25 OR (unique_ports > 15 AND attempts > 100)

[VPC Flow Logs - Medium: Data Exfiltration Detection]
action.email = 1
action.email.to = security-ops@example.com,data-governance@example.com
action.email.subject = MEDIUM: Potential Data Exfiltration Detected
alert.suppress = 1
alert.suppress.period = 4h
alert.track = 1
cron_schedule = 0 */4 * * *
description = MEDIUM: Detect large outbound data transfers that may indicate exfiltration (>50GB)
dispatch.earliest_time = -4h
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:cloudwatchlogs:vpcflow action=ACCEPT | stats sum(bytes) as total_bytes by srcaddr, dstaddr | where total_bytes > 53687091200 | eval total_gb=round(total_bytes/1024/1024/1024, 2) | sort -total_gb

[AWS Firewall - Medium: Suspicious DNS Queries]
action.email = 1
action.email.to = security-ops@example.com
action.email.subject = MEDIUM: Suspicious DNS Activity Detected
alert.suppress = 1
alert.suppress.period = 2h
alert.track = 1
cron_schedule = */30 * * * *
description = MEDIUM: Alert on DNS tunneling or suspicious domain queries
dispatch.earliest_time = -30m
dispatch.latest_time = now
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert dns_query=* | eval query_length=len(dns_query) | where query_length > 50 OR dns_query="*dga*" OR dns_query="*malware*" | stats count, values(dns_query) as queries by src_ip | where count > 10

# INFORMATIONAL/COMPLIANCE REPORTS

[VPC Flow Logs - Daily: Top Talkers Report]
action.email = 1
action.email.to = network-ops@example.com
action.email.subject = Daily Network Traffic Report - Top Talkers
cron_schedule = 0 8 * * *
description = Daily report of top 50 source IPs by traffic volume
dispatch.earliest_time = -24h@h
dispatch.latest_time = @h
enableSched = 1
search = index=aws sourcetype=aws:cloudwatchlogs:vpcflow | stats sum(bytes) as total_bytes, sum(packets) as total_packets, dc(dstaddr) as unique_destinations, count as connection_count by srcaddr | eval total_gb=round(total_bytes/1024/1024/1024, 2) | sort -total_bytes | head 50

[AWS Firewall - Daily: Denied Connections Summary]
action.email = 1
action.email.to = security-ops@example.com
action.email.subject = Daily Firewall Report - Denied Connections
cron_schedule = 0 9 * * *
description = Daily summary of denied connections by rule group, signature and source
dispatch.earliest_time = -24h@h
dispatch.latest_time = @h
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert action=DROP | stats count, dc(src_ip) as unique_sources, dc(dest_ip) as unique_targets by rule_group_name, signature | sort -count | head 100

[AWS Firewall - Weekly: Rule Effectiveness Report]
action.email = 1
action.email.to = security-ops@example.com,compliance@example.com
action.email.subject = Weekly Firewall Rule Effectiveness Report
cron_schedule = 0 10 * * 1
description = Weekly report on firewall rule performance and effectiveness
dispatch.earliest_time = -7d@d
dispatch.latest_time = @d
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert | stats count as total_triggers, sum(eval(if(action="DROP",1,0))) as blocks, sum(eval(if(action="ALERT",1,0))) as alerts, dc(src_ip) as unique_sources by rule_group_name, signature, rule_priority | eval effectiveness=round((blocks*100)/(blocks+alerts), 2) | sort -total_triggers

[Compliance - Daily: PCI-DSS Network Monitoring]
action.email = 1
action.email.to = compliance@example.com,security-ops@example.com
action.email.subject = PCI-DSS Daily Network Monitoring Report
cron_schedule = 0 7 * * *
description = Daily report for PCI-DSS requirement 10.6 (review logs and security events)
dispatch.earliest_time = -24h@h
dispatch.latest_time = @h
enableSched = 1
search = index=aws (sourcetype=aws:networkfirewall:alert OR sourcetype=aws:cloudwatchlogs:vpcflow) | lookup firewall_rule_compliance rule_id OUTPUT compliance_framework, compliance_requirement | where compliance_framework="PCI-DSS" | stats count by compliance_requirement, action, src_ip, dest_ip | sort compliance_requirement, -count

[Compliance - Weekly: HIPAA Security Rule Compliance]
action.email = 1
action.email.to = compliance@example.com,security-ops@example.com
action.email.subject = Weekly HIPAA Security Rule Compliance Report
cron_schedule = 0 9 * * 1
description = Weekly report for HIPAA Security Rule 164.312(e)(1) - Transmission Security
dispatch.earliest_time = -7d@d
dispatch.latest_time = @d
enableSched = 1
search = index=aws sourcetype=aws:networkfirewall:alert | lookup firewall_rule_compliance rule_id OUTPUT compliance_framework | where compliance_framework="HIPAA" | stats count as incidents, dc(src_ip) as affected_sources, values(signature) as security_events by rule_group_name | sort -incidents
"""
    
firewall:alert]
SHOULD_LINEMERGE = false
TIME_PREFIX = timestamp[=:\\s]+
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%Z
MAX_TIMESTAMP_LOOKAHEAD = 32
TRUNCATE = 100000
LINE_BREAKER = ([\\r\\n]+)
KV_MODE = json
EXTRACT-event_type = "event_type":\\s*"(?<event_type>[^"]+)"
EXTRACT-action = "action":\\s*"(?<action>[^"]+)"
EXTRACT-signature = "signature":\\s*"(?<signature>[^"]+)"
EXTRACT-src_ip = "src_ip":\\s*"(?<src_ip>[\\d.]+)"
EXTRACT-dest_ip = "dest_ip":\\s*"(?<dest_ip>[\\d.]+)"
EXTRACT-src_port = "src_port":\\s*(?<src_port>\\d+)
EXTRACT-dest_port = "dest_port":\\s*(?<dest_port>\\d+)
EXTRACT-protocol = "proto":\\s*"(?<protocol>[^"]+)"
FIELDALIAS-source_ip = src_ip AS src
FIELDALIAS-destination_ip = dest_ip AS dest
LOOKUP-threat_intel = threat_intel_ips ip AS src_ip OUTPUT threat_level, threat_category

[aws:cloudwatchlogs:vpcflow]
SHOULD_LINEMERGE = false
TIME_PREFIX = ^\\d+\\s+
TIME_FORMAT = %s
MAX_TIMESTAMP_LOOKAHEAD = 20
TRUNCATE = 100000
LINE_BREAKER = ([\\r\\n]+)
# VPC Flow Logs format: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
REPORT-vpcflow = extract_vpcflow_fields
FIELDALIAS-source = srcaddr AS src
FIELDALIAS-destination = dstaddr AS dest
FIELDALIAS-source_port = srcport AS src_port
FIELDALIAS-destination_port = dstport AS dest_port
LOOKUP-aws_services = aws_service_ports port AS dstport OUTPUT service_name

[aws:guardduty:finding]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_PREFIX = "updatedAt":\\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3NZ
EXTRACT-severity = "severity":\\s*(?<severity>[\\d.]+)
EXTRACT-finding_type = "type":\\s*"(?<finding_type>[^"]+)"
"""
    
    # transforms.conf - Field transformations
    transforms_conf = """[extract_vpcflow_fields]
REGEX = ^(\\d+)\\s+(\\d+)\\s+(\\S+)\\s+([\\d.]+)\\s+([\\d.]+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\w+)\\s+(\\S+)
FORMAT = version::$1 account_id::$2 interface_id::$3 srcaddr::$4 dstaddr::$5 srcport::$6 dstport::$7 protocol::$8 packets::$9 bytes::$10 start_time::$11 end_time::$12 action::$13 log_status::$14

[threat_intel_ips]
filename = threat_intel_ips.csv
case_sensitive_match = false

[aws_service_ports]
filename = aws_service_ports.csv

[firewall_rule_compliance]
filename = firewall_rule_compliance.csv

[mitre_attack_mapping]
filename = mitre_attack_mapping.csv

[attack_killchain]
filename = attack_killchain.csv

[cve_database]
filename = cve_database.csv
"""
    
    # macros.conf - Search macros
    macros_conf = """[aws_firewall_alerts]
definition = index=aws sourcetype=aws:networkfirewall:alert
iseval = 0

[vpc_flow_logs]
definition = index=aws sourcetype=aws:cloudwatchlogs:vpcflow
iseval = 0

[blocked_traffic]
definition = (action=DROP OR action=REJECT)
iseval = 0

[allowed_traffic]
definition = action=ACCEPT
iseval = 0

[high_severity_alerts]
definition = (severity>=7 OR action=DROP)
iseval = 0

[internal_ip_ranges]
definition = (srcaddr=10.0.0.0/8 OR srcaddr=172.16.0.0/12 OR srcaddr=192.168.0.0/16)
iseval = 0

[common_web_ports]
definition = (dest_port=80 OR dest_port=443 OR dest_port=8080 OR dest_port=8443)
iseval = 0
"""
    
    # Dashboard XML - Main monitoring dashboard
    dashboard_xml = """<dashboard version="1.1">
  <label>AWS Firewall &amp; Flow Logs Dashboard</label>
  <description>Real-time monitoring of AWS Network Firewall and VPC Flow Logs</description>
  
  <row>
    <panel>
      <title>Firewall Alert Rate (Last Hour)</title>
      <chart>
        <search>
          <query>`aws_firewall_alerts` | timechart span=5m count by action</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>5m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.axisTitleX.text">Time</option>
        <option name="charting.axisTitleY.text">Alerts</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
    
    <panel>
      <title>Blocked Connections</title>
      <single>
        <search>
          <query>`aws_firewall_alerts` `blocked_traffic` | stats count</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>5m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="underLabel">Last Hour</option>
        <option name="rangeColors">["0x65A637","0xF7BC38","0xD93F3C"]</option>
        <option name="rangeValues">[100,500]</option>
      </single>
    </panel>
    
    <panel>
      <title>VPC Flow Rejections</title>
      <single>
        <search>
          <query>`vpc_flow_logs` action=REJECT | stats count</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>5m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="underLabel">Last Hour</option>
        <option name="rangeColors">["0x65A637","0xF7BC38","0xD93F3C"]</option>
        <option name="rangeValues">[1000,5000]</option>
      </single>
    </panel>
    
    <panel>
      <title>Total Traffic (GB)</title>
      <single>
        <search>
          <query>`vpc_flow_logs` | stats sum(bytes) as total_bytes | eval total_gb=round(total_bytes/1024/1024/1024, 2)</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <refresh>5m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="underLabel">Last Hour</option>
        <option name="numberPrecision">0.00</option>
      </single>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Top 10 Blocked Source IPs</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` `blocked_traffic` | stats count as alert_count, values(signature) as signatures, values(dest_ip) as destinations by src_ip | sort -alert_count | head 10</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">cell</option>
        <option name="count">10</option>
      </table>
    </panel>
    
    <panel>
      <title>Top 10 Triggered Signatures</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` | stats count by signature, action | sort -count | head 10</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">cell</option>
        <option name="count">10</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>VPC Flow - Top Source IPs by Traffic Volume</title>
      <table>
        <search>
          <query>`vpc_flow_logs` | stats sum(bytes) as total_bytes, sum(packets) as total_packets, dc(dstaddr) as unique_dests by srcaddr | eval total_mb=round(total_bytes/1024/1024, 2) | sort -total_bytes | head 10 | fields srcaddr, total_mb, total_packets, unique_dests</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">cell</option>
      </table>
    </panel>
    
    <panel>
      <title>VPC Flow - Top Destination Ports</title>
      <chart>
        <search>
          <query>`vpc_flow_logs` | lookup aws_service_ports port AS dstport OUTPUT service_name | eval service=coalesce(service_name, "Port ".dstport) | stats count by service | sort -count | head 15</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Traffic by Protocol</title>
      <chart>
        <search>
          <query>`vpc_flow_logs` | eval protocol_name=case(protocol==6,"TCP",protocol==17,"UDP",protocol==1,"ICMP",1==1,"Other") | stats sum(bytes) as total_bytes by protocol_name | eval total_gb=round(total_bytes/1024/1024/1024, 2)</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.axisTitleX.text">Protocol</option>
        <option name="charting.axisTitleY.text">Traffic (GB)</option>
      </chart>
    </panel>
    
    <panel>
      <title>Accept vs Reject Ratio</title>
      <chart>
        <search>
          <query>`vpc_flow_logs` | stats count by action | eval action=upper(action)</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Recent High Severity Alerts</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` `high_severity_alerts` | table _time, src_ip, dest_ip, dest_port, signature, action | sort -_time | head 20</query>
          <earliest>-4h</earliest>
          <latest>now</latest>
          <refresh>2m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">row</option>
        <option name="count">20</option>
        <format type="color" field="action">
          <colorPalette type="map">{"DROP":#DC4E41,"ALERT":#F1813F,"PASS":#53A051}</colorPalette>
        </format>
      </table>
    </panel>
  </row>
</dashboard>"""

    # Threat Intelligence Dashboard
    threat_intel_dashboard = """<dashboard version="1.1">
  <label>Threat Intelligence</label>
  <description>Known malicious IPs and threat actor activity</description>
  
  <row>
    <panel>
      <title>Blocked Traffic from Threat Intel IPs</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` `blocked_traffic` | lookup threat_intel_ips ip as src_ip OUTPUT threat_level, threat_category, last_seen | where isnotnull(threat_level) | stats count as hits, latest(_time) as last_activity, values(dest_ip) as targeted_ips by src_ip, threat_level, threat_category | sort -hits</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">row</option>
        <format type="color" field="threat_level">
          <colorPalette type="map">{"critical":#DC4E41,"high":#F1813F,"medium":#F8BE34}</colorPalette>
        </format>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Threat Categories Over Time</title>
      <chart>
        <search>
          <query>`aws_firewall_alerts` | lookup threat_intel_ips ip as src_ip OUTPUT threat_category | where isnotnull(threat_category) | timechart span=1h count by threat_category</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    
    <panel>
      <title>Geographic Distribution of Threats</title>
      <chart>
        <search>
          <query>`aws_firewall_alerts` | iplocation src_ip | stats count by Country | sort -count | head 10</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>
</dashboard>"""

    # Compliance Dashboard
    compliance_dashboard = """<dashboard version="1.1">
  <label>Compliance &amp; Audit</label>
  <description>Regulatory compliance monitoring for PCI-DSS, HIPAA, SOC 2, and security frameworks</description>
  
  <row>
    <panel>
      <title>Compliance Framework Coverage</title>
      <single>
        <search>
          <query>index=aws sourcetype=aws:networkfirewall:alert | lookup firewall_rule_compliance rule_id OUTPUT compliance_framework | where isnotnull(compliance_framework) | stats dc(compliance_framework) as frameworks_covered</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="underLabel">Active Frameworks</option>
      </single>
    </panel>
    
    <panel>
      <title>Security Events (24h)</title>
      <single>
        <search>
          <query>`aws_firewall_alerts` | stats count</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="underLabel">Total Events</option>
        <option name="rangeColors">["0x65A637","0xF7BC38","0xD93F3C"]</option>
        <option name="rangeValues">[1000,5000]</option>
      </single>
    </panel>
    
    <panel>
      <title>Blocked Threats (24h)</title>
      <single>
        <search>
          <query>`aws_firewall_alerts` `blocked_traffic` | stats count</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="underLabel">Threats Prevented</option>
      </single>
    </panel>
    
    <panel>
      <title>Compliance Score</title>
      <single>
        <search>
          <query>`aws_firewall_alerts` | lookup firewall_rule_compliance rule_id OUTPUT compliance_framework | eval compliant=if(action="DROP" OR action="ALERT", 1, 0) | stats sum(compliant) as compliant_events, count as total_events | eval score=round((compliant_events/total_events)*100, 1)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="underLabel">Effectiveness %</option>
        <option name="rangeColors">["0xD93F3C","0xF7BC38","0x65A637"]</option>
        <option name="rangeValues">[80,95]</option>
      </single>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>PCI-DSS Requirement 1.2 - Firewall Configuration</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` | lookup firewall_rule_compliance rule_id OUTPUT compliance_framework, compliance_requirement | where compliance_framework="PCI-DSS" AND compliance_requirement LIKE "%1.2%" | stats count as events, dc(src_ip) as unique_sources, dc(dest_ip) as unique_destinations, values(action) as actions by rule_group_name, signature | sort -events</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">row</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>HIPAA 164.312(e)(1) - Transmission Security</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` | lookup firewall_rule_compliance rule_id OUTPUT compliance_framework, compliance_requirement | where compliance_framework="HIPAA" | stats count as security_events, dc(src_ip) as affected_systems, values(action) as actions_taken, latest(_time) as last_event by rule_group_name, signature | sort -security_events</query>
          <earliest>-7d</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">row</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>SOC 2 CC6.6 - Logical Access Controls</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` action=DROP | lookup firewall_rule_compliance rule_id OUTPUT compliance_framework, compliance_requirement | where compliance_framework="SOC 2" | stats count as blocked_attempts, dc(src_ip) as sources, values(dest_ip) as protected_assets by rule_group_name | sort -blocked_attempts</query>
          <earliest>-7d</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>NIST CSF PR.AC-5 - Network Integrity</title>
      <chart>
        <search>
          <query>`aws_firewall_alerts` | lookup firewall_rule_compliance rule_id OUTPUT compliance_framework | where compliance_framework="NIST CSF" | timechart span=1h count by action</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
      </chart>
    </panel>
    
    <panel>
      <title>CIS Controls - Network Monitoring</title>
      <chart>
        <search>
          <query>`vpc_flow_logs` | lookup firewall_rule_compliance rule_id OUTPUT compliance_framework | where compliance_framework="CIS Controls" | stats sum(bytes) as total_bytes by action | eval total_gb=round(total_bytes/1024/1024/1024, 2)</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Top Compliance Violations</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` action=DROP | lookup firewall_rule_compliance rule_id OUTPUT compliance_framework, compliance_requirement, violation_severity | where isnotnull(compliance_framework) | stats count as violation_count, dc(src_ip) as unique_violators, latest(_time) as last_occurrence by compliance_framework, compliance_requirement, violation_severity | sort -violation_count | head 20</query>
          <earliest>-7d</earliest>
          <latest>now</latest>
        </search>
        <format type="color" field="violation_severity">
          <colorPalette type="map">{"critical":#DC4E41,"high":#F1813F,"medium":#F8BE34,"low":#53A051}</colorPalette>
        </format>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Audit Trail - Access to Protected Resources</title>
      <table>
        <search>
          <query>`vpc_flow_logs` | iplocation dstaddr | where Country!="United States" | stats sum(bytes) as total_bytes, count as connection_attempts by srcaddr, dstaddr, Country | eval total_mb=round(total_bytes/1024/1024, 2) | sort -total_mb | head 50</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">row</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Failed Authentication Attempts (Compliance Monitoring)</title>
      <chart>
        <search>
          <query>`vpc_flow_logs` dstport IN (22,3389,445) action=REJECT | timechart span=1h count by dstport</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.axisTitleX.text">Time</option>
        <option name="charting.axisTitleY.text">Failed Attempts</option>
      </chart>
    </panel>
    
    <panel>
      <title>Encryption Protocol Usage</title>
      <chart>
        <search>
          <query>`aws_firewall_alerts` tls_version=* | stats count by tls_version | sort -count</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
        <option name="charting.legend.placement">right</option>
      </chart>
    </panel>
  </row>
</dashboard>"""

    # Advanced Threat Analysis Dashboard
    threat_analysis_dashboard = """<dashboard version="1.1">
  <label>Advanced Threat Analysis</label>
  <description>Deep threat hunting and attack pattern analysis</description>
  
  <row>
    <panel>
      <title>MITRE ATT&amp;CK Techniques Detected</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` | lookup mitre_attack_mapping signature OUTPUT technique_id, technique_name, tactic | where isnotnull(technique_id) | stats count as detections, dc(src_ip) as unique_sources, values(rule_group_name) as detecting_rules by technique_id, technique_name, tactic | sort -detections</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="drilldown">row</option>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Attack Kill Chain Stages</title>
      <chart>
        <search>
          <query>`aws_firewall_alerts` | lookup attack_killchain signature OUTPUT killchain_stage | where isnotnull(killchain_stage) | stats count by killchain_stage</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.axisTitleY.text">Detections</option>
      </chart>
    </panel>
    
    <panel>
      <title>Threat Actor TTPs Timeline</title>
      <chart>
        <search>
          <query>`aws_firewall_alerts` | lookup threat_actor_mapping src_ip OUTPUT threat_actor, motivation | where isnotnull(threat_actor) | timechart span=1h count by threat_actor</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Exploit Attempts by CVE</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` | rex field=signature "CVE-(?&lt;cve_id&gt;\\d{4}-\\d+)" | where isnotnull(cve_id) | lookup cve_database cve_id OUTPUT cvss_score, severity, description | stats count as exploit_attempts, dc(src_ip) as attackers, values(dest_ip) as targets by cve_id, cvss_score, severity | sort -cvss_score, -exploit_attempts</query>
          <earliest>-7d</earliest>
          <latest>now</latest>
        </search>
        <format type="color" field="cvss_score">
          <colorPalette type="minMidMax" maxColor="#DC4E41" minColor="#53A051"></colorPalette>
          <scale type="minMidMax" minValue="0" midValue="5" maxValue="10"></scale>
        </format>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Web Application Attacks</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` (alert_category="Web Application Attack" OR signature="*OWASP*" OR http_url=*) | stats count as attempts, dc(src_ip) as attackers, values(http_method) as methods, values(http_url) as targeted_urls by signature, dest_ip | sort -attempts</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Malware C2 Communication Patterns</title>
      <table>
        <search>
          <query>`aws_firewall_alerts` (alert_category="Malware Command and Control" OR signature="*C2*" OR signature="*Callback*") | stats count as beacons, dc(flow_id) as unique_flows, avg(byte_count) as avg_bytes, stdev(byte_count) as bytes_stdev by src_ip, dest_ip, dest_port | eval regularity=if(bytes_stdev&lt;100, "High", "Low") | sort -beacons</query>
          <earliest>-4h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Lateral Movement Detection</title>
      <table>
        <search>
          <query>`vpc_flow_logs` dstport IN (445,135,139,3389,5985,5986) | stats dc(dstaddr) as unique_targets, sum(bytes) as total_bytes, count as connections by srcaddr | where unique_targets &gt; 5 | eval total_mb=round(total_bytes/1024/1024, 2) | sort -unique_targets</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
    
    <panel>
      <title>Privilege Escalation Attempts</title>
      <chart>
        <search>
          <query>`aws_firewall_alerts` (signature="*Privilege*Escalation*" OR alert_category="Privilege Escalation") | timechart span=30m count by signature</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Cryptomining Activity Detection</title>
      <table>
        <search>
          <query>`vpc_flow_logs` (dstport=3333 OR dstport=4444 OR dstport=5555 OR dstport=7777 OR dstport=8888) | stats sum(bytes) as mining_traffic, count as connections, dc(dstaddr) as mining_pools by srcaddr | eval traffic_gb=round(mining_traffic/1024/1024/1024, 2) | where connections &gt; 100 | sort -traffic_gb</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
</dashboard>"""
    
    # Lookup files
    threat_intel_csv = """ip,threat_level,threat_category,last_seen,notes
198.51.100.1,critical,botnet,2024-01-01,Known C2 server
203.0.113.50,high,scanner,2024-01-05,Port scanning activity
192.0.2.100,medium,spam,2023-12-15,Email spam source
"""
    
    aws_services_csv = """port,service_name
22,SSH
80,HTTP
443,HTTPS
3389,RDP
3306,MySQL
5432,PostgreSQL
6379,Redis
9200,Elasticsearch
27017,MongoDB
8080,HTTP-Alt
8443,HTTPS-Alt
25,SMTP
53,DNS
21,FTP
23,Telnet
143,IMAP
993,IMAPS
110,POP3
995,POP3S
"""

    firewall_rule_compliance_csv = """rule_id,compliance_framework,compliance_requirement,violation_severity,description
rule-001,PCI-DSS,Requirement 1.2.1,critical,Restrict inbound and outbound traffic
rule-002,PCI-DSS,Requirement 1.3.4,high,Do not allow unauthorized outbound traffic
rule-003,HIPAA,164.312(e)(1),critical,Implement transmission security
rule-004,HIPAA,164.312(a)(1),high,Access control mechanisms
rule-005,SOC 2,CC6.6,high,Logical access controls
rule-006,SOC 2,CC6.7,medium,System operations security
rule-007,NIST CSF,PR.AC-5,high,Network integrity protection
rule-008,NIST CSF,DE.CM-1,medium,Network monitoring
rule-009,CIS Controls,13.1,high,Network boundary protection
rule-010,CIS Controls,13.2,medium,Log network traffic
rule-011,ISO 27001,A.13.1.1,high,Network controls
rule-012,ISO 27001,A.13.1.3,medium,Segregation of networks
"""

    mitre_attack_mapping_csv = """signature,technique_id,technique_name,tactic
SQL Injection,T1190,Exploit Public-Facing Application,Initial Access
Command Injection,T1059,Command and Scripting Interpreter,Execution
Remote Code Execution,T1203,Exploitation for Client Execution,Execution
Port Scan,T1046,Network Service Discovery,Discovery
Brute Force SSH,T1110,Brute Force,Credential Access
Brute Force RDP,T1110,Brute Force,Credential Access
DNS Tunneling,T1071.004,DNS,Command and Control
C2 Callback,T1071,Application Layer Protocol,Command and Control
Data Exfiltration,T1041,Exfiltration Over C2 Channel,Exfiltration
Lateral Movement SMB,T1021.002,SMB/Windows Admin Shares,Lateral Movement
"""

    attack_killchain_csv = """signature,killchain_stage
Port Scan,Reconnaissance
SQL Injection,Weaponization
Remote Code Execution,Exploitation
Privilege Escalation,Installation
C2 Callback,Command and Control
Data Exfiltration,Actions on Objectives
Brute Force,Delivery
Malware Download,Installation
"""

    cve_database_csv = """cve_id,cvss_score,severity,description
2024-12345,9.8,critical,Remote Code Execution vulnerability
2024-54321,7.5,high,SQL Injection vulnerability
2023-99999,8.1,high,Authentication bypass
2023-11111,6.5,medium,Information disclosure
"""
    
    # Write all configuration files
    files = {
        base_dir / "default" / "app.conf": app_conf,
        base_dir / "metadata" / "default.meta": default_meta,
        base_dir / "default" / "savedsearches.conf": savedsearches_conf,
        base_dir / "default" / "props.conf": props_conf,
        base_dir / "default" / "transforms.conf": transforms_conf,
        base_dir / "default" / "macros.conf": macros_conf,
        base_dir / "default" / "data" / "ui" / "views" / "firewall_dashboard.xml": dashboard_xml,
        base_dir / "default" / "data" / "ui" / "views" / "threat_intelligence.xml": threat_intel_dashboard,
        base_dir / "default" / "data" / "ui" / "views" / "network_analysis.xml": network_dashboard,
        base_dir / "default" / "data" / "ui" / "views" / "compliance_audit.xml": compliance_dashboard,
        base_dir / "default" / "data" / "ui" / "views" / "threat_analysis.xml": threat_analysis_dashboard,
        base_dir / "lookups" / "threat_intel_ips.csv": threat_intel_csv,
        base_dir / "lookups" / "aws_service_ports.csv": aws_services_csv,
        base_dir / "lookups" / "firewall_rule_compliance.csv": firewall_rule_compliance_csv,
        base_dir / "lookups" / "mitre_attack_mapping.csv": mitre_attack_mapping_csv,
        base_dir / "lookups" / "attack_killchain.csv": attack_killchain_csv,
        base_dir / "lookups" / "cve_database.csv": cve_database_csv,
    }
    
    for filepath, content in files.items():
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content)
    
    # Create comprehensive README
    readme = f"""# {app_label}

## Overview
Enterprise-grade monitoring solution for AWS Network Firewall and VPC Flow Logs with comprehensive threat intelligence, compliance reporting, and advanced threat hunting capabilities.

## Features

### 🎯 Core Capabilities
- **5 Interactive Dashboards**: Real-time monitoring, threat intelligence, network analysis, compliance reporting, and advanced threat hunting
- **16 Automated Alerts**: Tiered by severity (Critical, High, Medium) with specific thresholds
- **Advanced Field Extractions**: 40+ fields including HTTP, TLS/SSL, DNS, TCP, and application-layer data
- **Compliance Frameworks**: PCI-DSS, HIPAA, SOC 2, NIST CSF, CIS Controls, ISO 27001
- **MITRE ATT&CK Mapping**: Track adversary tactics and techniques
- **Kill Chain Analysis**: Map attacks to cyber kill chain stages

### 📊 Dashboards

#### 1. AWS Firewall & Flow Logs Dashboard
Main operational dashboard featuring:
- Real-time alert rate monitoring
- Blocked connection metrics
- Top blocked IPs and attack signatures
- Traffic volume and protocol distribution
- High-severity alerts feed

#### 2. Threat Intelligence Dashboard
Threat-focused analysis with:
- Known malicious IP tracking
- Threat categories and trends
- Geographic threat distribution
- Threat actor activity

#### 3. Network Traffic Analysis
Deep network insights including:
- Connection timelines and patterns
- Top talkers by bandwidth
- Unusual port activity detection
- Internal network communication analysis

#### 4. Compliance & Audit Dashboard
Regulatory compliance monitoring:
- **PCI-DSS**: Requirements 1.2, 1.3, 10.6
- **HIPAA**: 164.312(e)(1), 164.312(a)(1)
- **SOC 2**: CC6.6, CC6.7
- **NIST CSF**: PR.AC-5, DE.CM-1
- **CIS Controls**: 13.1, 13.2
- Compliance scoring and effectiveness metrics
- Audit trail for protected resource access
- Failed authentication tracking

#### 5. Advanced Threat Analysis
Threat hunting and attack pattern analysis:
- MITRE ATT&CK technique detection
- Cyber kill chain stage mapping
- CVE exploit attempt tracking
- Web application attack analysis
- Malware C2 communication patterns
- Lateral movement detection
- Privilege escalation attempts
- Cryptomining activity detection

## Alert Configuration

### Critical Severity Alerts (Immediate Response)
| Alert | Threshold | Frequency | Description |
|-------|-----------|-----------|-------------|
| High Alert Volume | >500 in 5min | Every 5min | Mass attack detection |
| Known Threat IPs | >5 blocks from critical IPs | Every 10min | Known threat actor activity |
| Rule Group Failures | 0 activity in 30min | Every 30min | Configuration issues |

### High Severity Alerts
| Alert | Threshold | Frequency | Description |
|-------|-----------|-----------|-------------|
| Rejected Connection Spike | 3σ above baseline | Every 15min | Anomalous rejection patterns |
| DDoS Pattern | >10K packets, <100 bytes avg | Every 10min | DDoS attack detection |
| SQL Injection | >10 attempts | Every 15min | SQLi attack attempts |
| Command Injection | >5 attempts | Every 15min | RCE attack attempts |

### Medium Severity Alerts
| Alert | Threshold | Frequency | Description |
|-------|-----------|-----------|-------------|
| Suspicious Outbound | >20 non-standard ports | Every 20min | Potential C2 communication |
| Port Scanning | >25 unique ports | Every 30min | Reconnaissance activity |
| Data Exfiltration | >50GB outbound | Every 4 hours | Large data transfers |
| Suspicious DNS | >10 long/DGA queries | Every 30min | DNS tunneling detection |

### Daily/Weekly Reports
- Top Talkers (Daily 8:00 AM)
- Denied Connections Summary (Daily 9:00 AM)
- Rule Effectiveness Report (Weekly Monday 10:00 AM)
- PCI-DSS Daily Report (Daily 7:00 AM)
- HIPAA Weekly Report (Weekly Monday 9:00 AM)

## Installation

### Prerequisites
- Splunk Enterprise 8.0+ or Splunk Cloud
- AWS CloudWatch Logs integration or S3 input
- Network Firewall and VPC Flow Logs enabled in AWS

### Step 1: Deploy the App
```bash
# Copy app to Splunk apps directory
cp -r {app_name} $SPLUNK_HOME/etc/apps/

# Set permissions
chown -R splunk:splunk $SPLUNK_HOME/etc/apps/{app_name}
```

### Step 2: Configure AWS Data Inputs

#### Option A: CloudWatch Logs (Recommended)
```bash
# Install Splunk Add-on for AWS
# Configure inputs for:
# - Log Group: /aws/networkfirewall/alert
#   Sourcetype: aws:networkfirewall:alert
# - Log Group: /aws/vpc/flowlogs
#   Sourcetype: aws:cloudwatchlogs:vpcflow
```

#### Option B: S3 Input
```bash
# Configure S3 input for:
# - Network Firewall alert logs
# - VPC Flow Logs
# Ensure proper sourcetype assignment
```

### Step 3: Update Email Configuration
Edit `local/savedsearches.conf`:
```conf
[AWS Firewall - Critical: High Alert Volume]
action.email.to = your-security-team@company.com
```

Update all alert email addresses for your organization.

### Step 4: Customize Thresholds
Adjust alert thresholds based on your environment:

```conf
# Example: Reduce DDoS threshold for smaller environments
[AWS Firewall - High: DDoS Attack Pattern]
search = ... | where total_packets > 5000 ...  # Was 10000
```

### Step 5: Populate Lookup Tables

#### Threat Intelligence
Update `lookups/threat_intel_ips.csv` with your threat feeds:
```csv
ip,threat_level,threat_category,last_seen,notes
1.2.3.4,critical,apt,2026-01-07,Known APT infrastructure
```

#### Compliance Mapping
Update `lookups/firewall_rule_compliance.csv`:
```csv
rule_id,compliance_framework,compliance_requirement,violation_severity,description
your-rule-001,PCI-DSS,Requirement 1.2.1,critical,Your rule description
```

#### MITRE ATT&CK Mapping
Update `lookups/mitre_attack_mapping.csv` for your signatures:
```csv
signature,technique_id,technique_name,tactic
Your Custom Signature,T1190,Exploit Public-Facing Application,Initial Access
```

### Step 6: Restart Splunk
```bash
$SPLUNK_HOME/bin/splunk restart
```

### Step 7: Verify Installation
```bash
# Test data ingestion
index=aws sourcetype=aws:* | stats count by sourcetype

# Verify field extractions
index=aws sourcetype=aws:networkfirewall:alert | table src_ip, dest_ip, signature, rule_group_name

# Check VPC Flow Log parsing
index=aws sourcetype=aws:cloudwatchlogs:vpcflow | table srcaddr, dstaddr, dstport, action
```

## Field Extractions

### Network Firewall Alert Fields
**Basic Fields:**
- event_type, action, signature, src_ip, dest_ip, src_port, dest_port, protocol

**Rule Information:**
- rule_group_name, rule_id, rule_action, rule_priority, firewall_name, availability_zone

**Packet/Flow Data:**
- packet_count, byte_count, flow_id, bytes_mb

**Suricata/Snort:**
- alert_category, alert_severity, signature_id, signature_rev

**Network Layer:**
- tcp_flags, tcp_seq, tcp_ack, icmp_type, icmp_code

**Application Layer:**
- http_method, http_hostname, http_url, http_user_agent, http_status
- tls_sni, tls_version, tls_subject, tls_issuer
- dns_query, dns_type, dns_rcode

### VPC Flow Log Fields
- version, account_id, interface_id
- srcaddr, dstaddr, srcport, dstport
- protocol, packets, bytes
- start_time, end_time, action, log_status

## Search Macros

| Macro | Definition | Usage |
|-------|-----------|-------|
| `` `aws_firewall_alerts` `` | Network Firewall alerts | `` `aws_firewall_alerts` action=DROP ``|
| `` `vpc_flow_logs` `` | VPC Flow Logs | `` `vpc_flow_logs` dstport=80 ``|
| `` `blocked_traffic` `` | Blocked/rejected traffic | `` `aws_firewall_alerts` `blocked_traffic` ``|
| `` `allowed_traffic` `` | Allowed traffic | `` `vpc_flow_logs` `allowed_traffic` ``|
| `` `high_severity_alerts` `` | Critical alerts | `` `aws_firewall_alerts` `high_severity_alerts` ``|
| `` `internal_ip_ranges` `` | RFC1918 private IPs | `` `vpc_flow_logs` `internal_ip_ranges` ``|
| `` `common_web_ports` `` | HTTP/HTTPS ports | `` search NOT `common_web_ports` ``|

## Example Searches

### Security Investigations

#### Find all activity from a suspicious IP
```spl
`aws_firewall_alerts` src_ip="1.2.3.4" 
| table _time, dest_ip, dest_port, signature, action, rule_group_name
```

#### Analyze lateral movement attempts
```spl
`vpc_flow_logs` dstport IN (445,135,139,3389) 
| stats dc(dstaddr) as targets, sum(bytes) as total_bytes by srcaddr 
| where targets > 5
```

#### Track exploitation attempts for specific CVE
```spl
`aws_firewall_alerts` signature="*CVE-2024-*" 
| stats count as attempts, values(dest_ip) as targets by src_ip, signature 
| sort -attempts
```

### Compliance Queries

#### PCI-DSS Requirement 1.2 - Review firewall rules
```spl
`aws_firewall_alerts` 
| lookup firewall_rule_compliance rule_id OUTPUT compliance_framework, compliance_requirement 
| where compliance_framework="PCI-DSS" 
| stats count by rule_group_name, signature, action
```

#### HIPAA 164.312(e)(1) - Transmission security violations
```spl
`aws_firewall_alerts` tls_version!="TLSv1.3" tls_version!="TLSv1.2"
| lookup firewall_rule_compliance rule_id OUTPUT compliance_framework 
| where compliance_framework="HIPAA"
| table _time, src_ip, dest_ip, tls_version
```

### Threat Hunting

#### Find beaconing behavior (C2)
```spl
`vpc_flow_logs` 
| bin _time span=1m 
| stats count, avg(bytes) as avg_bytes by _time, srcaddr, dstaddr, dstport 
| eventstats avg(avg_bytes) as overall_avg, stdev(avg_bytes) as stdev by srcaddr, dstaddr 
| where stdev < 50 AND count > 30
```

#### Detect DNS tunneling
```spl
`aws_firewall_alerts` dns_query=* 
| eval query_length=len(dns_query) 
| where query_length > 50 
| stats count, values(dns_query) as queries by src_ip 
| sort -count
```

## Customization Guide

### Adding Custom Rules
1. Update `lookups/firewall_rule_compliance.csv`
2. Map to compliance frameworks
3. Restart Splunk or reload lookups

### Creating Custom Alerts
```conf
[My Custom Alert]
action.email = 1
action.email.to = team@company.com
cron_schedule = */15 * * * *
description = Custom alert description
dispatch.earliest_time = -15m
dispatch.latest_time = now
enableSched = 1
search = `aws_firewall_alerts` custom_condition | where threshold
```

### Modifying Dashboard Panels
Edit XML files in `default/data/ui/views/` or use the visual editor in Splunk Web.

## Performance Optimization

### Index Configuration
```conf
[aws]
homePath = $SPLUNK_DB/aws/db
coldPath = $SPLUNK_DB/aws/colddb
thawedPath = $SPLUNK_DB/aws/thaweddb
maxDataSize = auto_high_volume
frozenTimePeriodInSecs = 2592000  # 30 days
```

### Search Optimization
- Use tstats for summary data
- Limit time ranges appropriately
- Use summary indexing for common queries
- Consider data model acceleration

## Troubleshooting

### No Data Appearing
```spl
# Check data ingestion
index=_internal source=*metrics.log group=per_sourcetype_thruput 
| where series LIKE "aws:%"

# Verify field extractions
index=aws sourcetype=aws:networkfirewall:alert 
| head 1 
| fieldsummary
```

### Alerts Not Triggering
- Check cron schedule syntax
- Verify email server configuration
- Review `$SPLUNK_HOME/var/log/splunk/scheduler.log`
- Test search manually

### Lookup Not Working
```spl
# Test lookup manually
| inputlookup threat_intel_ips.csv 
| head 10

# Verify lookup definition
| rest /services/data/transforms/lookups 
| search title="threat_intel_ips"
```

## Maintenance

### Regular Tasks
- **Daily**: Review critical alerts
- **Weekly**: Update threat intelligence feeds
- **Monthly**: Review and tune alert thresholds
- **Quarterly**: Update compliance mappings

### Backup Recommendations
```bash
# Backup lookups
tar -czf lookups-backup-$(date +%Y%m%d).tar.gz lookups/

# Backup configurations
tar -czf config-backup-$(date +%Y%m%d).tar.gz default/ local/
```

## Support & Resources

### Documentation
- [AWS Network Firewall Logs](https://docs.aws.amazon.com/network-firewall/latest/developerguide/logging-cw-logs.html)
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)

### Security Frameworks
- [MITRE ATT&CK](https://attack.mitre.org/)
- [PCI DSS](https://www.pcisecuritystandards.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Version History

- **1.0.0** (2026-01-07): Initial release
  - 5 comprehensive dashboards
  - 16 tiered alerts (3 Critical, 5 High, 4 Medium, 4 Reports)
  - 40+ custom field extractions
  - 6 compliance frameworks
  - MITRE ATT&CK integration
  - Cyber kill chain mapping
  - Advanced threat hunting capabilities

## License
Customize based on your organization's requirements.

## Contributors
Security Operations Team
"""
    
    
    for filepath, content in files.items():
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content)
    
    (base_dir / "README.md").write_text(readme)
    
    print(f"✓ AWS Firewall Monitoring Splunk app '{app_name}' created successfully!")
    print(f"✓ Location: ./{app_name}/")
    print(f"\n📦 Package Contents:")
    print(f"   ├── 5 Dashboards")
    print(f"   │   ├── Main Firewall Dashboard (operational)")
    print(f"   │   ├── Threat Intelligence (threat-focused)")
    print(f"   │   ├── Network Analysis (traffic patterns)")
    print(f"   │   ├── Compliance & Audit (regulatory)")
    print(f"   │   └── Advanced Threat Analysis (threat hunting)")
    print(f"   ├── 16 Automated Alerts")
    print(f"   │   ├── 3 Critical severity")
    print(f"   │   ├── 5 High severity")
    print(f"   │   ├── 4 Medium severity")
    print(f"   │   └── 4 Compliance reports (daily/weekly)")
    print(f"   ├── 40+ Custom Field Extractions")
    print(f"   │   ├── Network Firewall alerts (HTTP, TLS, DNS, TCP)")
    print(f"   │   └── VPC Flow Logs (14-field format)")
    print(f"   ├── 6 Lookup Tables")
    print(f"   │   ├── Threat Intelligence IPs")
    print(f"   │   ├── AWS Service Ports")
    print(f"   │   ├── Firewall Rule Compliance (PCI-DSS, HIPAA, SOC 2, etc.)")
    print(f"   │   ├── MITRE ATT&CK Mapping")
    print(f"   │   ├── Cyber Kill Chain Mapping")
    print(f"   │   └── CVE Database")
    print(f"   └── 7 Search Macros")
    print(f"\n🎯 Key Features:")
    print(f"   • Tiered alerting with specific thresholds")
    print(f"   • Multi-framework compliance (PCI-DSS, HIPAA, SOC 2, NIST CSF, CIS, ISO 27001)")
    print(f"   • MITRE ATT&CK technique detection")
    print(f"   • Cyber kill chain stage mapping")
    print(f"   • CVE exploit tracking")
    print(f"   • Advanced threat hunting capabilities")
    print(f"\n📋 Installation Steps:")
    print(f"1. Copy '{app_name}' directory to $SPLUNK_HOME/etc/apps/")
    print(f"2. Configure AWS data inputs:")
    print(f"   ├── Network Firewall: sourcetype=aws:networkfirewall:alert")
    print(f"   └── VPC Flow Logs: sourcetype=aws:cloudwatchlogs:vpcflow")
    print(f"3. Update email addresses in savedsearches.conf")
    print(f"4. Customize alert thresholds for your environment:")
    print(f"   ├── Critical: 500 alerts/5min (adjust for volume)")
    print(f"   ├── High: 10-10K events (tune per attack type)")
    print(f"   └── Medium: 20-50GB thresholds (adjust for network size)")
    print(f"5. Populate lookup tables:")
    print(f"   ├── threat_intel_ips.csv (add your threat feeds)")
    print(f"   ├── firewall_rule_compliance.csv (map your rules)")
    print(f"   └── mitre_attack_mapping.csv (map your signatures)")
    print(f"6. Restart Splunk: $SPLUNK_HOME/bin/splunk restart")
    print(f"7. Access dashboards from the app menu")
    print(f"\n🔍 Quick Verification:")
    print(f"   # Test data ingestion")
    print(f"   index=aws sourcetype=aws:* | stats count by sourcetype")
    print(f"   ")
    print(f"   # Verify field extractions")
    print(f"   index=aws sourcetype=aws:networkfirewall:alert ")
    print(f"   | table src_ip, dest_ip, signature, rule_group_name, http_method, tls_sni")
    print(f"\n⚡ Alert Threshold Examples:")
    print(f"   Critical: >500 alerts in 5 minutes (adjust ±200 for your volume)")
    print(f"   High: >10K packets with <100 byte avg (DDoS detection)")
    print(f"   Medium: >50GB outbound transfer in 4h (adjust for your bandwidth)")
    
    return base_dir

if __name__ == "__main__":
    create_aws_firewall_app(
        app_name="aws_firewall_monitor",
        app_label="AWS Firewall Monitor"
    )