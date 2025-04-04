"""
Port default suggestions for various monitoring types.
"""

# Default port suggestions for monitoring types
DEFAULT_PORT_SUGGESTIONS = {
    "ssh-banner": {
        "to_target": ["22"],
        "from_target": []
    },
    "tcp-connect": {
        "to_target": ["3389"],
        "from_target": []
    },
    "snmp": {
        "to_target": ["161"],
        "from_target": ["162"]
    },
    "ssl": {
        "to_target": ["443"],
        "from_target": []
    },
    "icmp": {
        "to_target": ["ICMP"],
        "from_target": []
    }
}

# Common application ports that might be monitored
COMMON_APPLICATION_PORTS = {
    "web": ["80", "443", "8080", "8443"],
    "database": ["1433", "3306", "5432", "27017", "6379"],
    "email": ["25", "110", "143", "465", "587", "993", "995"],
    "file_transfer": ["21", "22", "69", "115", "989", "990"],
    "directory_services": ["389", "636", "88", "464"],
    "messaging": ["5222", "5269", "1883", "8883"],
    "vpn": ["500", "4500", "1194", "1723"],
    "management": ["22", "23", "3389", "5900"]
}

# Template configurations for common use cases
PORT_TEMPLATES = {
    "web_server": {
        "name": "Web Server",
        "description": "Common ports for web servers",
        "to_target": ["80", "443", "8080", "8443"],
        "from_target": []
    },
    "database_server": {
        "name": "Database Server",
        "description": "Common ports for database servers",
        "to_target": ["1433", "3306", "5432", "6379", "27017"],
        "from_target": []
    },
    "windows_server": {
        "name": "Windows Server",
        "description": "Common ports for Windows servers",
        "to_target": ["3389", "445", "139", "135"],
        "from_target": ["514"]
    },
    "linux_server": {
        "name": "Linux Server",
        "description": "Common ports for Linux servers",
        "to_target": ["22"],
        "from_target": ["514"]
    },
    "network_device": {
        "name": "Network Device",
        "description": "Common ports for network equipment",
        "to_target": ["22", "23", "161"],
        "from_target": ["162", "514"]
    },
    "monitoring_agent": {
        "name": "Monitoring Agent",
        "description": "Common ports for monitoring agents",
        "to_target": ["9100", "9090", "9093"],
        "from_target": []
    }
}

# Firewall export templates
FIREWALL_TEMPLATES = {
    "cisco": {
        "name": "Cisco ASA",
        "header": """! Cisco ASA Firewall Rules
! Generated on {timestamp}
! For MaaS-NG server: {maas_ng_fqdn} ({maas_ng_ip})
!
""",
        "rule_format": "access-list MAAS-MONITORING extended permit {protocol} host {src_ip} host {dst_ip} {port_spec} ! {description}",
        "footer": """!
! End of generated rules
! Total rules: {rule_count}
"""
    },
    "juniper": {
        "name": "Juniper SRX",
        "header": """# Juniper SRX Security Policy
# Generated on {timestamp}
# For MaaS-NG server: {maas_ng_fqdn} ({maas_ng_ip})
#
set applications {
""",
        "rule_format": "    application maas-{protocol}-{port} protocol {protocol_lower} destination-port {port}",
        "policy_format": """
set security policies from-zone trust to-zone untrust policy MAAS-{rule_id} match source-address {src_ip}/32
set security policies from-zone trust to-zone untrust policy MAAS-{rule_id} match destination-address {dst_ip}/32
set security policies from-zone trust to-zone untrust policy MAAS-{rule_id} match application maas-{protocol}-{port}
set security policies from-zone trust to-zone untrust policy MAAS-{rule_id} then permit
set security policies from-zone trust to-zone untrust policy MAAS-{rule_id} then log session-init session-close
""",
        "footer": """
}
# End of generated rules
# Total rules: {rule_count}
"""
    },
    "paloalto": {
        "name": "Palo Alto Networks",
        "header": """<?xml version="1.0"?>
<config version="9.1.0" urldb="paloaltonetworks">
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <rulebase>
            <security>
""",
        "rule_format": """              <entry name="MAAS-MONITORING-{rule_id}">
                <from><member>trust</member></from>
                <to><member>untrust</member></to>
                <source><member>{src_ip}/32</member></source>
                <destination><member>{dst_ip}/32</member></destination>
                <service><member>service-{protocol}-{port}</member></service>
                <application><member>any</member></application>
                <action>allow</action>
                <description>{description}</description>
              </entry>""",
        "footer": """
            </security>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
<!-- End of generated rules -->
<!-- Total rules: {rule_count} -->
"""
    },
    "iptables": {
        "name": "Linux iptables",
        "header": """#!/bin/bash
# iptables rules for MaaS-NG monitoring
# Generated on {timestamp}
# For MaaS-NG server: {maas_ng_fqdn} ({maas_ng_ip})

# Flush existing rules
iptables -F MAAS-MONITORING 2>/dev/null || iptables -N MAAS-MONITORING
iptables -F MAAS-MONITORING

# Add monitoring rules
""",
        "rule_format": "iptables -A MAAS-MONITORING -p {protocol_lower} -s {src_ip}/32 -d {dst_ip}/32 --dport {port} -j ACCEPT # {description}",
        "footer": """
# Link chain to INPUT and FORWARD chains
iptables -A INPUT -j MAAS-MONITORING
iptables -A FORWARD -j MAAS-MONITORING

echo "Applied {rule_count} MAAS monitoring rules"
"""
    }
}