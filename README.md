> **Hands-on Microsoft Sentinel SOC lab featuring KQL based detections, Tor exit node threat intelligence, MITRE ATT&CK mapping, and full incident lifecycle handling in Azure.**

# Microsoft Sentinel SOC Lab: Simulated Tor-Based Threat Detection

This project showcases a **practical SOC analyst workflow** using **Microsoft Sentinel** to detect and investigate suspicious sign in activity originating from known Tor exit nodes. The lab focuses on **detection engineering, alert fidelity, and incident handling**, all executed in a controlled Azure environment using verified threat intelligence.

Rather than relying on noisy or unsafe traffic generation, the detection logic was validated using **synthetic telemetry modeled on real-world indicators** a common approach in production SOCs when live attacker simulation isn’t feasible.

> **Scope clarification**  
> No live Tor traffic, browsers, or third party tools were used. All events were simulated, but the indicators themselves were sourced from the official [Tor Project public exit node list](https://check.torproject.org/torbulkexitlist).

---

## SOC-Relevant Outcomes

This lab demonstrates how I showed hands on experience with:

- Deploying **Microsoft Sentinel** via ARM templates  
- Designing a **custom analytics rule** to detect Tor based access attempts  
- Applying accurate **entity mapping** (`Account` and `IP`) to enable investigation and correlation  
- Generating, triaging, and closing a **High-severity incident** end to end  
- Documenting findings in a **clear, analyst-ready incident report**  

Mapped to **MITRE ATT&CK** for threat context and reporting alignment:

- [T1090.003: Proxy – Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)  
- [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530)

---

## Evidence & Artifacts

### 1. Analytics Rule Configuration

![Sentinel Analytics Rule](assets/sentinel-rule.mp4)

*Custom KQL analytics rule using a known Tor exit IP, with explicit entity mapping for correlation.*

### 2. High-Severity Incident Detection

![Sentinel Incident](assets/incident.png)

*Incident showing a suspicious sign in from a Tor exit node, correlated to a specific user account.*

### 3. Incident Report (PDF)

📄 [View Full Incident Report (PDF)](assets/incident-report.pdf)

*Exported directly from Microsoft Sentinel. Includes alert metadata, investigation steps, and evidence timeline.*

> **Note:** PDF and video artifacts may not render directly in Github’s preview due to file size limitations, but are included in the repository.

---

## Analyst Methodology

### Threat Simulation Approach

In real SOC environments, analysts often need to validate detections without introducing real attacker traffic, especially in cloud only or license limited environments. This lab mirrors that reality.

- **Threat Indicator:** `185.220.101.10`  
  - Sourced from the official [Tor Project bulk exit list](https://check.torproject.org/torbulkexitlist)  
  - Verified as an active Tor exit node at the time of testing  
- **Simulation Technique:** Static event injection using KQL `datatable`  
- **Risk Profile:** Zero network impact; no authentication attempts or external connections  

This approach shows how SOC teams safely test analytics rules before deploying them to production.

---

## Detection Logic (KQL)

```kql
datatable(TimeGenerated: datetime, UserPrincipalName: string, IPAddress: string)
[
    datetime(2026-01-04T13:15:00Z), "attacker@sentinel-lab.onmicrosoft.com", "185.220.101.10"
]
| extend FullName = UserPrincipalName, Address = IPAddress

