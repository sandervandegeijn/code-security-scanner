# SECURITY_SCAN.md

Use this file at the root of the project being scanned. The scanner reads it
as authoritative project context. Keep facts current and remove placeholder
text before scanning.

## System Context

- Short description of the application: 
- Hosting model/platform:
- Production status: production / acceptance / test / development / proof of concept

## Exposure and Likelihood

- Area of attack: internet / internal network / VPN / remote workspace /
  internal subnet / local or physical access / unknown
- Publicly available: yes / no / partly / unknown
- Upstream controls that reduce exposure: load balancer, reverse proxy, web
  application firewall, API gateway, VPN, IP allow-list, single sign-on, or none
- Authentication method: none / local accounts / single sign-on / API keys /
  machine-to-machine tokens / other

## Damage Impact

- Data classification/damage class: negligible / some / serious / disruptive
- Types of data processed:
- Expected business impact if confidentiality, integrity, or availability is
  compromised:

## Developer Feedback on Scanner Findings

Append scanner-specific feedback here after reviewing reports. Include the
finding title, file/location, decision, reason, and any remediation or risk
acceptance reference.

Example format:

- Finding:
  Decision: confirmed / false positive / accepted risk / mitigated by context
  Reason:
  Remediation or risk reference:
