# Severity Criteria

## Critical

- Evidence of previous compromise (active incident).
- Exploitation results in a disclosure of sensitive information or can pose a severe impact to Client’s reputation.
- Business Critical systems are heavily impacted, with the ability to alter information or change system settings.
- The issue described resulted in a complete system compromise that gave the attacker the highest-level user privileges on the system.
- The vulnerability resides directly on business-critical systems.
- Exploitation is trivial with publicly available exploit code, or no exploit code is needed.
- No authentication is required to exploit the vulnerable service or application.
- Client has no countermeasures in place to defend against this successful attack, or the deployed countermeasures were ineffective.

## High

- Exploitation may result in a disclosure of sensitive information or may impact Client’s reputation.
- The issue described results in user-account or system compromise.
- Exploitation is trivial with publicly available exploit code, or no exploit code is needed.
- No authentication is required, or authentication is easily guessed/bypassed.
- Client has no countermeasures in place to defend against this successful attack, or the deployed countermeasures were ineffective.

## Medium

- Exploitation may result in the disclosure of a limited amount of moderately sensitive information.
- Exploitation requires a skilled attacker.
- Exploitation is non-trivial, and known exploit code either does not exist, or needs to be heavily modified to work effectively.
- Client has countermeasures in place that might impede this attack.
- Another attack vector is needed for successful exploitation, such as:
  - Client interaction
  - Social Engineering
  - Network or system misconfiguration

## Low

- Critical client information/data is not directly at risk.
- Requires several additional attack vectors, or one very complicated/rare vector, such as:
  - Control of the client system’s internet connection
  - Man-in-the-Middle access
  - Previous compromise of a system
  - Insider access/knowledge
- Exploitation is extremely difficult and/or time and resource intensive.
- Client has countermeasures in place that prevent exploitation.

## Informational

- Information that may be of interest to an attacker.
- May provide data that can be used in conjunction with another attack.
- Can aid in a higher-severity vulnerability
