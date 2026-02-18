## Configuring the Metasploitable Virtual Machine to be *HIPAA-Compliant*
  Purpose is to mimic the Medical Computer Systems environment.

## Problem
- Must be HIPAA-compliant.
  - However, we are constrained to our virtual machines and framework, so this naturally eliminates areas of HIPAA-compliance that are not appplicable, like: 
      - Finding an enterprise VPN for secure remote access.
      - Using industry-leading Next-Gen Firewalls for enhanced visibility of devices endpoints.
      - Regular updates (as this is a one-time project).
      - Potentially logging/monitoring capabilities (because our project is red-team focused).
      - Staff training and awareness.
      - Etc.

## Solution
- Implement strong security controls that are widely applicable.
  - Emulate what we can to get our test-target as compliant as possible within our constraints:
      - Data encryption, both in transit and at rest with AES-256.
      - Access controls, limit who can access the test VM (create multiple user accounts, strong password policy), potentially MFA.
      - Configure the firewall's inbound and outbound traffic, limit access from external networks inside, and limit employee access to the internet.
