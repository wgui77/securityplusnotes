
## 1.0 General Security Concepts
## 1.1 Compare and contrast various types of security controls.
## • Categories
−Technical security controls / Logical security controls
security enforced by system / software
Examples: firewalls, encryption, MFA, antivirus, IDSs (Intrusion Detection System)
“done by machines / computers / implemented by technology”

−Managerial security control / Administrative controls
Policies, rules, governance, planning, reduce risk of security incidents
Examples: risk assessments, audits, approval processes, written policies, security policy, awareness trainings
“decided by management”

−Operational
Day-to-day human procedures, ensure equipment contrinues to work as specified,  implemented and executed by people
Examples: incident response, backups, training, configuration management, patch management
“people following process”

−Physical
Real-world protection of facilities, (deter, detect, and prevent unauthorized access, theft, damage, or destruction of material assets)
Examples: locks, fences, guards, CCTV, Lighting, acess control vestibules, bollards, barricades
“protect the building”

## • Control types
−Preventive
Stops attacks before they happen
MFA, firewalls, locks, encryption, AV software (antivirus)

−Deterrent
Discourages attackers
Warning signs, visible cameras, lighting, fencing, bollards

−Detective
Finds attacks happening or after
IDS (Intrusion Detection System), logs, CCTV monitoring, security audits, vulnerability scanning

−Corrective
Fixes damage after an incident
restoring backups, patching systems, IRP (Incident Response Plan), DRPs (Disaster Recovery Plan)


−Compensating
Alternative control when main one isn’t possible
extra monitoring when encryption can’t be used, Backup power system, MFA, Application sandboxing, Network segmentation

−Directive
Guides behavior
policies, acceptable use rules, IRP (Incident Response Plan), AUP (Acceptable Use Policy)

https://www.examcompass.com/
https://lecbyo.files.cmp.optimizely.com/download/cf25ec24b8a511ef9ecbb69c0f9687be
## 1.2 Summarize fundamental security concepts.
• Confidentiality, Integrity, and Availability (CIA)
Confidentiality -> only authorized people see data (encryption, access control)
Integrity -> data is not alterd incorrectly (hashing, digital signatures)
Availability -> Systems are accessible when needed (redundancy, backups, failover)

•  Non-repudiation
Prevent denial of actions. Digital signatures ensure someone cannot deny sending a message

• Authentication, Authorization, and Accounting (AAA)
Authentication → “Who are you?” Password, biometrics, MFA
Authorization → “What can you do?” Permissions, roles
Accounting → “What did you do?” Logs, audit trails

• Gap analysis
Comparing where you are now vs. where you need to be, then identifying what’s missing to reach the desired security level.


• Zero Trust
    −Control Plane
        ◦ Adaptive  identity (context-based login)
        ◦ Threat scope reduction 
        ◦ Policy-driven access control
        ◦ Policy  Administrator (sets rules)
        ◦ Policy  Engine (decides access rules)
    −Data Plane
        ◦ Implicit trust zones
        ◦ Subject/System
        ◦ Policy Enforcement Point (actually allows/blocks access)


• Physical security
    −Bollards (block vehicles)
    −Access control vestibule
    −Fencing (perimeter control)
    −Video surveillance (monitoring)
    −Security guard (human response)
    −Access badge (identity access)
    −Lighting (visibility)
    −Sensors
        ◦ Infrared (heat detection)
        ◦ Pressure (weight detection)
        ◦ Microwave (motion detection)
        ◦ Ultrasonic (movement detection)

• Deception and disruption technology
    −Honeypot (fake system)
    −Honeynet (network of traps)
    −Honeyfile (fake sensitive file)
    −Honeytoken (fake credentials/data)


## 1.3
Explain the importance of change management processes and the impact to security.
• Business processes impacting security operation
−Approval process (who allows change)
−Ownership (who is responsible)
−Stakeholders (who is affected)
−Impact analysis (what could break)
−Test results (verify safety)
−Backout plan (rollback if failure)
−Maintenance window (safe time to change)
−Standard operating procedure

• Technical implications
−Allow lists/deny lists (security rule updates)
−Restricted activities 
−Downtime (service interruption)
−Service restart (system resets)
−Application restart (system resets)
−Legacy applications (harder to change)
−Dependencies (other systems affected)

• Documentation
−Updating diagrams
−Updating policies/procedures
• Version control

## 1.4 Explain the importance of using appropriate cryptographic solutions.
• Public key infrastructure (PKI)
    −Public key (shared openly)
    −Private key (kept secret)
    -Certificate authorities (verify identity)
    −Key escrow (backup of keys (controlled access))
• Encryption
    − Level
     ◦   Cryptographic Hardware
            - TPM (Trusted Platform Module)
                - Securely stores cryptographic keys
            - HSM (Hardware Security Module)
                - Dedicated hardware for key management/encryption
            - Secure enclave
                - Isolated secure processor area
     ◦   Full-disk (whole device) / Storage Encryption
            - SED (Self-Encrypting Drive)
                - Hardware-level disk encryption
            - FDE (Full Disk Encryption)
                - Software-based whole disk encryption
            - BitLocker
                - Microsoft full-disk encryption
     ◦   Partition (part of disk)
     ◦   File (individual file) 
            - EFS (Encrypted File System)
                - Encrypts individual files in Windows
     ◦   Volume (storage container)
     ◦   Database (structured data) 
     ◦   Record (single entry)
    − Transport/communication (data in transit (HTTPS, TLS))
    - Symmetric encryption
        - Same key encrypts/decrypts
        - Fast
        - Used for bulk data encryption
        - Examples:
            - AES
            - DES (deprecated)
            - 3DES (legacy)
            - IDEA (older/deprecated)
            - RC4 (weak stream cipher)
    - Asymmetric encryption
        - Public/private key pair
        - Slower
        - Used for key exchange + digital signatures
        - Examples:
            - RSA
            - ECC
            - DHE
            - ECDHE
    - Key Exchange & Session Security
        - IKE (Internet Key Exchange)
            - Used in IPsec (Internet Protocol Security) and VPNs (Virtual Private Network)
        - DHE (Diffie-Hellman Ephemeral)
            - Temporary session keys
            - Supports forward secrecy
        - ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
            - ECC-based version of DHE
        - PFS (Perfect Forward Secrecy)
            - Old sessions remain secure even if long-term key is compromised
        - KEK (Key Encryption Key)
            - Encrypts other keys
    - VPNs & Secure Communication Protocols
        - HTTPS (Hypertext Transfer Protocol Secure)
            - Secure web traffic using TLS
        - TLS (Transport Layer Security)
            - Successor to SSL (Secure Sockets Layer)
        - SSH (Secure Shell)
            - Secure remote login/command execution
        - SFTP (Secured File Transfer Protocol)
            - File transfer over SSH
        - FTPS (Secured File Transfer Protocol)
            - FTP (File Transfer Protocol) + SSL/TLS (Secure Sockets Layer/Transport Layer Security)
        - IPsec (Internet Protocol Security)
            - Secure IP communications
            - ESP (Encapsulated Security Payload) = encryption + integrity + authentication
            - AH (Authentication Header) = integrity/authentication only
        - VPN (Virtual Private Network)
            - Encrypted tunnel over public network
        - SRTP (Secure Real-Time Protocol)
            - Secure real-time audio/video transport
    - Wireless Encryption
        - CCMP
            - WPA2 encryption protocol
            - Uses AES
        - TKIP
            - Older WPA encryption protocol (legacy)

    - Implementation
        - GPG
        - PGP



----

## Cipher Modes
- ECB
    - Simplest/weakest
    - Not recommended
- CBC
    - Chains ciphertext blocks together
- CFB
    - Converts block cipher into stream cipher
- CTR (Counter mode)
    - Uses counters to generate keystream
- GCM
    - Counter mode + authentication/integrity

## Important Crypto Concepts
- IV (Initialization Vector)
    - Adds randomness
- XOR
    - Logical operation used in cryptography
- Key length
    - Longer key = stronger encryption
- AES-256
    - Strongest AES key size commonly used

## Hashing & Integrity
- Hashing
    - One-way function
- Salting
    - Adds randomness before hashing
- Digital signatures
    - Integrity + authentication + non-repudiation
- Key stretching
    - Slows password cracking

## PKI & Certificates
- PKI (Public Key Infrastructure)
- Public key
- Private key
- CA (Certificate Authority)
- CRL (Certificate Revocation List)
- OCSP
- CSR
- Root of trust
- Self-signed certificates
- Wildcard certificates

## Obfuscation
- Steganography
- Tokenization
- Data masking

## Blockchain
- Distributed ledger
- Immutable records







----
• Tools
    −Trusted Platform Module (TPM) (hardware key protection in PC)
    −Hardware security module (HSM) (secure key storage device)
    −Key management system (organizes keys)
    −Secure enclave (isolated secure processor area)
• Obfuscation
    −Steganography (hide data inside media)
    −Tokenization (replace data with tokens)
    −Data masking (hide sensitive parts)
• Hashing (One-way function (cannot reverse))
• Salting (Adds randomness before hashing)
• Digital signatures (Prove identity + integrity + non-repudiation)
• Key stretching (Slows down password cracking)
• Blockchain
    - Distributed public ledger
    - Immutable records
    - Open public ledger
• Certificates
    −Certificate authorities (CA) → trusted issuer
    −Certificate revocation lists (CRLs) → revoked certificates list
    -Online Certificate Status Protocol (OCSP) → real-time certificate check
    -Self-signed → not trusted publicly
    -Third-party 
    -Root of trust → top trusted authority
    -Certificate signing request (CSR) generation → request for certificate
    -Wildcard → covers multiple subdomains



## 2.0 Threats, Vulnerabilities, and Mitigations
## 2.1 
- Threat actors
−Nation-state
−Unskilled attacker
−Hacktivist
−Insider threat
−Organized crime
−Shadow IT
- Attributes of actors
−Internal/external
−Resources/funding
−Level of sophistication/capability
## • Motivations
−Data exfiltration
−Espionage
−Service disruption
−Blackmail
−Financial gain
−Philosophical/political beliefs
−Ethical
−Revenge
−Disruption/chaos
−War
Explain common threat vectors and attack surfaces.
## • Message-based
−Email
−Short Message Service (SMS)
−Instant messaging (IM)
## • Image-based
## • File-based
- Voice call
- Removable device
- Vulnerable software
−Client-based vs. agentless
- Unsupported systems
and applications
- Unsecure networks
−Wireless
−Wired
−Bluetooth
- Open service ports
- Default credentials
- Supply chain
−Managed service providers (MSPs)
−Vendors
−Suppliers
- Human vectors/social engineering
−Phishing
−Vishing
−Smishing
−Misinformation/disinformation
−Impersonation
−Business email compromise
−Pretexting
−Watering hole
−Brand impersonation
−Typosquatting
## 2.1
## 2.2
2.0 Threats, Vulnerabilities, and Mitigations


Explain various types of vulnerabilities.
## • Application
−Memory injection
−Buffer overflow
−Race conditions
◦ Time-of-check (TOC)
◦ Time-of-use (TOU)
−Malicious update
- Operating system (OS)-based
## • Web-based
−Structured Query Language
injection (SQLi)
−Cross-site scripting (XSS)
## • Hardware
−Firmware
−End-of-life
−Legacy
## • Virtualization
−Virtual machine (VM) escape
−Resource reuse
## • Cloud-specific
- Supply chain
−Service provider
−Hardware provider
−Software provider
## • Cryptographic
## • Misconfiguration
- Mobile device
−Side loading
−Jailbreaking
## • Zero-day
Given a scenario, analyze indicators of malicious activity.
- Malware attacks
−Ransomware
−Trojan
−Worm
−Spyware
−Bloatware
−Virus
−Keylogger
−Logic bomb
−Rootkit
- Physical attacks
−Brute force
−Radio frequency identification
(RFID) cloning
−Environmental

- Network attacks
−Distributed denial-of-service (DDoS)
◦Amplified
## ◦ Reflected
−Domain Name System (DNS) attacks
−Wireless
−On-path
−Credential replay
−Malicious code
- Application attacks
−Injection
−Buffer overflow
−Replay
−Privilege escalation
−Forgery
−Directory traversal
- Cryptographic attacks
−Downgrade
−Collision
−Birthday
- Password attacks
−Spraying
−Brute force
## • Indicators
−Account lockout
−Concurrent session usage
−Blocked content
−Impossible travel
−Resource consumption
−Resource inaccessibility
−Out-of-cycle logging
−Published/documented
−Missing logs
Explain the purpose of mitigation techniques used to secure the enterprise.
## • Segmentation
- Access control
−Access control list (ACL)
−Permissions
- Application allow list
## • Isolation
## • Patching
## • Encryption
## • Monitoring
- Least privilege
- Configuration enforcement
## • Decommissioning
- Hardening techniques
−Encryption
−Installation of endpoint protection
−Host-based firewall
−Host-based intrusion
prevention system (HIPS)
−Disabling ports/protocols
−Default password changes
−Removal of unnecessary software
2.0  |  Threats, Vulnerabilities, and Mitigations
## 2.3
## 2.4
## 2.5


Compare and contrast security implications of different architecture models.
- Architecture and infrastructure concepts
− Cloud
    - Service hosted by a provider instead of entirely on company-owned hardware.
    - example: amazon web services, microsoft, google.
    - advantage: scalabality, high availablity, fast deployment, reduced hardware cose, built-in redundancy.
    - risk: Misconfiguration storage, data exposure, vendor lock-in, shared infrastruture risks, internet dependency

- Responsibility matrix
    - responsibility among IaaS, PaaS, SaaS. 
    - lets refer this back to fundamental image. 
- Hybrid considerations
    - some on prem, some on cloud
    - benefits: flexible, gradual migration, sensitive data stays on prem
    - cons: complex security management, difficult identity integration, inconsistent policies, large aatack surface
- Third-party vendors
    - cloud is a third party..
    - risk: supply chain attacks, vendor outages, weak vendor security, compliance issues
    - controls: vendor assessments, contracts/ SLAs, audits, continous monitoring.
− Infrastructure as code (IaC)
    - IaC = managing infrastructure using code/scripts instead of manual setup.
    - example: red hat ansible. 
        - ansible: Ansible playbooks to automate the provisioning, configuration, and security hardening of resources across diverse environments like OpenStack, Kubernetes, and Azure. This automation ensures consistent configurations, minimizes human errors, and enhances the security of systems.
    - example: hashicorp terraform
        - Terraform enables users to describe their desired infrastructure state using a declarative language, specifically the HashiCorp Configuration Language (HCL). Instead of manually clicking through web consoles or writing step-by-step shell scripts, you write code that tells Terraform exactly what your infrastructure should look like. Terraform then handles the heavy lifting of creating an execution plan, determining dependencies, and provisioning the components safely.
    - advantages:
        - consistency, repeated deployment, fewer manual mistakes, faster recovery
    - risk:
        - misconfiguratons spread quickly, secrets stored in code, insecure templates, poor access control    
- Serverless
    - developers run code without managing servers
    - example: amazon web services lambda
        -allows you to run code without provisioning or managing servers. You simply upload your code, and Lambda automatically scales your application in response to events and handles all underlying infrastructure administration
    - advantages: reduced server management, automatic scaling, smaller infrastructure burden
    - risk: less visibility / control, dependency vulnerabilities, event injection attacks, IAM misconfigurations
− Microservices
    - applications splot into  many small independent services. (auth service, payment service, inventory service, notificatoin service)
    - advantage: fault isolaton, easier scaling, independent updates.
    - risk: more APIs to secure, increased attack surface, complex authentication, service-to-service trust issues. 
− Network infrastructure
    - Key takeaway: The Router connects networks, the Switch connects devices, the Firewall filters by rule, VLANs isolate within the switch, and IDS/IPS hunts for attacks inside the traffic.
    - Router 
        - Connects different networks together. It directs data packets between these networks using the best path
        - NAT (network address translation): allows many deviced on private network to share a single public IP address. 
        - what is a packet?
            - every packet has a header attached to it,
                - source IP (return address)
                - destination IP (where it is going)
                - packet number: (This is packet 4 of 500)
    - Switch
        - Connects devices within the same network (e.g., all computers in an office). It learns which device is connected to which port and sends data only to the intended recipient.
        - MAC address table: remebers which port leads to which device's physical address. 
    - Firewall
        -  Filters traffic based on rules (e.g., "allow web browsing," "block file-sharing," "deny traffic from a specific country"). It inspects packets and decides to pass, drop, or reject them.
        - stateful inspection: tracks the state of active connections
        - Types:
            - hardware firewall (standalone appliance)
            - next-generation firewall (NGFW): addes application awreness by reading further than header. looks into payload. (e.g. allowing "facebook", but blocking "facebook games")
            - virtual /  cloud firewall: (AWS security groups)
    - VLAN (virtual local area network)
        - Logically divides a single physical switch (or network) into multiple, isolated virtual networks. Devices on different VLANs cannot talk to each other without a router.
        - Tagging (802.1Q): adds a small tag to each Ethernet frame to identify which VLAN it belongs to 
    - IDS (Intrision Detection System)/IPS (Intrusion Prevention System)
        - Looks at packet's payload
        - Detect signatures of attacks (SQL injection, malware aptterns, port scans)
        - Action:
            - IDS alerts only (logs, emails admin)
            - IPS blocks inline (drops the malicous packet)
    - advantage: central traffic control, segmentation, monitoring
    - risk: single point of failure, misconfigured devices, lateral movement if flat network 
− Physical isolation
    - Keeping systems physically separated.
    - Air-gapped (Air-gapped = completely disconnected from other networks and internet.)
        - used in: military, critical infrastructure, nuclear facilities
        - advatange: extremely hard to remotely attack
        - risk: usb malware, insider threats, difficult updates/patching
- Logical segmentation
    - Separating systems logically rather than physically.
    - VLAN / ACL / subnets
    - advatange: limits lateral movement, better access control, lower cost than physical separation
    - risk: misconfigurations, VLAN hopping, shared infrastructure
- Software-defined networking (SDN)
    - SDN separates: control plane and data plane. Network becomes programmable
    - advantage: centralised management, dynamic segmentation, faster response
    - risk: controller compromise = huge risk, API vulnerabilities, misconfigurations affect entire network
− On-premises
    - Infrastructure hosted locally by the organization.
    - advantage: full control, better customization, local data governance.
    - risk: expensive, organisation handles everything, requires skilled staff
− Centralized
    - one central control location
    - advantage: easier management, consistent security
    - risk: single point of failure
- Decentralized
    - multiple Distributed system
    - advantage: better resilience, reduced single point failures
    - risk: harder management, inconsistent policies
−Containerization
    - Containers package apps + dependencies together.
    - Docker and Kubernetes
    - advantage: Lightweight, fast deployment, consistency
    - risk: container escape, insecure image, shared kernel vulnerabilities, weak orchestration security
        - what is shared kernel vulnerabilities
            - A shared kernel vulnerability occurs because containers do not have their own operating system; instead, every container on a host shares the single, underlying Linux kernel of that host.If a hacker breaks out of one container, the shared kernel gives them a direct pathway to compromise the host machine and every other container running on it.
            - Containers are just isolated processes running on the host OS. They use kernel features called namespaces (to hide files/processes from each other) and cgroups (to limit resource usage). However, they all talk to the exact same host kernel to execute tasks like writing data or sending network packets.
− Virtualization (virtual machines (VMs))
    - hypervisor runs multiple VMs, on one physical host
    - example: VMware, microsoft
    - advantage: isolation, snapshot recovery, efficient resource use
    - risk: VM escape, hypervisor attacks, VM sprawl, resource exhaustion
    -  Every VM has its own separate guest operating system and kernel. If a virus destroys the kernel of VM #1, VM #2 is completely unaffected because they are physically separated by a hypervisor.
−IoT (Internet of Things)
    - Internet-connected smart devices.
    - examples: smart cameras, smart thermostas, wearables
    - risk: weak passwords, rare patching, insecure firmware, large botnets. 
−Industrial control systems (ICS)/supervisory control and data acquisition (SCADA)
    - used in Industrial environment (power plant, manufacturing, water treatment)
    - monitor / controls systems.
    - in ICS, availability and safety are most important compare to confidentiality. 
    - risk: legacy systems, limited patching, physical consequences, nation-state attacks
−Real-time operating system (RTOS)
    - Processes data immediately within strict timing requirements.
    - used in : medical devices, autootive systems, robotics.
    - advantage: predictable timing, reliablity
    - risk: minimal security features, difficult patching, resource limitation
−Embedded systems
    - Dedicated-purpose computers inside devices.
    - e.g printers, routers, cars, medical devices
    - risk: hardcoded credentials, rare updates, physical exposures, limited resources
−High availability (HA)
    - Systems designed to stay online.
    - methods: redundancy, clutering, failover, load balancing
    - advantage: reduces downtime, improves resilence
    - risk: more complexity, misconfiguration failover, increased attack surface
- Considerations (These are factors organizations evaluate when choosing architectures.)
    −Availability
        - System uptime.
        - Attacks like DDoS and −Ransomware affect availability
    −Resilience
        - Ability to recover from failures/attacks.
        - e.g backups, redundancy, disaster recovery
    −Cost
        - security solution must balance
        - budget, risk, performance
    −Responsiveness
        - How quickly systems react.
        - important for: RTOS, ICS, cloud autoscaling
    −Scalability
        - Ability to grow without performance loss.
        - Cloud and microservices scale well.
    −Ease of deployment
        - How quickly systems can be deployed.
        - Containers and IaC improve this.
    −Risk transference
        - Shifting risk to another party.
        - e.g cyber insurance, cloud providers, managed service providers
    −Ease of recovery
        - How quickly systems can be restored.
        - e.g VM snapshots, backups, IaC redeployment 
    −Patch availability
        - Can updates be obtained quickly?
        - important for: OS, firmware, third-party software
    −Inability to patch
        - Some systems cannot be patched due to: legacy hardware, ICS updatime requirements, vendor limitation
        - compensating controls: segmentation, firewalls, minitoring
    −Power
        - critical for: datacenters, IoT, embedeed system
        - controls UPS, Generators, redundant power
    −Compute
        - Processing capability.
        - more compute = better performance, more VM / container support
        - but also means, more heat, more power use, more cost.



Given a scenario, apply security principles to secure enterprise infrastructure.
- Infrastructure considerations
−Device placement
−Security zones
−Attack surface
−Connectivity
−Failure modes
◦Fail-open
◦Fail-closed
−Device attribute
◦Active vs. passive
◦ Inline vs. tap/monitor
−Network appliances
◦Jump server
◦ Proxy  server
◦ Intrusion  prevention
system (IPS)/intrusion
detection system (IDS)
◦ Load balancer
## ◦ Sensors
−Port security
## ◦802.1X
## ◦ Extensible  Authentication
Protocol (EAP)
−Firewall types
◦ Web application firewall (WAF)
◦ Unified  threat
management (UTM)
◦ Next-generation firewall (NGFW)
◦ Layer 4/Layer 7
- Secure communication/access
−Virtual private network (VPN)
−Remote access
−Tunneling
◦Transport Layer Security (TLS)
◦Internet protocol security (IPSec)
−Software-defined wide area
network (SD-WAN)
−Secure access service edge (SASE)
- Selection of effective controls
## 3.0 Security Architecture
## 3.1
## 3.2


Compare and contrast concepts and strategies to protect data.
- Data types
−Regulated
−Trade secret
−Intellectual property
−Legal information
−Financial information
−Humanand non-human-readable
- Data classifications
−Sensitive
−Confidential
−Public
−Restricted
−Private
−Critical
- General data considerations
−Data states
◦Data at rest
◦ Data in transit
◦ Data in use
−Data sovereignty
−Geolocation
- Methods to secure data
−Geographic restrictions
−Encryption
−Hashing
−Masking
−Tokenization
−Obfuscation
−Segmentation
−Permission restrictions
Explain the importance of resilience and recovery in security architecture.
- High availability
−Load balancing vs. clustering
- Site considerations
−Hot
−Cold
−Warm
−Geographic dispersion
- Platform diversity
- Multi-cloud systems
- Continuity of operations
- Capacity planning
−People
−Technology
−Infrastructure
## • Testing
−Tabletop exercises
−Fail over
−Simulation
−Parallel processing
## • Backups
−Onsite/offsite
−Frequency
−Encryption
−Snapshots
−Recovery
−Replication
−Journaling
## • Power
−Generators
−Uninterruptible power supply (UPS)
## 3.0  |  Security Architecture
## 3.3
## 3.4


Given a scenario, apply common security techniques to computing resources.
- Secure baselines
−Establish
−Deploy
−Maintain
- Hardening targets
−Mobile devices
−Workstations
−Switches
−Routers
−Cloud infrastructure
−Servers
## −ICS/SCADA
−Embedded systems
## −RTOS
−IoT devices
- Wireless devices
−Installation considerations
◦ Site  surveys
◦Heat maps
- Mobile solutions
−Mobile device management (MDM)
−Deployment models
◦Bring your own device (BYOD)
◦Corporate-owned, personally
enabled (COPE)
◦ Choose your own device (CYOD)
−Connection methods
◦Cellular
◦Wi-Fi
◦Bluetooth
- Wireless security settings
− Wi-Fi Protected Access 3 (WPA3)
−AAA/Remote Authentication
Dial-In User Service (RADIUS)
−Cryptographic protocols
−Authentication protocols
- Application security
−Input validation
−Secure cookies
−Static code analysis
−Code signing
## • Sandboxing
## • Monitoring
Explain the security implications of proper hardware, software, and data asset
management.
- Acquisition/procurement process
## • Assignment/accounting
−Ownership
−Classification
- Monitoring/asset tracking
−Inventory
−Enumeration
## • Disposal/decommissioning
−Sanitization
−Destruction
−Certification
−Data retention
## 4.0 Security Operations
## 4.1
## 4.2

Explain various activities associated with vulnerability management.
- Identification methods
−Vulnerability scan
−Application security
◦Static analysis
◦Dynamic analysis
◦Package monitoring
−Threat feed
◦Open-source intelligence (OSINT)
◦Proprietary/third-party
◦Information-sharing organization
◦Dark web
−Penetration testing
−Responsible disclosure program
◦Bug bounty program
−System/process audit
## • Analysis
−Confirmation
◦False positive
◦False negative
−Prioritize
−Common Vulnerability
Scoring System (CVSS)
−Common Vulnerability
Enumeration (CVE)
−Vulnerability classification
−Exposure factor
−Environmental variables
−Industry/organizational impact
−Risk tolerance
- Vulnerability response
and remediation
−Patching
−Insurance
−Segmentation
−Compensating controls
−Exceptions and exemptions
- Validation of remediation
−Rescanning
−Audit
−Verification
## • Reporting
Explain security alerting and monitoring concepts and tools.
- Monitoring computing resources
−Systems
−Applications
−Infrastructure
## • Activities
−Log aggregation
−Alerting
−Scanning
−Reporting
−Archiving
−Alert response and remediation/validation
◦Quarantine
◦Alert tuning
## • Tools
−Security Content Automation Protocol (SCAP)
−Benchmarks
−Agents/agentless
− Security information and event management (SIEM)
## − Antivirus
− Data loss prevention (DLP)
−Simple Network Management Protocol (SNMP) traps
−NetFlow
−Vulnerability scanners
## 4.0  |  Security Operations
## 4.3
## 4.4


Given a scenario, modify enterprise capabilities to enhance security.
## • Firewall
−Rules
−Access lists
−Ports/protocols
−Screened subnets
## • IDS/IPS
−Trends
−Signatures
- Web filter
−Agent-based
−Centralized proxy
−Universal Resource Locator
(URL) scanning
−Content categorization
−Block rules
−Reputation
- Operating system security
−Group Policy
−SELinux
- Implementation of secure protocols
−Protocol selection
−Port selection
−Transport method
- DNS filtering
- Email security
−Domain-based Message
Authentication Reporting and
Conformance (DMARC)
−DomainKeys Identified Mail (DKIM)
−Sender Policy Framework (SPF)
−Gateway
- File integrity monitoring
## • DLP
- Network access control (NAC)
- Endpoint detection and response
(EDR)/extended detection
and response (XDR)
- User behavior analytics
Given a scenario, implement and maintain identity and access management.
## • Provisioning/de-provisioning
user accounts
- Permission assignments
and implications
- Identity proofing
## • Federation
- Single sign-on (SSO)
−Lightweight Directory
Access Protocol (LDAP)
−Open authorization (OAuth)
−Security Assertions Markup
Language (SAML)
## • Interoperability
## • Attestation
- Access controls
−Mandatory
−Discretionary
−Role-based
−Rule-based
−Attribute-based
−Time-of-day restrictions
−Least privilege
- Multifactor authentication
−Implementations
◦Biometrics
◦Hard/soft authentication tokens
◦Security keys
−Factors
◦Something you know
◦Something you have
◦Something you are
◦Somewhere you are
- Password concepts
−Password best practices
◦Length
◦Complexity
◦Reuse
◦Expiration
◦Age
−Password managers
−Passwordless
- Privileged access
management tools
−Just-in-time permissions
−Password vaulting
−Ephemeral credentials
## 4.5
## 4.6
## 4.0  |  Security Operations


Explain the importance of automation and orchestration related to secure operations.
- Use cases of automation
and scripting
−User provisioning
−Resource provisioning
−Guard rails
−Security groups
−Ticket creation
−Escalation
−Enabling/disabling services
−and access
−Continuous integration and testing
−Integrations and Application
programming interfaces (APIs)
## • Benefits
−Efficiency/time saving
−Enforcing baselines
−Standard infrastructure
configurations
−Scaling in a secure manner
−Employee retention
−Reaction time
−Workforce multiplier
- Other considerations
−Complexity
−Cost
−Single point of failure
−Technical debt
−Ongoing supportability
Explain appropriate incident response activities.
## • Process
−Preparation
−Detection
−Analysis
−Containment
−Eradication
−Recovery
−Lessons learned
## • Training
## • Testing
−Tabletop exercise
−Simulation
- Root cause analysis
- Threat hunting
- Digital forensics
−Legal hold
−Chain of custody
−Acquisition
−Reporting
−Preservation
−E-discovery
## 4.7
## 4.8
## 4.0  |  Security Operations
Given a scenario, use data sources to support an investigation.
- Log data
−Firewall logs
−Application logs
−Endpoint logs
−OS-specific security logs
−IPS/IDS logs
−Network logs
−Metadata
- Data sources
−Vulnerability scans
−Automated reports
−Dashboards
−Packet captures
## 4.9

Summarize elements of effective security governance.
## • Guidelines
## • Policies
−Acceptable use policy (AUP)
−Information security policies
−Business continuity
−Disaster recovery
−Incident response
−Software development
lifecycle (SDLC)
−Change management
## • Standards
−Password
−Access control
−Physical security
−Encryption
## • Procedures
−Change management
−Onboarding/offboarding
−Playbooks
- External considerations
−Regulatory
−Legal
−Industry
−Local/regional
−National
−Global
- Monitoring and revision
- Types of governance structures
−Boards
−Committees
−Government entities
−Centralized/decentralized
- Roles and responsibilities
for systems and data
−Owners
−Controllers
−Processors
−Custodians/stewards
Explain elements of the risk management process.
- Risk identification
- Risk assessment
−Ad hoc
−Recurring
−One-time
−Continuous
- Risk analysis
−Qualitative
−Quantitative
−Single loss expectancy (SLE)
−Annualized loss expectancy (ALE)
−Annualized rate of occurrence (ARO)
−Probability
−Likelihood
−Exposure factor
−Impact
- Risk register
−Key risk indicators
−Risk owners
−Risk threshold
- Risk tolerance
- Risk appetite
−Expansionary
−Conservative
−Neutral
- Risk management strategies
−Transfer
−Accept
## ◦ Exemption
◦Exception
−Avoid
−Mitigate
- Risk reporting
- Business impact analysis
−Recovery time objective (RTO)
−Recovery point objective (RPO)
−Mean time to repair (MTTR)
−Mean time between failures (MTBF)
5.0 Security Program Management and Oversight
## 5.1
## 5.2



Explain the processes associated with third-party risk assessment and management.
- Vendor assessment
−Penetration testing
−Right-to-audit clause
−Evidence of internal audits
−Independent assessments
−Supply chain analysis
- Vendor selection
−Due diligence
−Conflict of interest
- Agreement types
−Service-level agreement (SLA)
−Memorandum of agreement (MOA)
−Memorandum of
understanding (MOU)
−Master service agreement (MSA)
−Work order (WO)/statement
of work (SOW)
−Non-disclosure agreement (NDA)
−Business partners agreement (BPA)
- Vendor monitoring
## • Questionnaires
- Rules of engagement
Summarize elements of effective security compliance.
- Compliance reporting
−Internal
−External
- Consequences of non-compliance
−Fines
−Sanctions
−Reputational damage
−Loss of license
−Contractual impacts
- Compliance monitoring
−Due diligence/care
−Attestation and acknowledgement
−Internal and external
−Automation
## • Privacy
−Legal implications
◦Local/regional
◦National
◦Global
−Data subject
−Controller vs. processor
−Ownership
−Data inventory and retention
−Right to be forgotten
5.0  |  Security Program Management and Oversight
## 5.3
## 5.4
Explain types and purposes of audits and assessments.
## • Attestation
## • Internal
−Compliance
−Audit committee
−Self-assessments
## • External
−Regulatory
−Examinations
−Assessment
−Independent third-party audit
- Penetration testing
−Physical
−Offensive
−Defensive
−Integrated
−Known environment
−Partially known environment
−Unknown environment
−Reconnaissance
## ◦ Passive
◦Active
## 5.5

Given a scenario, implement security awareness practices.
## • Phishing
−Campaigns
−Recognizing a phishing attempt
−Responding to reported
suspicious messages
- Anomalous behavior recognition
−Risky
−Unexpected
−Unintentional
- User guidance and training
−Policy/handbooks
−Situational awareness
−Insider threat
−Password management
−Removable media and cables
−Social engineering
−Operational security
−Hybrid/remote work environments
- Reporting and monitoring
−Initial
−Recurring
## • Development
## • Execution
5.0  |  Security Program Management and Oversight
## 5.6


CompTIA Security+ SY0-701 Acronym List
The following is a list of acronyms that appears on the CompTIA Security+
SY0-701 exam. Candidates are encouraged to review the complete list and
attain a working knowledge of all listed acronyms as part of a comprehensive
exam preparation program.
## ACRONYM    DEFINITION
2FA Two-factor Authentication
3DES Triple Data Encryption Standard
AAA Authentication, Authorization, and Accounting
ACL Access Control List
AES Advanced Encryption Standard
AES-256 Advanced Encryption Standards 256-bit
AH Authentication Header
AI Artificial Intelligence
AIS Automated Indicator Sharing
ALE Annualized Loss Expectancy
AP Access Point
API Application Programming Interface
APT Advanced Persistent Threat
ARO Annualized Rate of Occurrence
ARP Address Resolution Protocol
ASLR Address Space Layout Randomization
ATT&CK Adversarial Tactics, Techniques, and Common Knowledge
AUP Acceptable Use Policy
AV Antivirus
BASH Bourne Again Shell
BCP Business Continuity Planning
BGP Border Gateway Protocol
BIA Business Impact Analysis
BIOS Basic Input/Output System
BPA Business Partners Agreement
BPDU Bridge Protocol Data Unit
BYOD Bring Your Own Device
CA Certificate Authority
CAPTCHA Completely Automated Public Turing Test to Tell Computers and Humans Apart
CAR Corrective Action Report
CASB Cloud Access Security Broker
CBC Cipher Block Chaining
CCMP Counter Mode/CBC-MAC Protocol
CCTV Closed-circuit Television
CERT Computer Emergency Response Team
CFB Cipher Feedback
CHAP Challenge Handshake Authentication Protocol
CIA Confidentiality, Integrity, Availability
CIO Chief Information Officer
CIRT Computer Incident Response Team
CMS Content Management System
COBO Corporate-owned, Business-only


COOP Continuity of Operation Planning
COPE Corporate Owned, Personally Enabled
CP Contingency Planning
CRC Cyclical Redundancy Check
CRL Certificate Revocation List
CSO Chief Security Officer
CSP Cloud Service Provider
CSR Certificate Signing Request
CSRF Cross-site Request Forgery
CSU Channel Service Unit
CTM Counter Mode
CTO Chief Technology Officer
CVE Common Vulnerability Enumeration
CVSS Common Vulnerability Scoring System
CYOD Choose Your Own Device
DAC Discretionary Access Control
DBA Database Administrator
DDoS Distributed Denial of Service
DEP Data Execution Prevention
DES Digital Encryption Standard
DHCP Dynamic Host Configuration Protocol
DHE Diffie-Hellman Ephemeral
DKIM DomainKeys Identified Mail
DLL Dynamic Link Library
DLP Data Loss Prevention
DMARC Domain Message Authentication Reporting and Conformance
DNAT Destination Network Address Translation
DNS Domain Name System
DNSSEC Domain Name System Security Extensions
DoS Denial of Service
DPO Data Privacy Officer
DRP Disaster Recovery Plan
DSA Digital Signature Algorithm
DSL Digital Subscriber Line
EAP Extensible Authentication Protocol
ECB Electronic Code Book
ECC Elliptic Curve Cryptography
ECDHE Elliptic Curve Diffie-Hellman Ephemeral
ECDSA Elliptic Curve Digital Signature Algorithm
EDR Endpoint Detection and Response
EFS Encrypted File System
ERP Enterprise Resource Planning
ESN Electronic Serial Number
ESP Encapsulated Security Payload
EULA End User License Agreement
FACL File System Access Control List
FDE Full Disk Encryption
FIM File Integrity Management
FPGA Field Programmable Gate Array
FRR False Rejection Rate
FTP File Transfer Protocol
FTPS Secured File Transfer Protocol
GCM Galois Counter Mode
GDPR General Data Protection Regulation
## ACRONYM    DEFINITION


GPG Gnu Privacy Guard
GPO Group Policy Object
GPS Global Positioning System
GPU Graphics Processing Unit
GRE Generic Routing Encapsulation
HA High Availability
HDD Hard Disk Drive
HIDS Host-based Intrusion Detection System
HIPS Host-based Intrusion Prevention System
HMAC Hashed Message Authentication Code
HOTP HMAC-based One-time Password
HSM Hardware Security Module
HTML Hypertext Markup Language
HTTP Hypertext Transfer Protocol
HTTPS Hypertext Transfer Protocol Secure
HVAC Heating, Ventilation Air Conditioning
IaaS Infrastructure as a Service
IaC Infrastructure as Code
IAM Identity and Access Management
ICMP Internet Control Message Protocol
ICS Industrial Control Systems
IDEA International Data Encryption Algorithm
IDF Intermediate Distribution Frame
IdP Identity Provider
IDS Intrusion Detection System
IEEE Institute of Electrical and Electronics Engineers
IKE Internet Key Exchange
IM Instant Messaging
IMAP Internet Message Access Protocol
IoC Indicators of Compromise
IoT Internet of Things
IP Internet Protocol
IPS Intrusion Prevention System
IPSec Internet Protocol Security
IR Incident Response
IRC Internet Relay Chat
IRP Incident Response Plan
ISO International Standards Organization
ISP Internet Service Provider
ISSO Information Systems Security Officer
IV Initialization Vector
KDC Key Distribution Center
KEK Key Encryption Key
L2TP Layer 2 Tunneling Protocol
LAN Local Area Network
LDAP Lightweight Directory Access Protocol
LEAP Lightweight Extensible Authentication Protocol
MaaS Monitoring as a Service
MAC Mandatory Access Control
MAC Media Access Control
MAC Message Authentication Code
MAN Metropolitan Area Network
MBR Master Boot Record
MD5 Message Digest 5
## ACRONYM    DEFINITION


MDF Main Distribution Frame
MDM Mobile Device Management
MFA Multifactor Authentication
MFD Multifunction Device
MFP Multifunction Printer
ML Machine Learning
MMS Multimedia Message Service
MOA Memorandum of Agreement
MOU Memorandum of Understanding
MPLS Multi-protocol Label Switching
MSA Master Service Agreement
MSCHAP Microsoft Challenge Handshake Authentication Protocol
MSP Managed Service Provider
MSSP Managed Security Service Provider
MTBF Mean Time Between Failures
MTTF Mean Time to Failure
MTTR Mean Time to Recover
MTU Maximum Transmission Unit
MX Mail Exchange
NAC Network Access Control
NAT Network Address Translation
NDA Non-disclosure Agreement
NFC Near Field Communication
NGFW Next-generation Firewall
NIDS Network-based Intrusion Detection System
NIPS Network-based Intrusion Prevention System
NIST National Institute of Standards & Technology
NTFS New Technology File System
NTLM New Technology LAN Manager
NTP Network Time Protocol
OAUTH Open Authorization
OCSP Online Certificate Status Protocol
OID Object Identifier
OS Operating System
OSINT Open-source Intelligence
OSPF Open Shortest Path First
OT Operational Technology
OTA Over the Air
OVAL Open Vulnerability Assessment Language
OWASP Open Worldwide Application Security Project
## P12 PKCS #12
P2P Peer to Peer
PaaS Platform as a Service
PAC Proxy Auto Configuration
PAM Privileged Access Management
PAM Pluggable Authentication Modules
PAP Password Authentication Protocol
PAT Port Address Translation
PBKDF2 Password-based Key Derivation Function 2
PBX Private Branch Exchange
PCAP Packet Capture
PCI DSS Payment Card Industry Data Security Standard
PDU Power Distribution Unit
PEAP Protected Extensible Authentication Protocol
## ACRONYM    DEFINITION


PED Personal Electronic Device
PEM Privacy Enhanced Mail
PFS Perfect Forward Secrecy
PGP Pretty Good Privacy
PHI Personal Health Information
PII Personally Identifiable Information
PIV Personal Identity Verification
PKCS Public Key Cryptography Standards
PKI Public Key Infrastructure
POP Post Office Protocol
POTS Plain Old Telephone Service
PPP Point-to-Point Protocol
PPTP Point-to-Point Tunneling Protocol
PSK Pre-shared Key
PTZ Pan-tilt-zoom
PUP Potentially Unwanted Program
RA Recovery Agent
RA Registration Authority
RACE Research and Development in Advanced Communications Technologies in Europe
RAD Rapid Application Development
RADIUS Remote Authentication Dial-in User Service
RAID Redundant Array of Inexpensive Disks
RAS Remote Access Server
RAT Remote Access Trojan
RBAC Role-based Access Control
RBAC Rule-based Access Control
RC4 Rivest Cipher version 4
RDP Remote Desktop Protocol
RFID Radio Frequency Identifier
RIPEMD RACE Integrity Primitives Evaluation Message Digest
ROI Return on Investment
RPO Recovery Point Objective
RSA Rivest, Shamir, & Adleman
RTBH Remotely Triggered Black Hole
RTO Recovery Time Objective
RTOS Real-time Operating System
RTP Real-time Transport Protocol
S/MIME Secure/Multipurpose Internet Mail Extensions
SaaS Software as a Service
SAE Simultaneous Authentication of Equals
SAML Security Assertions Markup Language
SAN Storage Area Network
SAN Subject Alternative Name
SASE Secure Access Service Edge
SCADA Supervisory Control and Data Acquisition
SCAP Security Content Automation Protocol
SCEP Simple Certificate Enrollment Protocol
SD-WAN Software-defined Wide Area Network
SDK Software Development Kit
SDLC Software Development Lifecycle
SDLM Software Development Lifecycle Methodology
SDN Software-defined Networking
SE Linux Security-enhanced Linux
SED Self-encrypting Drives
## ACRONYM    DEFINITION


SEH Structured Exception Handler
SFTP Secured File Transfer Protocol
SHA Secure Hashing Algorithm
SHTTP Secure Hypertext Transfer Protocol
SIEM Security Information and Event Management
SIM Subscriber Identity Module
SLA Service-level Agreement
SLE Single Loss Expectancy
SMB Server Message Block
SMS Short Message Service
SMTP Simple Mail Transfer Protocol
SMTPS Simple Mail Transfer Protocol Secure
SNMP Simple Network Management Protocol
SOAP Simple Object Access Protocol
SOAR Security Orchestration, Automation, Response
SoC System on Chip
SOC Security Operations Center
SOW Statement of Work
SPF Sender Policy Framework
SPIM Spam over Internet Messaging
SQL Structured Query Language
SQLi SQL Injection
SRTP Secure Real-Time Protocol
SSD Solid State Drive
SSH Secure Shell
SSL Secure Sockets Layer
SSO Single Sign-on
STIX Structured Threat Information eXchange
SWG Secure Web Gateway
TACACS+ Terminal Access Controller Access Control System
TAXII Trusted Automated eXchange of Indicator Information
TCP/IP Transmission Control Protocol/Internet Protocol
TGT Ticket Granting Ticket
TKIP Temporal Key Integrity Protocol
TLS Transport Layer Security
TOC                     Time-of-check
TOTP Time-based One-time Password
TOU                     Time-of-use
TPM Trusted Platform Module
TTP Tactics, Techniques, and Procedures
TSIG Transaction Signature
UAT User Acceptance Testing
UAV Unmanned Aerial Vehicle
UBA User Behavior Analytics
UDP User Datagram Protocol
UEFI Unified Extensible Firmware Interface
UEM Unified Endpoint Management
UPS Uninterruptible Power Supply
URI Uniform Resource Identifier
URL Universal Resource Locator
USB Universal Serial Bus
USB OTG USB On the Go
UTM Unified Threat Management
UTP Unshielded Twisted Pair
## ACRONYM    DEFINITION


VBA Visual Basic
VDE Virtual Desktop Environment
VDI Virtual Desktop Infrastructure
VLAN Virtual Local Area Network
VLSM Variable Length Subnet Masking
VM Virtual Machine
VoIP Voice over IP
VPC Virtual Private Cloud
VPN  Virtual Private Network
VTC Video Teleconferencing
WAF Web Application Firewall
WAP Wireless Access Point
WEP Wired Equivalent Privacy
WIDS Wireless Intrusion Detection System
WIPS Wireless Intrusion Prevention System
WO Work Order
WPA Wi-Fi Protected Access
WPS Wi-Fi Protected Setup
WTLS Wireless TLS
XDR Extended Detection and Response
XML Extensible Markup Language
XOR Exclusive Or
XSRF Cross-site Request Forgery
XSS Cross-site Scripting
## ACRONYM    DEFINITION

## EQUIPMENT
## •  Tablet
## •  Laptop
-  Web server
## •  Firewall
## •  Router
## •  Switch
## •  IDS
## •  IPS
-  Wireless access point
-  Virtual machines
-  Email system
-  Internet access
-  DNS server
-  IoT devices
-  Hardware tokens
## •  Smartphone
## SPARE PARTS/HARDWARE
-  NICs
-  Power supplies
-  GBICs
-  SFPs
## •  Managed Switch
-  Wireless access point
## •  UPS
## TOOLS
-  Wi-Fi analyzer
-  Network mapper
-  NetFlow analyzer
## SOFTWARE
-  Windows OS
-  Linux OS
## •  Kali Linux
-  Packet capture software
-  Pen testing software
-  Static and dynamic analysis tools
-  Vulnerability scanner
-  Network emulators
-  Sample code
-  Code editor
## •  SIEM
## •  Keyloggers
-  MDM software
## •  VPN
-  DHCP service
-  DNS service
## OTHER
-  Access to cloud environments
-  Sample network documentation/
diagrams
-  Sample logs
CompTIA has included this sample list of hardware and software
to assist candidates as they prepare for the Security+ SY0-701
certification exam. This list may also be helpful for training companies
that wish to create a lab component for their training offering. The
bulleted lists below each topic are sample lists and are not exhaustive.
CompTIA Security+ SY0-701 Hardware
and Software List
© 2023 CompTIA, Inc., used under license by CompTIA, Inc. All rights reserved. All certification programs and education related to such
programs are operated exclusively by CompTIA, Inc. CompTIA is a registered trademark of CompTIA, Inc. in the U.S. and internationally.
Other brands and company names mentioned herein may be trademarks or service marks of CompTIA, Inc. or of their respective owners.
Reproduction or dissemination prohibited without the written consent of CompTIA, Inc. Printed in the U.S. 10179-Jan2023
