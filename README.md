# SOC-Simulator
Email arrives → security controls detect it → SOC alert → human analyst investigates → verdict → incident report.

**The user wants to simulate a realistic organizational environment in which:**

* A simulated attacker sends phishing emails.
* A simulated client/user receives those emails.
* The emails are delivered into the client's mailbox.
* An email detection/inspection component automatically notices newly delivered emails.
* The email detector performs PRELIMINARY automated analysis.
* The detector generates security telemetry.
* Wazuh acts as the SIEM/security monitoring platform.
* Wazuh applies rules/correlation/severity logic.
* Medium/High-risk events become SOC alerts.
* The human user acts as the SOC L1 analyst.
* The analyst investigates the alert manually.
* The analyst extracts IOCs and decides what needs further investigation.
* The analyst invokes separate investigation/enrichment tools as required.
* The analyst determines the final verdict/severity.
* The analyst closes the alert.
* The analyst writes an incident/investigation report.

**The objective is NOT to create an automated "phishing checker" that simply gives the user the answer**

The project will use a controlled internal mail environment, rather than relying on a real Gmail account as the victim mailbox.
A controlled mail environment gives us control over:

* SMTP
* mail delivery
* mailbox creation
* email storage
* headers
* message replay
* test scenarios
* reset/reproducibility
* detection
* integration with Wazuh
* multiple simulated users (if needed)

An Gmail account in general would introduce an external Architecture and predictable unbehaviour: 
* Gmail Filtering
* Spam Classification
* Authentication Controls

The mailbox should therefore be a realistic webmail/client mailbox running inside the lab.

**Architecture**
