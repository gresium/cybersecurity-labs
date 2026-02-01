# Honeypot simulating SSH Server 
 
# Objective
Deploy a honeypot that simulates an SSH server, capture brute-force login attempts (username/password), and demonstrate automated mitigation (Fail2Ban). This was a lab/educational exercise to show how attackers probe public SSH and how simple defenses can gather telemetry and block offenders.
 
# Environment
•	Host: VirtualBox VM running Kali Linux (guest)
•	User: kali (local development)
•	Tools attempted: Cowrie (full honeypot), Fail2Ban, custom Python honeypot (final working solution)
•	Ports used: honeypot on TCP 2222, hardened SSH on 2223 (planned)
 
# Summary of what I did (high level)
1.	Attempted to install Cowrie (a full-featured SSH honeypot) and set up hardened SSH and Fail2Ban.
2.	Hit multiple environment and repository issues when trying to run Cowrie (missing bin/cowrie, repo problems, syntax/indentation confusion from manual edits).
3.	Rather than spend excessive time debugging installer/repo issues for the school project, switched to a minimal Python honeypot that:
o	Listens on TCP/2222,
o	Presents a fake SSH banner,
o	Captures username/password typed by a client,
o	Logs attempts to a local log file,
o	Can be monitored by Fail2Ban for automated banning.
 
# What failed / issues encountered (brief, honest)
•	Cowrie install encountered missing scripts (bin/cowrie), repo-state confusion, and later file/indentation errors while editing a 1700-line cowrie.cfg. I tried to fix by restoring cowrie.cfg.dist and making targeted edits, but the environment contained a partly broken repo and running Cowrie repeatedly failed.
•	Manual edits to large config files caused syntax/indentation mistakes and SyntaxError when running Python scripts.
•	Time constraints (project deadline) made it more practical to demonstrate the concept with a small, robust honeypot rather than recover a full Cowrie deployment.
These are realistic issues you often hit in real deployments — repo/permission/config drift and copy/paste errors are common.
 
# Final working solution (what I actually ran)
I implemented a single-file, minimal honeypot (~/honeypot.py) that you can run directly. It is safe for a lab environment, simple to explain, and produces clear logs for analysis.
Script (created as ~/honeypot.py)
(Already created in the VM; below is the canonical version used.)

# Optional: integration with Fail2Ban (demonstrated idea)
I prepared Fail2Ban configs to watch the honeypot.log and ban IPs after repeated attempts. Implementation steps (if you want to enable it)

# What I learned (lessons)
•	Full-featured projects like Cowrie are great for production telemetry but can be time-consuming to install and debug in a short lab window. Repo/permission/config issues are common and costly.
•	For school demonstrations, a minimal, well-documented prototype that captures the same concept (collecting attacker credentials and showing automated response) is perfectly acceptable and often clearer.
•	Always keep backups before editing large config files. Use cp etc/cowrie.cfg.dist etc/cowrie.cfg and append overrides instead of manually editing huge files.
•	Use git clone into a clean folder; don’t try to “repair” a broken mixed folder unless you know git internals.



