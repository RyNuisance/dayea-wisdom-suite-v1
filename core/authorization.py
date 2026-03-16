"""
authorization.py — The Permission Checker

Think of this like a contract you sign before entering a building.
Before the toolkit does ANYTHING, it forces the user to confirm:
 1. They own or have written permission to test the target
 2. They understand the legal implications
 3. They define EXACTLY what they're allowed to test (the "scope")

If any of these checks fail → the tool stops completely.
"""

import os
from datetime import datetime


class AuthorizationGate:
 """
 The "Bouncer" class.
 
 Every single run of the toolkit must pass through here first.
 No exceptions. No shortcuts.
 """

 def __init__(self, logger):
 # We pass in the logger so this class can record what happens
 self.logger = logger
 self.auth_record = {} # We'll store the authorization details here

 def verify(self) -> bool:
 """
 Walk the user through a series of checks.
 Returns True if everything checks out, False if anything fails.
 
 Returns:
 bool: True = authorized, False = not authorized
 """
 print("\n" + "="*60)
 print(" AUTHORIZATION VERIFICATION")
 print("="*60)
 print("\nBefore this tool runs, you MUST confirm authorization.")
 print("This protects YOU legally and ensures ethical use.\n")

 # Check 1: Written permission
 if not self._check_written_permission():
 return False

 # Check 2: Scope definition
 if not self._define_scope():
 return False

 # Check 3: Legal acknowledgment
 if not self._legal_acknowledgment():
 return False

 # All checks passed — log it and continue
 self._save_auth_record()
 print("\n✅ Authorization confirmed. Proceeding safely.\n")
 return True

 def _check_written_permission(self) -> bool:
 """
 Ask if the user has written permission.
 Written = email, contract, or signed document from the system owner.
 """
 print("CHECK 1: Written Permission")
 print("-" * 40)
 print("Do you have WRITTEN authorization to perform penetration")
 print("testing on the target system(s)?")
 print("\nExamples of written permission:")
 print(" • A signed penetration testing agreement")
 print(" • An email from the system owner authorizing testing")
 print(" • A bug bounty program scope that includes this target")
 print(" • You OWN the system yourself\n")

 response = input("Type YES to confirm, anything else to exit: ").strip().upper()

 if response != "YES":
 self.logger.warning("User did not confirm written permission")
 return False

 # Ask for reference number or description
 reference = input("\nBriefly describe your authorization (e.g. 'Own lab', 'Client contract #123'): ").strip()
 if not reference:
 reference = "Not provided"

 self.auth_record['permission_confirmed'] = True
 self.auth_record['permission_reference'] = reference
 self.logger.info(f"Written permission confirmed. Reference: {reference}")
 print("✅ Permission confirmed.\n")
 return True

 def _define_scope(self) -> bool:
 """
 Ask the user to define their scope.
 
 Scope = the exact list of what you're allowed to test.
 Like a builder's blueprint — you only work on what's on the plan.
 
 Example scope: "192.168.1.0/24" means only test IPs in that range.
 """
 print("CHECK 2: Define Your Scope")
 print("-" * 40)
 print("You must define EXACTLY what you are authorized to test.")
 print("The tool will REFUSE to run against anything outside this scope.\n")
 print("Examples:")
 print(" • Single IP: 192.168.1.100")
 print(" • IP Range: 192.168.1.0/24")
 print(" • Domain: testsite.example.com")
 print(" • Multiple: 192.168.1.100, 192.168.1.101\n")

 scope_input = input("Enter your authorized scope: ").strip()

 if not scope_input:
 print("Scope cannot be empty.")
 self.logger.warning("Empty scope provided")
 return False

 # Parse scope into a list (split by commas)
 scope_list = [s.strip() for s in scope_input.split(',') if s.strip()]

 print(f"\nYour authorized scope ({len(scope_list)} target(s)):")
 for i, target in enumerate(scope_list, 1):
 print(f" {i}. {target}")

 confirm = input("\nIs this correct? (YES/no): ").strip().upper()
 if confirm != "YES":
 print("Scope not confirmed. Please restart and try again.")
 return False

 self.auth_record['scope'] = scope_list
 self.logger.info(f"Scope defined: {scope_list}")
 print("✅ Scope confirmed.\n")
 return True

 def _legal_acknowledgment(self) -> bool:
 """
 Final legal acknowledgment.
 The user must read and agree to the terms before proceeding.
 """
 print("⚖️ CHECK 3: Legal Acknowledgment")
 print("-" * 40)
 print("""
By proceeding, you acknowledge that:

 1. You have WRITTEN authorization to test the defined scope
 2. Unauthorized computer access is ILLEGAL in most countries
 (e.g. Computer Fraud and Abuse Act in the US, Computer 
 Misuse Act in the UK, and similar laws worldwide)
 3. You take FULL legal responsibility for how you use this tool
 4. This tool is for DEFENSIVE security purposes only
 5. You will not use findings to cause harm or for personal gain
 6. All findings will be reported responsibly to the system owner
 """)

 response = input("Type 'I AGREE' to acknowledge and proceed: ").strip().upper()

 if response != "I AGREE":
 self.logger.warning("User did not agree to legal terms")
 return False

 self.auth_record['legal_acknowledged'] = True
 self.auth_record['acknowledged_at'] = datetime.now().isoformat()
 self.logger.info("Legal acknowledgment confirmed")
 print("✅ Legal acknowledgment confirmed.\n")
 return True

 def _save_auth_record(self):
 """
 Save a record of the authorization to a file.
 This creates a paper trail — important for professional engagements.
 Like saving a receipt.
 """
 self.auth_record['session_start'] = datetime.now().isoformat()

 os.makedirs("logs", exist_ok=True)
 filename = f"logs/auth_record_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

 with open(filename, 'w') as f:
 f.write("DAYEA — AUTHORIZATION RECORD\n")
 f.write("="*40 + "\n")
 for key, value in self.auth_record.items():
 f.write(f"{key}: {value}\n")

 self.logger.info(f"Authorization record saved to {filename}")
 print(f" Authorization record saved to: {filename}")
