"""
menu.py — The Dashboard / Control Panel

This is what the user sees after they're authorized.
It's the main hub — like a TV remote — you pick what you want to do.

Options will include:
 1. Run Network Scanner (Recon)
 2. Run Vulnerability Intel (Intel)
 3. Run Web Application Tester (Breach)
 4. Run Full Scan (all of the above)
 5. View Reports
 6. Exit
"""

import os
import sys


class MainMenu:
 """
 The main control panel for the toolkit.
 
 Once the user is authorized, this is what they interact with.
 It presents options, takes input, and launches the right module.
 """

 def __init__(self, settings: dict, logger):
 self.settings = settings
 self.logger = logger
 self.running = True # Controls the main loop

 def run(self):
 """
 The main loop.
 
 A "loop" is like a merry-go-round — it keeps spinning 
 (showing the menu) until the user chooses to stop (Exit).
 """
 while self.running:
 self._display_menu()
 choice = self._get_choice()
 self._handle_choice(choice)

 def _display_menu(self):
 """
 Print the menu to the screen.
 Called every time we return to the main menu.
 """
 scope = self.settings.get('scope', ['Not defined'])
 scope_display = ', '.join(scope) if scope else 'Not defined'

 print("\n" + "="*60)
 print(" DAYEA — MAIN MENU")
 print("="*60)
 print(f" Authorized Scope: {scope_display}")
 print("-"*60)
 print("""
 SCANNING MODULES:
 ─────────────────
 [1] Recon — Network Scanner
 [2] Intel — Vulnerability Checker 
 [3] Breach — Web Application Scanner
 [4] Full Scan — Run All Modules

 RESULTS:
 ────────
 [5] View Reports — Browse saved scan results
 [6] Open Log File — View the activity log

 SETTINGS:
 ─────────
 [7] ⚙️ Settings — View/Edit configuration
 [8] Exit — Quit the toolkit
 """)
 print("="*60)

 def _get_choice(self) -> str:
 """
 Ask the user to type their choice and return it.
 
 Returns:
 str: Whatever the user typed
 """
 try:
 choice = input(" Enter your choice (1-8): ").strip()
 return choice
 except KeyboardInterrupt:
 # This handles when the user presses Ctrl+C
 print("\n\n Ctrl+C detected. Exiting safely...")
 self.logger.info("User pressed Ctrl+C — exiting")
 sys.exit(0)

 def _handle_choice(self, choice: str):
 """
 Look at what the user chose and do the right thing.
 
 This is called a "dispatcher" — it dispatches (sends) the
 user to the right place based on their choice.
 
 Args:
 choice: The number the user typed
 """
 self.logger.info(f"User selected menu option: {choice}")

 if choice == '1':
 self._launch_scout()
 elif choice == '2':
 self._launch_inspector()
 elif choice == '3':
 self._launch_web_tester()
 elif choice == '4':
 self._launch_full_scan()
 elif choice == '5':
 self._view_reports()
 elif choice == '6':
 self._view_log()
 elif choice == '7':
 self._view_settings()
 elif choice == '8':
 self._exit()
 else:
 print(f"\n '{choice}' is not a valid option. Please enter 1-8.")

 # ── Module Launchers ────────────────────────────────────────────
 # These will connect to the actual modules (built in next steps)
 # For now they show a "Coming Soon" placeholder

 def _launch_scout(self):
 """Launch the Network Scanner module"""
 print("\n Launching Recon — Network Scanner...")
 self.logger.section("LAUNCHING: Network Scanner (Recon)")
 try:
 from modules.scout import NetworkScanner
 scanner = NetworkScanner(self.settings, self.logger)
 scanner.run()
 except ImportError:
 print(" ⏳ Module coming in Step 2. Framework is ready!")
 self.logger.info("Recon module not yet installed")

 def _launch_inspector(self):
 """Launch the Vulnerability Intel module"""
 print("\n Launching Intel — Vulnerability Checker...")
 self.logger.section("LAUNCHING: Vulnerability Intel")
 try:
 from modules.inspector import VulnerabilityIntel
 inspector = VulnerabilityIntel(self.settings, self.logger)
 inspector.run()
 except ImportError:
 print(" ⏳ Module coming in Step 3. Framework is ready!")
 self.logger.info("Intel module not yet installed")

 def _launch_web_tester(self):
 """Launch the Web Application Tester module"""
 print("\n Launching Breach — Web Application Scanner...")
 self.logger.section("LAUNCHING: Web Application Tester")
 try:
 from modules.web_tester import WebTester
 tester = WebTester(self.settings, self.logger)
 tester.run()
 except ImportError:
 print(" ⏳ Module coming in Step 4. Framework is ready!")
 self.logger.info("Breach module not yet installed")

 def _launch_full_scan(self):
 """Run all three modules in sequence"""
 print("\n Full Scan — Running all modules in sequence...")
 self.logger.section("LAUNCHING: Full Scan (All Modules)")
 print(" This will run: Recon → Intel → Breach")
 confirm = input(" Confirm full scan? (YES/no): ").strip().upper()
 if confirm == "YES":
 self._launch_scout()
 self._launch_inspector()
 self._launch_web_tester()
 print("\n ✅ Full scan sequence complete.")
 else:
 print(" Full scan cancelled.")

 def _view_reports(self):
 """Show available reports"""
 print("\n Available Reports:")
 print(" " + "-"*40)
 reports_dir = self.settings.get('output_dir', 'reports')
 if os.path.exists(reports_dir):
 files = os.listdir(reports_dir)
 if files:
 for i, f in enumerate(files, 1):
 print(f" {i}. {f}")
 else:
 print(" No reports generated yet. Run a scan first.")
 else:
 print(" Reports folder doesn't exist yet. Run a scan first.")

 def _view_log(self):
 """Show the current log file path"""
 log_path = self.logger.get_log_file_path()
 print(f"\n Current log file: {log_path}")
 print(" (Open this file in any text editor to view activity)")

 def _view_settings(self):
 """Display current settings"""
 print("\n ⚙️ Current Settings:")
 print(" " + "-"*40)
 for key, value in self.settings.items():
 if not key.startswith('_'): # Skip comment fields
 print(f" {key:20} : {value}")
 print("\n To change settings, edit: config/settings.json")

 def _exit(self):
 """Gracefully exit the toolkit"""
 print("\n Thank you for using Dayea responsibly.")
 print(" All activity has been logged.\n")
 self.logger.info("User exited toolkit gracefully")
 self.running = False
 sys.exit(0)
