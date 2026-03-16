"""
logger.py — The Security Camera

Every single thing this toolkit does gets recorded here.
This is critical for:
 - Legal protection (proof of what you did and didn't do)
 - Debugging (finding problems in the tool itself)
 - Audit trails (showing clients exactly what was tested)

Think of it like a black box recorder on an airplane.
It runs quietly in the background and captures everything.
"""

import logging
import os
from datetime import datetime


class ToolkitLogger:
 """
 A wrapper around Python's built-in logging system.
 
 "Wrapper" means we took something that already exists (Python's logger)
 and added our own custom features on top — like adding a custom case
 to a phone.
 
 Log Levels (from least to most serious):
 DEBUG → Very detailed info, only useful when hunting bugs
 INFO → Normal operations ("Scan started", "Found 3 open ports")
 WARNING → Something unusual but not breaking ("Slow response time")
 ERROR → Something went wrong ("Could not connect to target")
 CRITICAL→ Catastrophic failure ("Tool is about to crash")
 """

 def __init__(self, log_dir: str = "logs"):
 """
 Set up the logger when the toolkit first starts.
 
 Args:
 log_dir: The folder where log files will be saved
 """
 # Create the logs folder if it doesn't exist
 os.makedirs(log_dir, exist_ok=True)

 # Create a unique log filename using the current timestamp
 # This means every session gets its own log file
 timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
 self.log_file = os.path.join(log_dir, f"session_{timestamp}.log")

 # Create the logger object with the name "dayea"
 self.logger = logging.getLogger("dayea")
 self.logger.setLevel(logging.DEBUG) # Capture EVERYTHING

 # ── Handler 1: Write to a FILE ──────────────────────────────
 # This saves logs permanently to disk
 file_handler = logging.FileHandler(self.log_file)
 file_handler.setLevel(logging.DEBUG)

 # Format: [2024-01-15 14:30:22] INFO - Scan started on 192.168.1.1
 file_format = logging.Formatter(
 '[%(asctime)s] %(levelname)-8s - %(message)s',
 datefmt='%Y-%m-%d %H:%M:%S'
 )
 file_handler.setFormatter(file_format)

 # ── Handler 2: Print to SCREEN ──────────────────────────────
 # This shows logs in the terminal as they happen
 console_handler = logging.StreamHandler()
 console_handler.setLevel(logging.INFO) # Only show INFO and above on screen

 console_format = logging.Formatter(
 '%(levelname)-8s %(message)s'
 )
 console_handler.setFormatter(console_format)

 # Attach both handlers to our logger
 self.logger.addHandler(file_handler)
 self.logger.addHandler(console_handler)

 # Log the very first entry
 self.logger.info(f"Logger initialized. Session log: {self.log_file}")

 # ── Convenience methods ─────────────────────────────────────────
 # These are shortcuts so we can write logger.info() instead of
 # logger.logger.info() which would look weird.

 def debug(self, message: str):
 """Log detailed debug info (not shown on screen by default)"""
 self.logger.debug(message)

 def info(self, message: str):
 """Log normal operational info"""
 self.logger.info(message)

 def warning(self, message: str):
 """Log something unusual"""
 self.logger.warning(f" {message}")

 def error(self, message: str):
 """Log an error"""
 self.logger.error(f"{message}")

 def critical(self, message: str):
 """Log a critical failure"""
 self.logger.critical(f" {message}")

 def section(self, title: str):
 """
 Log a visual section divider.
 Makes the log file easier to read by separating sections.
 
 Example output:
 ════════════════════════════════
 MODULE: Network Scanner
 ════════════════════════════════
 """
 divider = "═" * 40
 self.logger.info(divider)
 self.logger.info(f" {title}")
 self.logger.info(divider)

 def get_log_file_path(self) -> str:
 """Returns the path to the current log file"""
 return self.log_file
