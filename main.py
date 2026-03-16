#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           DAYEA - Professional Penetration Testing      ║
║                    Framework v1.0                            ║
║                                                              ║
║   FOR AUTHORIZED USE ONLY                              ║
║  Only run this against systems you OWN or have WRITTEN       ║
║  permission to test. Unauthorized use is illegal.            ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import os
from datetime import datetime
from core.authorization import AuthorizationGate
from core.logger import ToolkitLogger
from core.config_loader import ConfigLoader
from core.menu import MainMenu


def startup_banner():
    """
    This just prints the welcome screen when the tool starts.
    Like the splash screen on a video game.
    """
    print("""

    ██████╗  █████╗ ██╗   ██╗███████╗ █████╗ 
    ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗
    ██║  ██║███████║ ╚████╔╝ █████╗  ███████║
    ██║  ██║██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██║
    ██████╔╝██║  ██║   ██║   ███████╗██║  ██║
    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    
        Professional Security Testing Framework
    ─────────────────────────────────────────────
    Open Source Security Platform
    Professional Security Testing Framework
    
    Started: {time}
    
     LEGAL REMINDER: Only test systems you are AUTHORIZED to test ⚠️
    """.format(time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))


def main():
    """
    This is the STARTING POINT of the entire program.
    Think of it like the ignition key — everything starts here.
    
    The steps are:
    1. Show the welcome screen
    2. Check that the user has permission to run tests (Authorization Gate)
    3. Load the settings/config
    4. Start the main menu
    """

    # Step 1: Show the banner
    startup_banner()

    # Step 2: Initialize the logger first
    # The logger is like a security camera — it records EVERYTHING the tool does
    logger = ToolkitLogger()
    logger.info("Dayea started")

    # Step 3: Authorization Gate
    # This is the bouncer at the door. You MUST prove you have permission before anything runs.
    auth = AuthorizationGate(logger)
    if not auth.verify():
        print("\nAuthorization not confirmed. Exiting for safety.")
        print("   You must have written permission to test a target system.")
        logger.warning("Authorization denied - tool exited")
        sys.exit(1)

    # Step 4: Load config
    # Config is like the settings menu — it tells the tool how to behave
    config = ConfigLoader(logger)
    settings = config.load()

    if not settings:
        print("\nCould not load configuration. Please check config/settings.yaml")
        sys.exit(1)

    # Step 5: Launch the main menu
    # This is the dashboard — the user picks what they want to do
    logger.info(f"Authorized user session started. Target scope: {settings.get('scope', 'undefined')}")
    menu = MainMenu(settings, logger)
    menu.run()


if __name__ == "__main__":
    main()
