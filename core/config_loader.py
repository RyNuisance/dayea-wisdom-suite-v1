"""
config_loader.py — The Settings Panel

This reads the settings file (config/settings.yaml) and loads
all the preferences for how the tool should behave.

Think of it like the Settings app on your phone — you set your 
preferences once, and every app respects them.

YAML is a simple settings file format. It looks like:
    scan_speed: normal
    timeout: 30
    output_folder: reports/
"""

import os
import json


class ConfigLoader:
    """
    Reads and validates the toolkit's configuration.
    
    We use JSON instead of YAML to keep things simple and avoid
    needing to install extra libraries.
    """

    # These are the REQUIRED settings — the tool can't run without them
    REQUIRED_FIELDS = ['scope', 'output_dir', 'scan_timeout']

    # These are DEFAULT values used if the user doesn't set them
    DEFAULTS = {
        'scan_speed': 'normal',       # How fast to scan (slow/normal/fast)
        'scan_timeout': 30,            # How long to wait for responses (seconds)
        'output_dir': 'reports',       # Where to save reports
        'max_threads': 10,             # How many scans to run at once
        'verbose': False,              # Show extra detail? True/False
        'web_test_depth': 2,           # How deep to crawl websites
        'port_range': '1-1024',        # Which ports to scan
        'scope': []                    # Authorized targets (set during auth)
    }

    def __init__(self, logger):
        self.logger = logger
        self.config_file = "config/settings.json"

    def load(self) -> dict:
        """
        Load settings from file, or create a default settings file
        if one doesn't exist yet.
        
        Returns:
            dict: All settings as a dictionary
                  (a dictionary is like a list of label:value pairs)
        """
        self.logger.info("Loading configuration...")

        # If no config file exists yet, create one with defaults
        if not os.path.exists(self.config_file):
            self.logger.warning(f"No config file found at {self.config_file}")
            self.logger.info("Creating default configuration file...")
            self._create_default_config()

        # Load the config file
        try:
            with open(self.config_file, 'r') as f:
                user_settings = json.load(f)

            # Merge user settings with defaults
            # (if user didn't set something, use the default value)
            settings = {**self.DEFAULTS, **user_settings}

            self.logger.info(f"Configuration loaded successfully")
            self.logger.debug(f"Settings: {settings}")
            return settings

        except json.JSONDecodeError as e:
            # The file exists but has a formatting error
            self.logger.error(f"Config file has a formatting error: {e}")
            self.logger.info("Falling back to default settings")
            return self.DEFAULTS

        except Exception as e:
            self.logger.error(f"Unexpected error loading config: {e}")
            return None

    def _create_default_config(self):
        """
        Create a default config file so the user has a template to edit.
        """
        os.makedirs("config", exist_ok=True)

        default_config = {
            "_comment": "Dayea Wisdom Suite Configuration File - Edit these settings to customize the tool",
            "scope": [],
            "scan_speed": "normal",
            "scan_timeout": 30,
            "output_dir": "reports",
            "max_threads": 10,
            "verbose": False,
            "web_test_depth": 2,
            "port_range": "1-1024"
        }

        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=4)

        self.logger.info(f"Default config created at: {self.config_file}")

    def update_scope(self, scope_list: list):
        """
        Update the scope in the config file after authorization.
        
        This is called by the Authorization Gate after the user
        defines their authorized targets.
        
        Args:
            scope_list: List of authorized IP addresses or domains
        """
        try:
            # Load current config
            with open(self.config_file, 'r') as f:
                settings = json.load(f)

            # Update scope
            settings['scope'] = scope_list

            # Save back to file
            with open(self.config_file, 'w') as f:
                json.dump(settings, f, indent=4)

            self.logger.info(f"Scope updated in config: {scope_list}")

        except Exception as e:
            self.logger.error(f"Could not update scope in config: {e}")
