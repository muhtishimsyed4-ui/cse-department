"""
Configuration management for NetGuard application.
Loads environment variables and provides centralized config access.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration class."""
    
    # Flask Configuration
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-please-change')
    PORT = int(os.getenv('FLASK_PORT', 5001))
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Network Configuration
    NETWORK_INTERFACE = os.getenv('NETWORK_INTERFACE', 'eth0')
    SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', 300))  # 5 minutes default
    SECURITY_SCAN_ENABLED = os.getenv('SECURITY_SCAN_ENABLED', 'True').lower() == 'true'
    
    # SMTP Email Settings
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USERNAME = os.getenv('SMTP_USERNAME', 'taryareddy123@gmail.com')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'lonbbmlhcnohcemm')
    EMAIL_FROM = os.getenv('EMAIL_FROM', 'taryareddy123@gmail.com')
    EMAIL_TO = os.getenv('EMAIL_TO', 'akashreddy12390@gmail.com')
    SEND_NEW_DEVICE_ALERTS = os.getenv('SEND_NEW_DEVICE_ALERTS', 'True').lower() == 'true'
    SEND_HIGH_RISK_ALERTS = os.getenv('SEND_HIGH_RISK_ALERTS', 'True').lower() == 'true'
    
    # Database
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'netguard.db')
    
    @classmethod
    def validate(cls) -> bool:
        """
        Validate critical configuration values.
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        errors = []
        
        if cls.SECRET_KEY == 'dev-secret-key-please-change' and not cls.DEBUG:
            errors.append("FLASK_SECRET_KEY must be set in production")
        
        if cls.SEND_NEW_DEVICE_ALERTS or cls.SEND_HIGH_RISK_ALERTS:
            if not cls.SMTP_USERNAME or not cls.SMTP_PASSWORD:
                errors.append("SMTP credentials required for email alerts")
            if not cls.EMAIL_TO:
                errors.append("EMAIL_TO must be set to receive alerts")
        
        if errors:
            print("⚠️  Configuration Warnings:")
            for error in errors:
                print(f"   - {error}")
            return False
        
        return True
    
    @classmethod
    def display(cls):
        """Display current configuration (hide sensitive data)."""
        print("\n" + "="*50)
        print("NetGuard Configuration")
        print("="*50)
        print(f"Flask Port:           {cls.PORT}")
        print(f"Debug Mode:           {cls.DEBUG}")
        print(f"Network Interface:    {cls.NETWORK_INTERFACE}")
        print(f"Scan Interval:        {cls.SCAN_INTERVAL}s")
        print(f"Security Scan:        {cls.SECURITY_SCAN_ENABLED}")
        print(f"Database:             {cls.DATABASE_PATH}")
        print(f"Email Alerts:         {cls.SEND_NEW_DEVICE_ALERTS or cls.SEND_HIGH_RISK_ALERTS}")
        if cls.SMTP_USERNAME:
            print(f"SMTP User:            {cls.SMTP_USERNAME}")
        print("="*50 + "\n")
