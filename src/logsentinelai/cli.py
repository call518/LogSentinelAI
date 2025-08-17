#!/usr/bin/env python3
"""
LogSentinelAI Command Line Interface

Main entry point for the LogSentinelAI package.
"""


import sys
import argparse
from typing import Optional

# Logging setup
from logsentinelai.core.commons import setup_logger

logger = setup_logger("logsentinelai.cli")

def main() -> None:
    """Main CLI entry point"""
    logger.info("LogSentinelAI CLI started.")
    epilog_text = (
        """
Examples:
  # HTTP Access Log Analysis
  logsentinelai-httpd-access --log-path /var/log/apache2/access.log

  # Linux System Log Analysis  
  logsentinelai-linux-system --mode realtime

  # Download GeoIP Database
  logsentinelai-geoip-download

  # Lookup IP Geolocation (single IP)
  logsentinelai-geoip-lookup 8.8.8.8
  # or via unified CLI
  logsentinelai geoip-lookup 8.8.8.8

Available Commands:
  logsentinelai-httpd-access   - Analyze HTTP access logs
  logsentinelai-httpd-server   - Analyze HTTP server error logs
  logsentinelai-linux-system   - Analyze Linux system logs
  logsentinelai-general-log    - Analyze any general log files
  logsentinelai-geoip-download - Download GeoIP database
  logsentinelai-geoip-lookup   - Lookup IP geolocation using configured GeoIP database

For detailed help on each command, use: <command> --help
        """
    )
    parser = argparse.ArgumentParser(
        prog="logsentinelai",
        description="AI-Powered Log Analyzer - Leverages LLM to analyze log files and detect security events",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog_text
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version="LogSentinelAI v0.1.0"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available analysis commands",
        metavar="COMMAND"
    )
    
    # HTTP Access Log Analysis
    httpd_access_parser = subparsers.add_parser(
        "httpd-access",
        help="Analyze HTTP access logs"
    )
    httpd_access_parser.add_argument(
        "--log-path",
        help="Path to log file"
    )
    httpd_access_parser.add_argument(
        "--mode",
        choices=["batch", "realtime"],
        default="batch",
        help="Analysis mode (default: batch)"
    )
    
    # Linux System Log Analysis
    linux_parser = subparsers.add_parser(
        "linux-system", 
        help="Analyze Linux system logs"
    )
    linux_parser.add_argument(
        "--log-path",
        help="Path to log file"
    )
    linux_parser.add_argument(
        "--mode",
        choices=["batch", "realtime"],
        default="batch",
        help="Analysis mode (default: batch)"
    )
    
    # General Log Analysis
    general_parser = subparsers.add_parser(
        "general-log", 
        help="Analyze any general log files"
    )
    general_parser.add_argument(
        "--log-path",
        help="Path to log file"
    )
    general_parser.add_argument(
        "--mode",
        choices=["batch", "realtime"],
        default="batch",
        help="Analysis mode (default: batch)"
    )
    
    # TCP Dump Analysis
    # REMOVED: TCP Dump analysis functionality has been removed
    
    # GeoIP Database Download
    geoip_parser = subparsers.add_parser(
        "geoip-download",
        help="Download GeoIP database"
    )

    # GeoIP Lookup
    geoip_lookup_parser = subparsers.add_parser(
        "geoip-lookup",
        help="Lookup IP geolocation using configured GeoIP database"
    )
    geoip_lookup_parser.add_argument(
        "ip",
        help="IP address to lookup"
    )
    
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        logger.warning("No command provided. Showing help.")
        return

    logger.info(f"Command selected: {args.command}")

    # Route to appropriate analyzer
    if args.command == "httpd-access":
        logger.debug("Routing to httpd_access analyzer.")
        from .analyzers.httpd_access import main as httpd_access_main
        sys.argv = ["logsentinelai-httpd-access"]
        if hasattr(args, 'log_path') and args.log_path:
            sys.argv.extend(["--log-path", args.log_path])
        if hasattr(args, 'mode') and args.mode:
            sys.argv.extend(["--mode", args.mode])
        httpd_access_main()
        logger.info("httpd_access analysis completed.")

    elif args.command == "linux-system":
        logger.debug("Routing to linux_system analyzer.")
        from .analyzers.linux_system import main as linux_system_main
        sys.argv = ["logsentinelai-linux-system"]
        if hasattr(args, 'log_path') and args.log_path:
            sys.argv.extend(["--log-path", args.log_path])
        if hasattr(args, 'mode') and args.mode:
            sys.argv.extend(["--mode", args.mode])
        linux_system_main()
        logger.info("linux_system analysis completed.")

    elif args.command == "general-log":
        logger.debug("Routing to general_log analyzer.")
        from .analyzers.general_log import main as general_log_main
        sys.argv = ["logsentinelai-general-log"]
        if hasattr(args, 'log_path') and args.log_path:
            sys.argv.extend(["--log-path", args.log_path])
        if hasattr(args, 'mode') and args.mode:
            sys.argv.extend(["--mode", args.mode])
        general_log_main()
        logger.info("general_log analysis completed.")

    elif args.command == "geoip-download":
        logger.debug("Routing to geoip_downloader.")
        from .utils.geoip_downloader import main as geoip_main
        geoip_main()
        logger.info("GeoIP database download completed.")
    elif args.command == "geoip-lookup":
        logger.debug("Routing to geoip_lookup.")
        from .utils.geoip_lookup import main as geoip_lookup_main
        sys.argv = ["geoip-lookup", args.ip]
        geoip_lookup_main()
        logger.info(f"GeoIP lookup completed for IP: {args.ip}")

if __name__ == "__main__":
    main()
