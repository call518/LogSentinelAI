#!/usr/bin/env python3
"""
LogSentinelAI Command Line Interface

Main entry point for the LogSentinelAI package.
"""

import sys
import argparse
from typing import Optional

def main() -> None:
    """Main CLI entry point"""
    epilog_text = (
        """
Examples:
  # HTTP Access Log Analysis
  logsentinelai-httpd-access --log-path /var/log/apache2/access.log

  # Linux System Log Analysis  
  logsentinelai-linux-system --mode realtime

  # TCP Dump Analysis with SSH
  logsentinelai-tcpdump --remote --ssh admin@server.com --ssh-key ~/.ssh/id_rsa

  # Download GeoIP Database
  logsentinelai-geoip-download

  # Lookup IP Geolocation (single IP)
  logsentinelai-geoip-lookup 8.8.8.8
  # or via unified CLI
  logsentinelai geoip-lookup 8.8.8.8

Available Commands:
  logsentinelai-httpd-access   - Analyze HTTP access logs
  logsentinelai-httpd-apache   - Analyze Apache error logs
  logsentinelai-linux-system   - Analyze Linux system logs
  logsentinelai-tcpdump        - Analyze TCP dump packets
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
    
    # TCP Dump Analysis
    tcpdump_parser = subparsers.add_parser(
        "tcpdump",
        help="Analyze TCP dump packets"
    )
    tcpdump_parser.add_argument(
        "--log-path",
        help="Path to log file"
    )
    tcpdump_parser.add_argument(
        "--mode",
        choices=["batch", "realtime"],
        default="batch",
        help="Analysis mode (default: batch)"
    )
    
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
        return
    
    # Route to appropriate analyzer
    if args.command == "httpd-access":
        from .analyzers.httpd_access import main as httpd_access_main
        # Convert args to sys.argv format expected by analyzer
        sys.argv = ["logsentinelai-httpd-access"]
        if hasattr(args, 'log_path') and args.log_path:
            sys.argv.extend(["--log-path", args.log_path])
        if hasattr(args, 'mode') and args.mode:
            sys.argv.extend(["--mode", args.mode])
        httpd_access_main()
    
    elif args.command == "linux-system":
        from .analyzers.linux_system import main as linux_system_main
        sys.argv = ["logsentinelai-linux-system"]
        if hasattr(args, 'log_path') and args.log_path:
            sys.argv.extend(["--log-path", args.log_path])
        if hasattr(args, 'mode') and args.mode:
            sys.argv.extend(["--mode", args.mode])
        linux_system_main()
    
    elif args.command == "tcpdump":
        from .analyzers.tcpdump_packet import main as tcpdump_main
        sys.argv = ["logsentinelai-tcpdump"]
        if hasattr(args, 'log_path') and args.log_path:
            sys.argv.extend(["--log-path", args.log_path])
        if hasattr(args, 'mode') and args.mode:
            sys.argv.extend(["--mode", args.mode])
        tcpdump_main()
    
    elif args.command == "geoip-download":
        from .utils.geoip_downloader import main as geoip_main
        geoip_main()
    elif args.command == "geoip-lookup":
        from .utils.geoip_lookup import main as geoip_lookup_main
        sys.argv = ["geoip-lookup", args.ip]
        geoip_lookup_main()

if __name__ == "__main__":
    main()
