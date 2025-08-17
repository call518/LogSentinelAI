#!/usr/bin/env python3
"""
GeoIP Database Download Helper Script

This script downloads the MaxMind GeoLite2-Country database required for
GeoIP enrichment functionality in LogSentinelAI.

Requirements:
- Internet connection
- requests library (included in requirements.txt)

Usage:
    python download_geoip_database.py [--output-dir /path/to/directory]
"""

import os
import sys
import argparse
import gzip
import shutil
from pathlib import Path

# 로깅 설정 추가
from ..core.commons import setup_logger
logger = setup_logger("logsentinelai.utils.geoip_downloader")

try:
    import requests
except ImportError:
    print("❌ ERROR: requests library not found")
    print("💡 Please install dependencies: pip install -r requirements.txt")
    logger.error("requests library not found - missing dependency")
    sys.exit(1)


def download_geoip_database(output_dir: str = None) -> bool:
    """
    Download MaxMind GeoLite2-City database (only City, not Country)
    Args:
        output_dir: Directory to save the database file (default: ~/.logsentinelai)
    Returns:
        bool: True if successful, False otherwise
    """
    if output_dir is None:
        output_dir = os.path.expanduser('~/.logsentinelai')
    # GeoLite2-City database URLs (prioritize these two)
    database_urls = [
        "https://git.io/GeoLite2-City.mmdb",
        "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
        # fallback sources (if any) can be added here
    ]
    output_path = Path(output_dir)
    final_file = output_path / "GeoLite2-City.mmdb"
    print("=" * 60)
    print("GeoIP Database Download (City)")
    print("=" * 60)
    print(f"Output: {final_file}")
    print("-" * 60)
    
    try:
        # Create output directory if it doesn't exist
        output_path.mkdir(parents=True, exist_ok=True)
        # Check if database already exists
        if final_file.exists():
            response = input(f"Database already exists at {final_file}. Overwrite? (y/N): ")
            if response.lower() != 'y':
                print("❌ Download cancelled")
                return False
        # Try different sources
        for i, database_url in enumerate(database_urls, 1):
            print(f"📡 Trying source {i}/{len(database_urls)}: {database_url}")
            try:
                is_compressed = database_url.endswith('.gz')
                temp_file = output_path / ("temp_download.mmdb.gz" if is_compressed else "temp_download.mmdb")
                response = requests.get(database_url, stream=True, timeout=30)
                response.raise_for_status()
                total_size = int(response.headers.get('content-length', 0))
                downloaded_size = 0
                with open(temp_file, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_size += len(chunk)
                            if total_size > 0:
                                progress = (downloaded_size / total_size) * 100
                                print(f"\r📥 Progress: {progress:.1f}% ({downloaded_size:,} / {total_size:,} bytes)", end='')
                print(f"\n✅ Download completed from source {i}")
                if is_compressed:
                    print("📦 Extracting compressed database...")
                    with gzip.open(temp_file, 'rb') as f_in:
                        with open(final_file, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    temp_file.unlink()
                else:
                    temp_file.rename(final_file)
                break
            except requests.RequestException as e:
                print(f"\n❌ Source {i} failed: {e}")
                logger.error(f"GeoIP download source {i} failed: {e}")
                if temp_file.exists():
                    temp_file.unlink()
                if i == len(database_urls):
                    print("\n❌ All download sources failed")
                    logger.error("All GeoIP download sources failed")
                    return False
                print(f"🔄 Trying next source...")
                logger.warning(f"Trying next GeoIP download source after failure: {e}")
                continue
        # Verify final database file
        if not final_file.exists():
            print("❌ Database file was not created successfully")
            return False
        file_size = final_file.stat().st_size
        if file_size < 1000:
            print(f"❌ Downloaded file seems too small ({file_size} bytes)")
            final_file.unlink()
            return False
        print(f"📊 Database size: {file_size:,} bytes ({file_size / 1024 / 1024:.1f} MB)")
        print("=" * 60)
        print("✅ GeoIP database download completed successfully!")
        print("=" * 60)
        print(f"Database location: {final_file.absolute()}")
        print("💡 Make sure GEOIP_DATABASE_PATH in config points to this file")
        print("💡 Example config setting:")
        print(f"   GEOIP_DATABASE_PATH={final_file.absolute()}")
        print("=" * 60)
        return True
    except requests.RequestException as e:
        print(f"\n❌ Download failed: {e}")
        logger.error(f"GeoIP database download failed: {e}")
        return False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.exception(f"Unexpected error during GeoIP database download: {e}")
        return False


def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(
        description="Download MaxMind GeoLite2-City database for LogSentinelAI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python download_geoip_database.py
  python download_geoip_database.py --output-dir /etc/geoip
  python download_geoip_database.py --output-dir .

Note:
  The GeoLite2-City database is provided by MaxMind under Creative Commons
  Attribution-ShareAlike 4.0 International License. For production use,
  consider registering for a MaxMind account to get the most recent data.
        """
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default=os.path.expanduser('~/.logsentinelai'),
        help='Directory to save the database file (default: ~/.logsentinelai)'
    )
    args = parser.parse_args()
    success = download_geoip_database(args.output_dir)
    if success:
        sys.exit(0)
    else:
        print("\n❌ Database download failed")
        print("💡 You can also manually download from:")
        print("   https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        sys.exit(1)


if __name__ == "__main__":
    main()
