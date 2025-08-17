"""
NOTE: This script prints IP geolocation info to stdout for user query only.
It does NOT log or persist sensitive data to any file or system log.
"""
import sys
import json
from logsentinelai.core.geoip import get_geoip_lookup
from logsentinelai.core.commons import setup_logger

logger = setup_logger("logsentinelai.utils.geoip_lookup")

def main():
    if len(sys.argv) != 2:
        print("Usage: logsentinelai geoip-lookup <ip>")
        logger.error("Invalid arguments for GeoIP lookup - IP address required")
        sys.exit(1)
    
    ip = sys.argv[1]
    
    try:
        geoip = get_geoip_lookup()
        if not geoip:
            print(f"❌ ERROR: GeoIP service not available")
            logger.error("GeoIP service not available for lookup")
            sys.exit(1)
            
        result = geoip.lookup_city(ip)
        output = {
            "ip": ip,
            "country_code": result.get("country_code"),
            "country_name": result.get("country_name"),
            "city": result.get("city"),
            "region": result.get("region"),
            "region_code": result.get("region_code"),
            "lat": None,
            "lon": None,
        }
        # If location is present, extract lat/lon
        if isinstance(result.get("location"), dict):
            output["lat"] = result["location"].get("lat")
            output["lon"] = result["location"].get("lon")
        print(json.dumps(output, ensure_ascii=False, indent=4))
        logger.info(f"GeoIP lookup completed for IP: {ip}")
        
    except Exception as e:
        print(f"❌ ERROR: GeoIP lookup failed: {e}")
        logger.exception(f"GeoIP lookup failed for IP {ip}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
