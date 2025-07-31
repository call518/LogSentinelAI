"""
NOTE: This script prints IP geolocation info to stdout for user query only.
It does NOT log or persist sensitive data to any file or system log.
"""
import sys
import json
from logsentinelai.core.geoip import get_geoip_lookup

def main():
    if len(sys.argv) != 2:
        print("Usage: logsentinelai geoip-lookup <ip>")
        sys.exit(1)
    ip = sys.argv[1]
    geoip = get_geoip_lookup()
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

if __name__ == "__main__":
    main()
