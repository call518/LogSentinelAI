"""
GeoIP lookup and enrichment module
Provides IP geolocation functionality for log analysis
"""
import os
import ipaddress
from typing import Dict, Any, Optional

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

from .config import GEOIP_CONFIG
from .commons import setup_logger

logger = setup_logger("logsentinelai.core.geoip")

class GeoIPLookup:
    """GeoIP lookup utility for enriching IP addresses with city and geo_point information"""
    
    def __init__(self):
        """Initialize GeoIP lookup with MaxMind database"""
        self.enabled = GEOIP_CONFIG["enabled"] and GEOIP_AVAILABLE
        self.database_path = os.path.expanduser(GEOIP_CONFIG["database_path"])
        self.fallback_country = GEOIP_CONFIG["fallback_country"]
        self.include_private_ips = GEOIP_CONFIG["include_private_ips"]
        self.cache_size = GEOIP_CONFIG["cache_size"]
        
        self._cache = {}
        self._cache_order = []
        self._reader = None
        
        if self.enabled:
            self._initialize_database()
    
    def _initialize_database(self):
        """Initialize GeoIP database reader"""
        try:
            if not os.path.exists(self.database_path):
                print(f"⚠️  GeoIP database not found at {self.database_path}")
                if self._auto_download_database():
                    print("✅ GeoIP database downloaded successfully!")
                else:
                    print("❌ Failed to download GeoIP database automatically")
                    print("💡 You can manually download using: logsentinelai-geoip-download")
                    self.enabled = False
                    return
            
            self._reader = geoip2.database.Reader(self.database_path)
            print()
            print(f"💡 GeoIP database loaded: {self.database_path}")
            
        except Exception as e:
            print(f"WARNING: Failed to initialize GeoIP database: {e}")
            logger.error(f"Failed to initialize GeoIP database: {e}")
            self.enabled = False
    
    def _auto_download_database(self) -> bool:
        """Automatically download GeoIP database"""
        try:
            from ..utils.geoip_downloader import download_geoip_database
            os.makedirs(os.path.dirname(self.database_path), exist_ok=True)
            output_dir = os.path.dirname(self.database_path)
            return download_geoip_database(output_dir)
        except (ImportError, Exception) as e:
            print(f"WARNING: Auto-download failed: {e}")
            logger.error(f"GeoIP database auto-download failed: {e}")
            return False
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP address is private/internal"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False
    
    def _manage_cache(self, ip: str):
        """Manage cache size using LRU eviction"""
        if len(self._cache) >= self.cache_size:
            oldest_ip = self._cache_order.pop(0)
            del self._cache[oldest_ip]
        
        if ip in self._cache_order:
            self._cache_order.remove(ip)
        self._cache_order.append(ip)
    
    def lookup_city(self, ip_str: str) -> Dict[str, Any]:
        """
        Lookup city and geo_point information for an IP address
        Args:
            ip_str: IP address string
        Returns:
            Dict with city, country, region, and geo_point (lat/lon) information
        """
        if not self.enabled:
            return {"ip": ip_str, "country_code": "N/A", "country_name": "GeoIP Disabled"}
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            return {"ip": ip_str, "country_code": "INVALID", "country_name": "Invalid IP"}
        if self._is_private_ip(ip_str) and not self.include_private_ips:
            return {"ip": ip_str, "country_code": "PRIVATE", "country_name": "Private IP"}
        if ip_str in self._cache:
            self._cache_order.remove(ip_str)
            self._cache_order.append(ip_str)
            return self._cache[ip_str]
        try:
            response = self._reader.city(ip_str)
            city_info = {
                "ip": ip_str,
                "country_code": response.country.iso_code or "UNKNOWN",
                "country_name": response.country.name or self.fallback_country,
                "city": response.city.name or None,
                "region": response.subdivisions.most_specific.name or None,
                "region_code": response.subdivisions.most_specific.iso_code or None,
                "location": {
                    "lat": response.location.latitude,
                    "lon": response.location.longitude
                } if response.location.latitude is not None and response.location.longitude is not None else None
            }
            self._manage_cache(ip_str)
            self._cache[ip_str] = city_info
            return city_info
        except geoip2.errors.AddressNotFoundError:
            city_info = {"ip": ip_str, "country_code": "UNKNOWN", "country_name": self.fallback_country}
            self._manage_cache(ip_str)
            self._cache[ip_str] = city_info
            return city_info
        except Exception as e:
            print(f"WARNING: GeoIP lookup failed for {ip_str}: {e}")
            logger.error(f"GeoIP lookup failed for {ip_str}: {e}")
            return {"ip": ip_str, "country_code": "ERROR", "country_name": "Lookup Failed"}
    
    def close(self):
        """Close GeoIP database reader"""
        if self._reader:
            self._reader.close()
            self._reader = None

# Global GeoIP lookup instance
_geoip_lookup = None

def get_geoip_lookup() -> GeoIPLookup:
    """Get or create global GeoIP lookup instance"""
    global _geoip_lookup
    if _geoip_lookup is None:
        _geoip_lookup = GeoIPLookup()
    return _geoip_lookup

def enrich_source_ips_with_geoip(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich source_ips in analysis data with GeoIP country information
    
    Args:
        analysis_data: Analysis result data containing events with source_ips or source_ip/dest_ip
    
    Returns:
        Dict[str, Any]: Analysis data with enriched source_ips as text strings
    """
    if not GEOIP_CONFIG["enabled"] or not GEOIP_AVAILABLE:
        return analysis_data
    
    geoip = get_geoip_lookup()
    if not geoip.enabled:
        return analysis_data
    
    def enrich_ip_geo(ip_str):
        """Convert IP string to enriched geo dict for Kibana geo_point. Only valid IPs will be mapped as {ip: ...}."""
        if not isinstance(ip_str, str):
            return ip_str
        try:
            # Only enrich if valid IPv4/IPv6 string
            ipaddress.ip_address(ip_str)
        except Exception:
            # Not a valid IP, return None (will be filtered out in ES mapping)
            return None
        try:
            city_info = geoip.lookup_city(ip_str)
            if city_info.get("country_code") in ["N/A", "ERROR", "INVALID"]:
                return None
            elif city_info.get("country_code") == "PRIVATE":
                return None
            elif city_info.get("country_code") == "UNKNOWN":
                return None
            return city_info
        except Exception:
            return None
    
    # Deep copy to avoid modifying original data
    enriched_data = analysis_data.copy()
    # Fields to enrich in events and statistics
    ip_list_fields = ["source_ips", "dest_ips"]
    ip_dict_fields = ["top_source_ips", "top_dest_ips", "top_event_ips"]
    # Process events array
    if "events" in enriched_data and isinstance(enriched_data["events"], list):
        for event in enriched_data["events"]:
            if isinstance(event, dict):
                # Enrich all relevant IP fields in event
                for field in ip_list_fields:
                    if field in event:
                        if isinstance(event[field], list):
                            enriched_ips = []
                            for ip_item in event[field]:
                                if isinstance(ip_item, str):
                                    enriched = enrich_ip_geo(ip_item)
                                    if enriched:
                                        enriched_ips.append(enriched)
                                elif isinstance(ip_item, dict) and "ip" in ip_item:
                                    enriched = enrich_ip_geo(ip_item["ip"])
                                    if enriched:
                                        enriched_ips.append(enriched)
                            event[field] = enriched_ips
                        elif isinstance(event[field], str):
                            enriched = enrich_ip_geo(event[field])
                            if enriched:
                                event[field] = enriched
                            else:
                                event[field] = None
                # Also handle any other direct IP fields (future-proof)
                for key, value in event.items():
                    if key.endswith("_ip") and isinstance(value, str):
                        enriched = enrich_ip_geo(value)
                        if enriched:
                            event[key] = enriched
                        else:
                            event[key] = None
    # Process statistics
    if "statistics" in enriched_data and isinstance(enriched_data["statistics"], dict):
        stats = enriched_data["statistics"]
        for field in ip_dict_fields:
            if field in stats and isinstance(stats[field], dict):
                enriched_field = {}
                for ip, count in stats[field].items():
                    enriched_key = enrich_ip_geo(ip)
                    if enriched_key:
                        enriched_field[str(enriched_key)] = count
                stats[field] = enriched_field
    return enriched_data
