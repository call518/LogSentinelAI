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

class GeoIPLookup:
    """GeoIP lookup utility for enriching IP addresses with country information"""
    
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
            print(f"✓ GeoIP database loaded: {self.database_path}")
            
        except Exception as e:
            print(f"WARNING: Failed to initialize GeoIP database: {e}")
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
    
    def lookup_country(self, ip_str: str) -> Dict[str, str]:
        """
        Lookup country information for an IP address
        
        Args:
            ip_str: IP address string
        
        Returns:
            Dict with country information: {"country_code": "US", "country_name": "United States"}
        """
        if not self.enabled:
            return {"country_code": "N/A", "country_name": "GeoIP Disabled"}
        
        # Validate IP format
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            return {"country_code": "INVALID", "country_name": "Invalid IP"}
        
        # Check for private IPs
        if self._is_private_ip(ip_str) and not self.include_private_ips:
            return {"country_code": "PRIVATE", "country_name": "Private IP"}
        
        # Check cache first
        if ip_str in self._cache:
            self._cache_order.remove(ip_str)
            self._cache_order.append(ip_str)
            return self._cache[ip_str]
        
        # Lookup in database
        try:
            response = self._reader.country(ip_str)
            country_info = {
                "country_code": response.country.iso_code or "UNKNOWN",
                "country_name": response.country.name or self.fallback_country
            }
            
            self._manage_cache(ip_str)
            self._cache[ip_str] = country_info
            return country_info
            
        except geoip2.errors.AddressNotFoundError:
            country_info = {"country_code": "UNKNOWN", "country_name": self.fallback_country}
            self._manage_cache(ip_str)
            self._cache[ip_str] = country_info
            return country_info
            
        except Exception as e:
            print(f"WARNING: GeoIP lookup failed for {ip_str}: {e}")
            return {"country_code": "ERROR", "country_name": "Lookup Failed"}
    
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
    
    def enrich_ip_text(ip_str):
        """Convert IP string to enriched format"""
        if not isinstance(ip_str, str):
            return ip_str
        
        try:
            country_info = geoip.lookup_country(ip_str)
            if country_info["country_code"] in ["N/A", "ERROR", "INVALID"]:
                return ip_str
            elif country_info["country_code"] == "PRIVATE":
                return f"{ip_str} (Private)"
            elif country_info["country_code"] == "UNKNOWN":
                return f"{ip_str} (Unknown)"
            else:
                return f"{ip_str} ({country_info['country_code']} - {country_info['country_name']})"
        except Exception:
            return ip_str
    
    # Deep copy to avoid modifying original data
    enriched_data = analysis_data.copy()
    
    # Process events array
    if "events" in enriched_data and isinstance(enriched_data["events"], list):
        for event in enriched_data["events"]:
            if isinstance(event, dict):
                # Handle source_ips arrays
                if "source_ips" in event and isinstance(event["source_ips"], list):
                    enriched_ips = []
                    for ip_item in event["source_ips"]:
                        if isinstance(ip_item, str):
                            enriched_ips.append(enrich_ip_text(ip_item))
                        elif isinstance(ip_item, dict) and "ip" in ip_item:
                            enriched_ips.append(enrich_ip_text(ip_item["ip"]))
                        else:
                            enriched_ips.append(ip_item)
                    event["source_ips"] = enriched_ips
                
                # Handle individual IP fields (TCPDUMP)
                if "source_ip" in event:
                    event["source_ip"] = enrich_ip_text(event["source_ip"])
                if "dest_ip" in event:
                    event["dest_ip"] = enrich_ip_text(event["dest_ip"])
    
    # Process statistics
    if "statistics" in enriched_data and isinstance(enriched_data["statistics"], dict):
        stats = enriched_data["statistics"]
        
        # Enrich top_source_ips
        if "top_source_ips" in stats and isinstance(stats["top_source_ips"], dict):
            enriched_top_ips = {}
            for ip, count in stats["top_source_ips"].items():
                enriched_key = enrich_ip_text(ip)
                enriched_top_ips[enriched_key] = count
            stats["top_source_ips"] = enriched_top_ips
        
        # Handle TCPDUMP-specific statistics
        for field in ["top_source_addresses", "top_destination_addresses"]:
            if field in stats and isinstance(stats[field], dict):
                enriched_field = {}
                for ip, count in stats[field].items():
                    enriched_key = enrich_ip_text(ip)
                    enriched_field[enriched_key] = count
                stats[field] = enriched_field
    
    return enriched_data
