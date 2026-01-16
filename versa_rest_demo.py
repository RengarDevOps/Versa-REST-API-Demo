#!/usr/bin/env python3
"""
Versa Director REST API Demo - Standalone GUI Application
==========================================================
A standalone GUI application for testing Versa Director REST APIs.

Author: Rengaramalingam A
Email:  rengahcl@gmail.com, rengaramalingam.a@versa-networks.com

DISCLAIMER:
-----------
This script is provided "AS IS" without warranty of any kind, express or implied.
Use at your own risk. The author and Versa Networks are not responsible for any
damage, data loss, or issues arising from the use of this script. Always test
in a non-production environment first.

Features:
---------
- Real-time logging with syntax-highlighted output
- Input fields for credentials and parameters
- CURL command generation for each API call
- Threading to prevent GUI freezing

API Categories & Endpoints:
---------------------------
VERSA DIRECTOR API (13 endpoints):
  - Director Package Info     : GET /api/operational/system/package-info
  - Appliances Detail         : GET /vnms/appliance/appliance/lite
  - List Templates            : GET /vnms/sdwan/workflow/templates
  - Export Template           : GET /vnms/template/export
  - VD HA Details             : POST /api/config/vnmsha/actions/_operations/get-vnmsha-details
  - Get Audit Logs            : GET /vnms/audit/logs
  - List All Tasks            : GET /vnms/tasks
  - Get Task Details          : GET /vnms/tasks/task/{task_number}
  - Initiate VD Backup        : POST /api/config/system/recovery/backup/_operations
  - VD System Details         : GET /vnms/dashboard/vdStatus/sysDetails
  - Appliances List (TSV)     : GET /vnms/appliance/appliance/lite (formatted)
  - Get Organizations         : GET /nextgen/organization
  - System Uptime             : GET /vnms/system/uptime

VOS API (7 endpoints):
  - Device Config             : GET /vnms/appliance/export
  - Interfaces Brief          : GET /api/operational/devices/device/{device}/live-status/interfaces/brief
  - List Snapshots            : GET /api/operational/devices/device/{device}/live-status/system/snapshots
  - Alarm Statistics          : GET /api/operational/devices/device/{device}/live-status/alarms/statistics/detail
  - List Images               : POST /api/config/devices/device/{device}/config/system/package/list/_operations
  - BGP Status                : GET /api/operational/devices/device/{device}/live-status/bgp/neighbors/brief
  - Reboot Device             : POST /api/config/devices/device/{device}/config/system/_operations/reboot

SECURITY PACKAGE - SPACK (4 endpoints):
  - Fetch SPACK List          : GET /vnms/spack/checkavailableupdates
  - Download SPACK            : POST /vnms/spack/download
  - Upgrade SPACK             : POST /vnms/spack/schedule/updateAppliance
  - List SPACK                : GET /nextgen/spack/downloads

OS SECURITY PACKAGE - OSSPACK (5 endpoints):
  - Fetch OSSPACK List        : GET /vnms/osspack/device/check-osspack-updates
  - Download OSSPACK          : POST /vnms/osspack/download
  - Upgrade OSSPACK           : POST /vnms/osspack/schedule/updateAppliance
  - List Director OSSPACK     : GET /vnms/osspack/director/all-downloads
  - List Device OSSPACK       : GET /vnms/osspack/device/all-downloads

Usage:
------
    python VD_REST_API_Demo_Standalaone.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import requests
import json
import urllib.parse
import threading
import os
from requests.auth import HTTPBasicAuth
from typing import Tuple, Optional
from datetime import datetime

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()


class VDApiDemo:
    """Class to handle Versa Director REST API demonstration calls"""
    
    def __init__(self, director_ip: str, username: str, password: str, 
                 template_name: str = "BRANCH", device_name: str = "BRANCH1", 
                 appliance_name: str = "BRANCH1", version: str = "2064",
                 os_version: str = "bionic", osspack_version: str = "20251006",
                 product: str = "versa-flexvnf",
                 task_number: str = "", hide_password: bool = False, 
                 log_callback=None, task_number_callback=None):
        """
        Initialize VD API Demo
        
        Args:
            director_ip: Director IP address
            username: API username
            password: API password
            template_name: Template name for template operations
            device_name: Device name for device operations
            appliance_name: Appliance name for appliance operations
            version: Security package version to download
            os_version: OS version for OSSPACK
            osspack_version: OSSPACK version
            product: Product name for OSSPACK
            task_number: Task number for task operations
            hide_password: Hide password in CURL commands if True
            log_callback: Function to call for logging (optional)
            task_number_callback: Function to call when task number is updated (optional)
        """
        self.director_ip = director_ip
        self.username = username
        self.password = password
        self.template_name = template_name
        self.device_name = device_name
        self.appliance_name = appliance_name
        self.version = version
        self.os_version = os_version
        self.osspack_version = osspack_version
        self.product = product
        self.task_number = task_number
        self.hide_password = hide_password
        self.log_callback = log_callback
        self.task_number_callback = task_number_callback
        self.encoded_password = urllib.parse.quote(password, safe='')
        self.base_url = f"https://{director_ip}:9182"
    
    def log(self, message: str):
        """Log message using callback or print"""
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)
    
    def get_first_device(self) -> str:
        """Get the first device from comma-separated device list"""
        device_list = [d.strip() for d in self.device_name.split(',') if d.strip()]
        return device_list[0] if device_list else self.device_name
    
    def format_curl_command(self, method: str, url: str, headers: dict = None, data: dict = None) -> str:
        """Format a curl command for easy copy/paste"""
        curl_parts = [f"curl -k"]
        
        if method.upper() != "GET":
            curl_parts.append(f"-X {method.upper()}")
        
        if data:
            json_data = json.dumps(data)
            curl_parts.append(f"-d '{json_data}'")
        
        curl_parts.append(f"'{url}'")
        
        if headers:
            for key, value in headers.items():
                curl_parts.append(f"-H '{key}: {value}'")
        
        # Mask password in CURL command if hide_password is enabled
        if self.hide_password:
            curl_parts.append(f"-u '{self.username}:********'")
        else:
            curl_parts.append(f"-u '{self.username}:{self.password}'")
        
        return " ".join(curl_parts)
    
    def make_api_call(self, 
                      method: str, 
                      endpoint: str, 
                      description: str,
                      headers: dict = None,
                      data: dict = None) -> Tuple[bool, str, int]:
        """Make a REST API call and log results"""
        default_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        if headers:
            default_headers.update(headers)
        headers = default_headers
        
        url = f"https://{self.director_ip}:9182{endpoint}"
        
        # Log the API call
        self.log("="*80)
        self.log(f"📡 VD API Demo: {description}")
        self.log("="*80)
        self.log(f"Method: {method.upper()}")
        self.log(f"Endpoint: {endpoint}")
        self.log(f"URL: {url}")
        
        curl_cmd = self.format_curl_command(method, url, headers, data)
        self.log(f"\n📋 Equivalent CURL Command:")
        self.log(curl_cmd)
        
        try:
            if method.upper() == "GET":
                response = requests.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=headers,
                    verify=False,
                    timeout=30
                )
            elif method.upper() == "POST":
                response = requests.post(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=headers,
                    json=data,
                    verify=False,
                    timeout=30
                )
            elif method.upper() == "PUT":
                response = requests.put(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=headers,
                    json=data,
                    verify=False,
                    timeout=30
                )
            elif method.upper() == "DELETE":
                response = requests.delete(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=headers,
                    verify=False,
                    timeout=30
                )
            else:
                self.log(f"\n❌ Unsupported HTTP method: {method}")
                return False, "Unsupported method", 0
            
            # Log response
            self.log(f"\n📥 Response:")
            self.log(f"Status Code: {response.status_code}")
            self.log(f"Status: {'✅ Success' if response.ok else '❌ Failed'}")
            
            # Try to parse and pretty-print JSON
            try:
                json_response = response.json()
                prettified = json.dumps(json_response, indent=2, sort_keys=False)
                self.log(f"\n{prettified}")
                return response.ok, prettified, response.status_code
            except json.JSONDecodeError:
                # Not JSON, return raw text
                self.log(f"\n{response.text}")
                return response.ok, response.text, response.status_code
                
        except requests.exceptions.Timeout:
            self.log(f"\n❌ Request timeout after 30 seconds")
            return False, "Timeout", 0
        except requests.exceptions.ConnectionError as e:
            self.log(f"\n❌ Connection error: {e}")
            return False, str(e), 0
        except Exception as e:
            self.log(f"\n❌ Error: {e}")
            return False, str(e), 0
        finally:
            self.log("="*80 + "\n")
    
    # ==================== VERSA DIRECTOR API METHODS ====================
    
    def get_director_package_info(self) -> Tuple[bool, str, int]:
        """Get Director Package Information"""
        return self.make_api_call(
            method="GET",
            endpoint="/api/operational/system/package-info",
            description="Director Package Info"
        )
    
    def get_all_appliances(self) -> Tuple[bool, str, int]:
        """Get all appliances detail"""
        return self.make_api_call(
            method="GET",
            endpoint="/vnms/appliance/appliance/lite?offset=0&limit=2500",
            description="Get All Appliances Detail"
        )
    
    def list_template_names(self) -> Tuple[bool, str, int]:
        """List template names"""
        return self.make_api_call(
            method="GET",
            endpoint="/vnms/sdwan/workflow/templates",
            description="List Template Names"
        )
    
    def export_template_config(self) -> Tuple[bool, str, int]:
        """Export Template configuration"""
        return self.make_api_call(
            method="GET",
            endpoint=f"/vnms/template/export?templateName={self.template_name}",
            description=f"Export Template Config ({self.template_name})",
            headers={"Accept": "text/plain"}
        )

    def initiate_vd_backup(self) -> Tuple[bool, str, int]:
        """Initiate Versa Director backup"""
        return self.make_api_call(
            method="POST",
            endpoint="/api/config/system/recovery/backup/_operations",
            description="Initiate VD Backup",
            data={"backup": {"include-package-dir": "false"}}
        )
    
    def get_audit_logs(self) -> Tuple[bool, str, int]:
        """Get Audit Logs"""
        return self.make_api_call(
            method="GET",
            endpoint="/vnms/audit/logs?offset=0&limit=25",
            description="Get Audit Logs"
        )
    
    def get_vnmsha_details(self) -> Tuple[bool, str, int]:
        """Get VNMSHA details"""
        return self.make_api_call(
            method="POST",
            endpoint="/api/config/vnmsha/actions/_operations/get-vnmsha-details",
            description="Get VNMSHA Details"
        )
    
    def get_vd_system_details(self) -> Tuple[bool, str, int]:
        """Versa Director System details"""
        return self.make_api_call(
            method="GET",
            endpoint="/vnms/dashboard/vdStatus/sysDetails",
            description="VD System Details"
        )
    
    def list_all_tasks(self) -> Tuple[bool, str, int]:
        """List all tasks"""
        return self.make_api_call(
            method="GET",
            endpoint="/vnms/tasks",
            description="List All Tasks"
        )
    
    def get_task_details(self) -> Tuple[bool, str, int]:
        """Get specific task details"""
        if not self.task_number:
            self.log("❌ Error: Task Number is required")
            self.log("   Please enter a Task Number in the input field")
            return False, "Task Number required", 0
        
        return self.make_api_call(
            method="GET",
            endpoint=f"/vnms/tasks/task/{self.task_number}",
            description=f"Get Task Details (Task #{self.task_number})"
        )
    
    def get_appliances_tsv_format(self) -> Tuple[bool, str, int]:
        """Get appliances list in TSV format with proper column alignment"""
        self.log("📊 Fetching Appliances List...")
        
        try:
            success, response_text, status_code = self.make_api_call(
                method="GET",
                endpoint="/vnms/appliance/appliance/lite?offset=0&limit=2500",
                description="Get Appliances List"
            )
            
            if not success:
                return False, response_text, status_code
            
            try:
                data = json.loads(response_text)
                appliances = data.get("versanms.ApplianceStatusResult", {}).get("appliances", [])
                
                if not appliances:
                    self.log("⚠️  No appliances found")
                    return True, "No appliances found", status_code
                
                # Collect all data first
                table_data = []
                device_names = []
                
                for app in appliances:
                    name = app.get("name", "N/A")
                    uuid = app.get("uuid", "N/A")
                    owner_org = app.get("ownerOrg", "N/A")
                    template_status = app.get("templateStatus", "N/A")
                    ping_status = app.get("ping-status", "N/A")
                    sync_status = app.get("sync-status", "N/A")
                    
                    # Extract SPACK version
                    spack_version = "N/A"
                    if "SPack" in app and "spackVersion" in app["SPack"]:
                        spack_version = app["SPack"]["spackVersion"]
                    
                    # Extract OSSPACK version
                    osspack_version = "N/A"
                    if "OssPack" in app and "osspackVersion" in app["OssPack"]:
                        osspack_version = app["OssPack"]["osspackVersion"]
                    
                    table_data.append({
                        'name': name,
                        'uuid': uuid,
                        'owner_org': owner_org,
                        'template_status': template_status,
                        'ping_status': ping_status,
                        'sync_status': sync_status,
                        'spack_version': spack_version,
                        'osspack_version': osspack_version
                    })
                    
                    # Add device name to list (skip N/A)
                    if name != "N/A":
                        device_names.append(name)
                
                # Sort by ping_status
                table_data.sort(key=lambda x: x['ping_status'])
                
                # Define column widths for proper alignment
                col_widths = {
                    'name': 20,
                    'uuid': 38,
                    'owner_org': 15,
                    'template_status': 16,
                    'ping_status': 13,
                    'sync_status': 13,
                    'spack_version': 12,
                    'osspack_version': 14
                }
                
                # Create formatted table
                formatted_lines = []
                
                # Header
                header = (
                    f"{'NAME':<{col_widths['name']}} "
                    f"{'UUID':<{col_widths['uuid']}} "
                    f"{'OWNER_ORG':<{col_widths['owner_org']}} "
                    f"{'TEMPLATE_STATUS':<{col_widths['template_status']}} "
                    f"{'PING_STATUS':<{col_widths['ping_status']}} "
                    f"{'SYNC_STATUS':<{col_widths['sync_status']}} "
                    f"{'SPACK_VER':<{col_widths['spack_version']}} "
                    f"{'OSSPACK_VER':<{col_widths['osspack_version']}}"
                )
                formatted_lines.append(header)
                
                # Separator line
                separator = (
                    f"{'-' * col_widths['name']} "
                    f"{'-' * col_widths['uuid']} "
                    f"{'-' * col_widths['owner_org']} "
                    f"{'-' * col_widths['template_status']} "
                    f"{'-' * col_widths['ping_status']} "
                    f"{'-' * col_widths['sync_status']} "
                    f"{'-' * col_widths['spack_version']} "
                    f"{'-' * col_widths['osspack_version']}"
                )
                formatted_lines.append(separator)
                
                # Data rows
                for row in table_data:
                    line = (
                        f"{row['name']:<{col_widths['name']}} "
                        f"{row['uuid']:<{col_widths['uuid']}} "
                        f"{row['owner_org']:<{col_widths['owner_org']}} "
                        f"{row['template_status']:<{col_widths['template_status']}} "
                        f"{row['ping_status']:<{col_widths['ping_status']}} "
                        f"{row['sync_status']:<{col_widths['sync_status']}} "
                        f"{row['spack_version']:<{col_widths['spack_version']}} "
                        f"{row['osspack_version']:<{col_widths['osspack_version']}}"
                    )
                    formatted_lines.append(line)
                
                formatted_output = "\n".join(formatted_lines)
                
                # Add comma-separated device list at the end
                comma_separated_devices = ", ".join(device_names)
                
                self.log(f"\n{'='*80}")
                self.log(f"✅ Found {len(appliances)} appliances (sorted by ping-status)")
                self.log(f"{'='*80}\n")
                self.log(formatted_output)
                self.log(f"\n{'='*80}")
                self.log(f"📋 Comma-Separated Device List:")
                self.log(f"{'='*80}")
                self.log(comma_separated_devices)
                self.log(f"{'='*80}\n")
                
                return True, formatted_output, status_code
                
            except json.JSONDecodeError as e:
                self.log(f"❌ Error parsing JSON: {e}")
                return False, f"JSON parsing error: {e}", status_code
                
        except Exception as e:
            self.log(f"❌ Error processing appliances TSV: {e}")
            return False, f"Error: {e}", 0
    
    def get_all_organizations(self) -> Tuple[bool, str, int]:
        """Get all organizations from Versa Director"""
        self.log("🏢 Fetching all organizations...")
        
        try:
            success, response_text, status_code = self.make_api_call(
                method="GET",
                endpoint="/nextgen/organization?offset=1&limit=25&uuidOnly=false",
                description="Get All Organizations",
                headers={"Accept": "application/hal+json"}
            )
            
            if not success:
                return False, response_text, status_code
            
            try:
                data = json.loads(response_text)
                prettified = json.dumps(data, indent=2, sort_keys=False)
                
                org_count = 0
                if isinstance(data, dict):
                    if "_embedded" in data and "organizations" in data["_embedded"]:
                        org_count = len(data["_embedded"]["organizations"])
                    elif "organizations" in data:
                        org_count = len(data["organizations"])
                
                self.log(f"\n{'='*80}")
                self.log(f"✅ Retrieved {org_count} organizations")
                self.log(f"{'='*80}\n")
                self.log(prettified)
                
                return True, prettified, status_code
                
            except json.JSONDecodeError as e:
                self.log(f"❌ Error parsing JSON: {e}")
                return False, response_text, status_code
                
        except Exception as e:
            self.log(f"❌ Error fetching organizations: {e}")
            return False, f"Error: {e}", 0
    
    def get_system_uptime(self) -> Tuple[bool, str, int]:
        """Get Versa Director system uptime"""
        self.log("⏱️  Fetching system uptime...")
        
        try:
            success, response_text, status_code = self.make_api_call(
                method="GET",
                endpoint="/vnms/system/uptime",
                description="Get System Uptime",
                headers={"Accept": "application/hal+json"}
            )
            
            if not success:
                return False, response_text, status_code
            
            try:
                data = json.loads(response_text)
                
                uptime_info = ""
                if isinstance(data, dict):
                    if "uptime" in data:
                        uptime_info = f"Uptime: {data['uptime']}"
                    elif "system-uptime" in data:
                        uptime_info = f"System Uptime: {data['system-uptime']}"
                
                prettified = json.dumps(data, indent=2, sort_keys=False)
                
                self.log(f"\n{'='*80}")
                if uptime_info:
                    self.log(f"✅ {uptime_info}")
                else:
                    self.log(f"✅ System uptime retrieved")
                self.log(f"{'='*80}\n")
                self.log(prettified)
                
                return True, prettified, status_code
                
            except json.JSONDecodeError as e:
                self.log(f"❌ Error parsing JSON: {e}")
                return False, response_text, status_code
                
        except Exception as e:
            self.log(f"❌ Error fetching system uptime: {e}")
            return False, f"Error: {e}", 0
    
    # ==================== VOS API METHODS ====================
    
    def export_device_config(self) -> Tuple[bool, str, int]:
        """Export Device configuration"""
        first_device = self.get_first_device()
        return self.make_api_call(
            method="GET",
            endpoint=f"/vnms/appliance/export?applianceName={first_device}",
            description=f"Export Device Config ({first_device})",
            headers={"Accept": "text/plain"}
        )
    
    def get_interfaces_brief(self) -> Tuple[bool, str, int]:
        """Get interfaces brief"""
        first_device = self.get_first_device()
        return self.make_api_call(
            method="GET",
            endpoint=f"/api/operational/devices/device/{first_device}/live-status/interfaces/brief",
            description=f"Interfaces Brief ({first_device})"
        )
    
    def list_snapshots(self) -> Tuple[bool, str, int]:
        """List system snapshots for device"""
        first_device = self.get_first_device()
        return self.make_api_call(
            method="GET",
            endpoint=f"/api/operational/devices/device/{first_device}/live-status/system/snapshots",
            description=f"List System Snapshots ({first_device})"
        )
    
    def get_alarm_statistics(self) -> Tuple[bool, str, int]:
        """Display alarm statistics in detail"""
        first_device = self.get_first_device()
        return self.make_api_call(
            method="GET",
            endpoint=f"/api/operational/devices/device/{first_device}/live-status/alarms/statistics/detail",
            description=f"Get Alarm Statistics ({first_device})"
        )
    
    def list_images(self) -> Tuple[bool, str, int]:
        """List available images/packages on device"""
        first_device = self.get_first_device()
        return self.make_api_call(
            method="POST",
            endpoint=f"/api/config/devices/device/{first_device}/config/system/package/list/_operations",
            description=f"List Images/Packages ({first_device})"
        )
    
    def get_bgp_status(self) -> Tuple[bool, str, int]:
        """Get BGP neighbors status"""
        first_device = self.get_first_device()
        return self.make_api_call(
            method="GET",
            endpoint=f"/api/operational/devices/device/{first_device}/live-status/bgp/neighbors/brief/?deep=true",
            description=f"Get BGP Neighbors Status ({first_device})"
        )
    
    def reboot_device(self) -> Tuple[bool, str, int]:
        """Reboot Device and Restart Services"""
        first_device = self.get_first_device()
        return self.make_api_call(
            method="POST",
            endpoint=f"/api/config/devices/device/{first_device}/config/system/_operations/reboot",
            description=f"Reboot Device ({first_device})",
            data={"reboot": {"after": 5}}
        )
    
    # ==================== SPACK API METHODS ====================
    
    def list_spack_downloads(self) -> Tuple[bool, str, int]:
        """List downloaded SPACK on Director"""
        return self.make_api_call(
            method="GET",
            endpoint="/nextgen/spack/downloads?offset=0&limit=25",
            description="List SPACK - Show what SPACK files are already downloaded and available in Versa Director"
        )
    
    def get_latest_security_package(self) -> Tuple[bool, str, int]:
        """Get the latest security package available"""
        return self.make_api_call(
            method="GET",
            endpoint="/vnms/spack/checkavailableupdates?updatetype=full",
            description="Fetch SPACK List - Check what SPACK versions are available for download from cloud server"
        )
    
    def download_security_package(self) -> Tuple[bool, str, int]:
        """Download specific security package"""
        success, response_text, status_code = self.make_api_call(
            method="POST",
            endpoint=f"/vnms/spack/download?updatetype=full&versionToDownload={self.version}",
            description=f"Download Security Package (version {self.version})"
        )
        
        # Check if response contains task-id and auto-fetch task details
        if success and response_text:
            try:
                json_response = json.loads(response_text)
                if "TaskResponse" in json_response:
                    task_id = json_response["TaskResponse"].get("task-id")
                    if task_id:
                        self.log(f"\n🔍 Task created with ID: {task_id}")
                        self.log(f"⏳ Automatically fetching task details...\n")
                        
                        # Update task number in the instance
                        self.task_number = str(task_id)
                        
                        # Update task number in GUI if callback provided
                        if self.task_number_callback:
                            self.task_number_callback(str(task_id))
                        
                        # Auto-fetch task details
                        import time
                        time.sleep(1)  # Brief pause before fetching
                        self.get_task_details()
            except json.JSONDecodeError:
                pass  # Response is not JSON, that's okay
        
        return success, response_text, status_code
    
    def update_spack_on_device(self) -> Tuple[bool, str, int]:
        """Upgrade security package on specific device(s)"""
        # Parse comma-separated device names and create list
        device_list = [d.strip() for d in self.device_name.split(',') if d.strip()]
        
        if not device_list:
            self.log("❌ Error: Device name is required")
            return False, "Device name required", 0
        
        # Construct package name
        package_name = f"versa-security-package-{self.version}.tbz2"
        
        # Use API endpoint with port 9182
        url = f"https://{self.director_ip}:9182/vnms/spack/schedule/updateAppliance"
        
        data = {
            "versanms.scheduleSpackUpgradeRequest": {
                "device-list": device_list,
                "packageName": package_name,
                "version": self.version,
                "flavour": "premium",
                "updateType": "FULL"
            }
        }
        
        default_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        # Log the API call
        self.log("="*80)
        self.log(f"📡 VD API Demo: Upgrade SPACK on Device(s) ({', '.join(device_list)}, version {self.version})")
        self.log("="*80)
        self.log(f"Method: POST")
        self.log(f"URL: {url}")
        self.log(f"Data: {json.dumps(data, indent=2)}")
        
        # Mask password in CURL if hide_password is enabled
        password_display = "********" if self.hide_password else self.password
        curl_cmd = f"curl -k -X POST '{url}' -H 'Accept: application/json' -H 'Content-Type: application/json' -u '{self.username}:{password_display}' --data-raw '{json.dumps(data)}'"
        self.log(f"\n📋 Equivalent CURL Command:")
        self.log(curl_cmd)
        
        try:
            response = requests.post(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                headers=default_headers,
                json=data,
                verify=False,
                timeout=30
            )
            
            self.log(f"\n📥 Response:")
            self.log(f"Status Code: {response.status_code}")
            self.log(f"Status: {'✅ Success' if response.ok else '❌ Failed'}")
            
            try:
                json_response = response.json()
                prettified = json.dumps(json_response, indent=2, sort_keys=False)
                self.log(f"\n{prettified}")
                
                # Check if response contains task-id and auto-fetch task details
                if response.ok and "TaskResponse" in json_response:
                    task_id = json_response["TaskResponse"].get("task-id")
                    if task_id:
                        self.log(f"\n🔍 Task created with ID: {task_id}")
                        self.log(f"⏳ Automatically fetching task details...\n")
                        
                        # Update task number in the instance
                        self.task_number = str(task_id)
                        
                        # Update task number in GUI if callback provided
                        if self.task_number_callback:
                            self.task_number_callback(str(task_id))
                        
                        # Auto-fetch task details
                        import time
                        time.sleep(1)  # Brief pause before fetching
                        self.get_task_details()
                
                return response.ok, prettified, response.status_code
            except json.JSONDecodeError:
                self.log(f"\n{response.text}")
                return response.ok, response.text, response.status_code
                
        except Exception as e:
            self.log(f"\n❌ Error: {e}")
            return False, str(e), 0
        finally:
            self.log("="*80 + "\n")
    
    # ==================== OSSPACK API METHODS ====================
    
    def list_latest_osspack(self) -> Tuple[bool, str, int]:
        """Check OSSPACK updates available"""
        endpoint = (f"/vnms/osspack/device/check-osspack-updates?"
                   f"curr-version=0&"
                   f"os-version={self.os_version}&"
                   f"update-type=full")
        
        return self.make_api_call(
            method="GET",
            endpoint=endpoint,
            description=f"Fetch OSSPACK List - Check what OSSPACK versions are available for download from cloud server (os-version={self.os_version})"
        )
    
    def list_downloaded_director_osspack(self) -> Tuple[bool, str, int]:
        """List all downloaded OSSPACK on Director"""
        return self.make_api_call(
            method="GET",
            endpoint="/vnms/osspack/director/all-downloads",
            description="List Director OSSPACK - Show what OSSPACK files for Director that are already downloaded and available in Versa Director"
        )
    
    def list_downloaded_device_osspack(self) -> Tuple[bool, str, int]:
        """List all downloaded OSSPACK on Devices"""
        return self.make_api_call(
            method="GET",
            endpoint="/vnms/osspack/device/all-downloads",
            description="List Device OSSPACK - Show what OSSPACK files for VOS that are already downloaded and available in Versa Director"
        )
    
    def download_osspack(self) -> Tuple[bool, str, int]:
        """Download OSSPACK"""
        endpoint = (f"/vnms/osspack/download?"
                   f"product={self.product}&"
                   f"version={self.osspack_version}&"
                   f"update-type=full&"
                   f"os-version={self.os_version}")
        
        success, response_text, status_code = self.make_api_call(
            method="POST",
            endpoint=endpoint,
            description=f"Download OSSPACK (product={self.product}, version={self.osspack_version}, os={self.os_version})",
            data={}
        )
        
        # Check if response contains task-id and auto-fetch task details
        if success and response_text:
            try:
                json_response = json.loads(response_text)
                if "TaskResponse" in json_response:
                    task_id = json_response["TaskResponse"].get("task-id")
                    if task_id:
                        self.log(f"\n🔍 Task created with ID: {task_id}")
                        self.log(f"⏳ Automatically fetching task details...\n")
                        
                        # Update task number in the instance
                        self.task_number = str(task_id)
                        
                        # Update task number in GUI if callback provided
                        if self.task_number_callback:
                            self.task_number_callback(str(task_id))
                        
                        # Auto-fetch task details
                        import time
                        time.sleep(1)  # Brief pause before fetching
                        self.get_task_details()
            except json.JSONDecodeError:
                pass  # Response is not JSON, that's okay
        
        return success, response_text, status_code
    
    def update_osspack_on_device(self) -> Tuple[bool, str, int]:
        """Upgrade OSSPACK on device(s)"""
        # Parse comma-separated device names and create list
        device_list = [d.strip() for d in self.device_name.split(',') if d.strip()]
        
        if not device_list:
            self.log("❌ Error: Device name is required")
            return False, "Device name required", 0
        
        # Use port 9182 endpoint
        url = f"https://{self.director_ip}:9182/vnms/osspack/schedule/updateAppliance"
        
        # Custom implementation for this endpoint
        data = {
            "devices": device_list,
            "update-type": "full",
            "version": self.osspack_version,
            "os-version": self.os_version
        }
        
        default_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        # Log the API call
        self.log("="*80)
        self.log(f"📡 VD API Demo: Upgrade OSSPACK on Device(s) ({', '.join(device_list)}, version {self.osspack_version})")
        self.log("="*80)
        self.log(f"Method: POST")
        self.log(f"URL: {url}")
        self.log(f"Data: {json.dumps(data, indent=2)}")
        
        # Mask password in CURL if hide_password is enabled
        password_display = "********" if self.hide_password else self.password
        curl_cmd = f"curl -k -X POST '{url}' -H 'Accept: application/json' -H 'Content-Type: application/json' -u '{self.username}:{password_display}' -d '{json.dumps(data)}'"
        self.log(f"\n📋 Equivalent CURL Command:")
        self.log(curl_cmd)
        
        try:
            response = requests.post(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                headers=default_headers,
                json=data,
                verify=False,
                timeout=30
            )
            
            self.log(f"\n📥 Response:")
            self.log(f"Status Code: {response.status_code}")
            self.log(f"Status: {'✅ Success' if response.ok else '❌ Failed'}")
            
            try:
                json_response = response.json()
                prettified = json.dumps(json_response, indent=2, sort_keys=False)
                self.log(f"\n{prettified}")
                
                # Check if response contains task-id and auto-fetch task details
                if response.ok and "TaskResponse" in json_response:
                    task_id = json_response["TaskResponse"].get("task-id")
                    if task_id:
                        self.log(f"\n🔍 Task created with ID: {task_id}")
                        self.log(f"⏳ Automatically fetching task details...\n")
                        
                        # Update task number in the instance
                        self.task_number = str(task_id)
                        
                        # Update task number in GUI if callback provided
                        if self.task_number_callback:
                            self.task_number_callback(str(task_id))
                        
                        # Auto-fetch task details
                        import time
                        time.sleep(1)  # Brief pause before fetching
                        self.get_task_details()
                
                return response.ok, prettified, response.status_code
            except json.JSONDecodeError:
                self.log(f"\n{response.text}")
                return response.ok, response.text, response.status_code
                
        except Exception as e:
            self.log(f"\n❌ Error: {e}")
            return False, str(e), 0
        finally:
            self.log("="*80 + "\n")
        
        try:
            response = requests.post(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                headers=default_headers,
                json=data,
                verify=False,
                timeout=30
            )
            
            self.log(f"\n📥 Response:")
            self.log(f"Status Code: {response.status_code}")
            self.log(f"Status: {'✅ Success' if response.ok else '❌ Failed'}")
            
            try:
                json_response = response.json()
                prettified = json.dumps(json_response, indent=2, sort_keys=False)
                self.log(f"\n{prettified}")
                return response.ok, prettified, response.status_code
            except json.JSONDecodeError:
                self.log(f"\n{response.text}")
                return response.ok, response.text, response.status_code
                
        except Exception as e:
            self.log(f"\n❌ Error: {e}")
            return False, str(e), 0
        finally:
            self.log("="*80 + "\n")


class VDApiDemoApp:
    """Main GUI Application for VD REST API Demo"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔬 Versa Director REST API Demo")
        self.root.geometry("1400x900")
        
        # Configure grid weight for resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Create main container
        main_container = ttk.Frame(self.root, padding="10")
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_container.columnconfigure(0, weight=1)
        main_container.rowconfigure(1, weight=1)
        
        # Create credentials frame
        self.create_credentials_frame(main_container)
        
        # Create PanedWindow for resizable sections
        paned_window = ttk.PanedWindow(main_container, orient=tk.HORIZONTAL)
        paned_window.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        
        # Create API buttons frame (left side)
        buttons_frame = ttk.Frame(paned_window)
        self.create_buttons_frame(buttons_frame)
        paned_window.add(buttons_frame, weight=1)
        
        # Create output log frame (right side) - flexible/expandable
        output_frame = ttk.Frame(paned_window)
        self.create_output_frame(output_frame)
        paned_window.add(output_frame, weight=3)
        
        # Log welcome message
        self.log("="*80)
        self.log("🚀 Versa Director REST API Demo Application Started")
        self.log(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("="*80)
        self.log("\n💡 Enter your credentials and click any API button to test\n")
    
    def create_credentials_frame(self, parent):
        """Create credentials input frame"""
        cred_frame = ttk.LabelFrame(parent, text="📝 Connection Settings", padding="8")
        cred_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Row 1: Director IP, Username, Password, Hide Password Checkbox, Clear Log, Download Log Buttons
        row1 = ttk.Frame(cred_frame)
        row1.pack(fill="x", pady=2)
        
        ttk.Label(row1, text="Director IP:", width=10).pack(side="left", padx=(0, 3))
        self.director_ip_var = tk.StringVar(value="10.192.244.101")
        ttk.Entry(row1, textvariable=self.director_ip_var, width=15).pack(side="left", padx=(0, 10))
        
        ttk.Label(row1, text="Username:", width=9).pack(side="left", padx=(0, 3))
        self.username_var = tk.StringVar(value="Administrator")
        ttk.Entry(row1, textvariable=self.username_var, width=12).pack(side="left", padx=(0, 10))
        
        ttk.Label(row1, text="Password:", width=9).pack(side="left", padx=(0, 3))
        self.password_var = tk.StringVar(value="BestSDWAN1+")
        ttk.Entry(row1, textvariable=self.password_var, show="*", width=12).pack(side="left", padx=(0, 10))
        
        # Hide Password checkbox
        self.hide_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row1, text="Hide Password", variable=self.hide_password_var).pack(side="left", padx=(0, 10))
        
        ttk.Button(row1, text="🗑️ Clear Log", command=self.clear_log, width=14).pack(side="left", padx=(0, 5))
        ttk.Button(row1, text="💾 Download Log", command=self.download_log, width=15).pack(side="left", padx=(0, 5))
        
        # Row 2: Template, Device/Appliance, SPACK Version, Task Number
        row2 = ttk.Frame(cred_frame)
        row2.pack(fill="x", pady=2)
        
        ttk.Label(row2, text="Template:", width=9).pack(side="left", padx=(0, 3))
        self.template_var = tk.StringVar(value="BRANCH")
        ttk.Entry(row2, textvariable=self.template_var, width=10).pack(side="left", padx=(0, 10))
        
        ttk.Label(row2, text="Device:", width=7).pack(side="left", padx=(0, 3))
        self.device_var = tk.StringVar(value="CONTROLLER1")
        ttk.Entry(row2, textvariable=self.device_var, width=13).pack(side="left", padx=(0, 10))
        
        ttk.Label(row2, text="SPACK Ver:", width=9).pack(side="left", padx=(0, 3))
        self.version_var = tk.StringVar(value="2064")
        ttk.Entry(row2, textvariable=self.version_var, width=8).pack(side="left", padx=(0, 10))
        
        ttk.Label(row2, text="Task#:", width=6).pack(side="left", padx=(0, 3))
        self.task_number_var = tk.StringVar(value="")
        ttk.Entry(row2, textvariable=self.task_number_var, width=8).pack(side="left", padx=(0, 10))
        
        ttk.Label(row2, text="OSSPACK:", width=8).pack(side="left", padx=(0, 3))
        self.osspack_version_var = tk.StringVar(value="20251006")
        ttk.Entry(row2, textvariable=self.osspack_version_var, width=10).pack(side="left", padx=(0, 10))
        
        ttk.Label(row2, text="OS Type:", width=8).pack(side="left", padx=(0, 3))
        self.os_version_var = tk.StringVar(value="bionic")
        os_combo = ttk.Combobox(row2, textvariable=self.os_version_var, width=10, state="readonly")
        os_combo['values'] = ('bionic', 'trusty')
        os_combo.pack(side="left", padx=(0, 10))
        
        ttk.Label(row2, text="Product:", width=7).pack(side="left", padx=(0, 3))
        self.product_var = tk.StringVar(value="versa-flexvnf")
        product_combo = ttk.Combobox(row2, textvariable=self.product_var, width=14, state="readonly")
        product_combo['values'] = ('versa-flexvnf', 'versa-director')
        product_combo.pack(side="left")
    
    def create_dynamic_button_grid(self, frame, buttons, min_width=140):
        """Create a dynamic button grid that adjusts columns based on frame width"""
        # Store button data for dynamic resizing
        frame.button_data = buttons
        frame.min_button_width = min_width
        frame.button_widgets = []
        frame.last_cols = 0  # Track last column count to avoid unnecessary redraws
        
        def relayout_buttons(event=None):
            """Recalculate button layout based on current frame width"""
            # Get current width - use the scrollable_frame width for better accuracy
            width = frame.winfo_width()
            
            # During initial setup, width might be 1, so use a reasonable default
            if width <= 1:
                width = 350  # Default starting width
            
            # Calculate how many columns can fit
            padding = 30  # Account for frame padding and margins
            usable_width = width - padding
            cols = max(1, usable_width // (min_width + 6))  # 6 for button padding
            
            # Only relayout if column count changed
            if cols == frame.last_cols and frame.button_widgets:
                return
            
            frame.last_cols = cols
            
            # Clear existing buttons
            for widget in frame.button_widgets:
                widget.destroy()
            frame.button_widgets = []
            
            # Clear column configurations
            for col in range(10):  # Clear up to 10 columns
                frame.columnconfigure(col, weight=0)
            
            # Create buttons in grid
            for i, (button_name, api_method) in enumerate(buttons):
                btn = ttk.Button(
                    frame,
                    text=button_name,
                    command=lambda m=api_method, n=button_name: self.run_api_call(m, n)
                )
                row = i // cols
                col = i % cols
                btn.grid(row=row, column=col, padx=3, pady=3, sticky="ew")
                frame.button_widgets.append(btn)
            
            # Configure column weights for current layout
            for col in range(cols):
                frame.columnconfigure(col, weight=1)
        
        # Bind to frame resize
        frame.bind("<Configure>", relayout_buttons)
        
        # Store reference for manual triggering
        frame.relayout_buttons = relayout_buttons
        
        # Initial layout with delay to ensure proper sizing
        frame.after(10, relayout_buttons)
        frame.after(100, relayout_buttons)
    
    def create_buttons_frame(self, parent):
        """Create API buttons frame with dynamic responsive layout"""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        
        # Canvas for scrolling
        canvas = tk.Canvas(parent, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        # Store scrollable frame reference for width tracking
        self.scrollable_frame = scrollable_frame
        
        def on_canvas_configure(event):
            """Update scroll region and trigger button relayout"""
            canvas.configure(scrollregion=canvas.bbox("all"))
            # Trigger relayout of all button sections
            for child in scrollable_frame.winfo_children():
                if hasattr(child, 'relayout_buttons'):
                    child.after(10, child.relayout_buttons)
        
        scrollable_frame.bind("<Configure>", on_canvas_configure)
        
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Make canvas window expand to canvas width
        def on_canvas_resize(event):
            canvas.itemconfig(canvas_window, width=event.width)
            # Trigger relayout after canvas resize
            scrollable_frame.after(20, lambda: trigger_all_relayouts())
        
        canvas.bind("<Configure>", on_canvas_resize)
        
        def trigger_all_relayouts():
            """Trigger relayout on all button frames"""
            for child in scrollable_frame.winfo_children():
                if hasattr(child, 'relayout_buttons'):
                    child.relayout_buttons()
        
        # Store reference for later use
        self.trigger_all_relayouts = trigger_all_relayouts
        
        # Section 1: Versa Director API
        vd_frame = ttk.LabelFrame(scrollable_frame, text="Versa Director API", padding=10)
        vd_frame.pack(fill="both", expand=True, pady=5, padx=5)
        
        vd_buttons = [
            ("Director Package", "get_director_package_info"),
            ("Appliances Detail", "get_all_appliances"),
            ("List Templates", "list_template_names"),
            ("Export Template", "export_template_config"),
            ("VD HA Details", "get_vnmsha_details"),
            ("Get Audit Logs", "get_audit_logs"),
            ("List All Tasks", "list_all_tasks"),
            ("Get Task Details", "get_task_details"),
            ("Initiate VD Backup", "initiate_vd_backup"),
            ("VD System Details", "get_vd_system_details"),
            ("Appliances List (TSV)", "get_appliances_tsv_format"),
            ("Get Organizations", "get_all_organizations"),
            ("System Uptime", "get_system_uptime"),
        ]
        
        self.create_dynamic_button_grid(vd_frame, vd_buttons)
        
        # Section 2: VOS API
        vos_frame = ttk.LabelFrame(scrollable_frame, text="VOS API", padding=10)
        vos_frame.pack(fill="both", expand=True, pady=5, padx=5)
        
        vos_buttons = [
            ("Device Config", "export_device_config"),
            ("Interfaces Brief", "get_interfaces_brief"),
            ("List Snapshots", "list_snapshots"),
            ("Alarm Statistics", "get_alarm_statistics"),
            ("List Images", "list_images"),
            ("BGP Status", "get_bgp_status"),
            ("Reboot Device", "reboot_device"),
        ]
        
        self.create_dynamic_button_grid(vos_frame, vos_buttons)
        
        # Section 3: Security Package (SPACK)
        spack_frame = ttk.LabelFrame(scrollable_frame, text="Security Package (SPACK)", padding=10)
        spack_frame.pack(fill="both", expand=True, pady=5, padx=5)
        
        spack_buttons = [
            ("Fetch SPACK List", "get_latest_security_package"),
            ("Download SPACK", "download_security_package"),
            ("Upgrade SPACK", "update_spack_on_device"),
            ("List SPACK", "list_spack_downloads"),
        ]
        
        self.create_dynamic_button_grid(spack_frame, spack_buttons)
        
        # Section 4: OS Security Package (OSSPACK)
        osspack_frame = ttk.LabelFrame(scrollable_frame, text="OS Security Package (OSSPACK)", padding=10)
        osspack_frame.pack(fill="both", expand=True, pady=5, padx=5)
        
        osspack_buttons = [
            ("Fetch OSSPACK List", "list_latest_osspack"),
            ("Download OSSPACK", "download_osspack"),
            ("Upgrade OSSPACK", "update_osspack_on_device"),
            ("List Director OSSPACK", "list_downloaded_director_osspack"),
            ("List Device OSSPACK", "list_downloaded_device_osspack"),
        ]
        
        self.create_dynamic_button_grid(osspack_frame, osspack_buttons)
        
        canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Trigger initial layout after everything is packed
        scrollable_frame.after(200, trigger_all_relayouts)
        scrollable_frame.after(500, trigger_all_relayouts)
    
    def create_output_frame(self, parent):
        """Create output log frame - flexible/expandable with color syntax highlighting"""
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        
        output_container = ttk.LabelFrame(parent, text="📋 API Response Log", padding="5")
        output_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        output_container.rowconfigure(0, weight=1)
        output_container.columnconfigure(0, weight=1)
        
        # Create scrolled text widget - fully expandable and READ-ONLY
        self.output_text = scrolledtext.ScrolledText(
            output_container,
            wrap=tk.WORD,
            font=("Courier", 9),
            bg="#0d1117",  # GitHub dark background
            fg="#c9d1d9",  # Default light gray text
            insertbackground="white",
            state="disabled"  # Make it read-only
        )
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # COLOR SCHEME OPTIONS - Choose one of the schemes below:
        
        # SCHEME 1: GitHub Dark (High Contrast) - CURRENT
        self.output_text.tag_config("header", foreground="#58a6ff", font=("Courier", 9, "bold"))  # Bright blue headers
        self.output_text.tag_config("separator", foreground="#30363d")  # Dark gray separators
        self.output_text.tag_config("curl", foreground="#ffffff", font=("Courier", 9, "bold"))  # Pure white CURL
        self.output_text.tag_config("response", foreground="#7ee787")  # Bright green responses
        self.output_text.tag_config("success", foreground="#3fb950", font=("Courier", 9, "bold"))  # Green success
        self.output_text.tag_config("error", foreground="#ff7b72", font=("Courier", 9, "bold"))  # Bright red errors
        self.output_text.tag_config("info", foreground="#ffa657")  # Orange/amber info
        self.output_text.tag_config("json", foreground="#d2a8ff")  # Purple JSON
        self.output_text.tag_config("task", foreground="#79c0ff")  # Cyan task info
        self.output_text.tag_config("default", foreground="#c9d1d9")  # Light gray default
        
        # SCHEME 2: Monokai Pro (Vibrant) - Uncomment to use
        # self.output_text.tag_config("header", foreground="#66d9ef", font=("Courier", 9, "bold"))  # Cyan headers
        # self.output_text.tag_config("separator", foreground="#464646")  # Gray separators
        # self.output_text.tag_config("curl", foreground="#f8f8f2", font=("Courier", 9, "bold"))  # Off-white CURL
        # self.output_text.tag_config("response", foreground="#a6e22e")  # Lime green responses
        # self.output_text.tag_config("success", foreground="#a6e22e", font=("Courier", 9, "bold"))  # Lime success
        # self.output_text.tag_config("error", foreground="#f92672", font=("Courier", 9, "bold"))  # Pink/red errors
        # self.output_text.tag_config("info", foreground="#e6db74")  # Yellow info
        # self.output_text.tag_config("json", foreground="#ae81ff")  # Purple JSON
        # self.output_text.tag_config("task", foreground="#66d9ef")  # Cyan task
        # self.output_text.tag_config("default", foreground="#f8f8f2")  # Off-white default
        
        # SCHEME 3: Dracula (Popular Dark Theme) - Uncomment to use
        # self.output_text.tag_config("header", foreground="#8be9fd", font=("Courier", 9, "bold"))  # Cyan headers
        # self.output_text.tag_config("separator", foreground="#44475a")  # Gray separators
        # self.output_text.tag_config("curl", foreground="#f8f8f2", font=("Courier", 9, "bold"))  # White CURL
        # self.output_text.tag_config("response", foreground="#50fa7b")  # Green responses
        # self.output_text.tag_config("success", foreground="#50fa7b", font=("Courier", 9, "bold"))  # Green success
        # self.output_text.tag_config("error", foreground="#ff5555", font=("Courier", 9, "bold"))  # Red errors
        # self.output_text.tag_config("info", foreground="#f1fa8c")  # Yellow info
        # self.output_text.tag_config("json", foreground="#bd93f9")  # Purple JSON
        # self.output_text.tag_config("task", foreground="#8be9fd")  # Cyan task
        # self.output_text.tag_config("default", foreground="#f8f8f2")  # White default
        
        # SCHEME 4: Nord (Cool Blues/Greens) - Uncomment to use
        # self.output_text.tag_config("header", foreground="#88c0d0", font=("Courier", 9, "bold"))  # Frost blue headers
        # self.output_text.tag_config("separator", foreground="#3b4252")  # Dark gray separators
        # self.output_text.tag_config("curl", foreground="#eceff4", font=("Courier", 9, "bold"))  # Snow white CURL
        # self.output_text.tag_config("response", foreground="#a3be8c")  # Green responses
        # self.output_text.tag_config("success", foreground="#a3be8c", font=("Courier", 9, "bold"))  # Green success
        # self.output_text.tag_config("error", foreground="#bf616a", font=("Courier", 9, "bold"))  # Red errors
        # self.output_text.tag_config("info", foreground="#ebcb8b")  # Yellow info
        # self.output_text.tag_config("json", foreground="#b48ead")  # Purple JSON
        # self.output_text.tag_config("task", foreground="#81a1c1")  # Blue task
        # self.output_text.tag_config("default", foreground="#d8dee9")  # Light gray default
        
        # SCHEME 5: Solarized Dark (Professional) - Uncomment to use
        # self.output_text.tag_config("header", foreground="#268bd2", font=("Courier", 9, "bold"))  # Blue headers
        # self.output_text.tag_config("separator", foreground="#073642")  # Very dark gray separators
        # self.output_text.tag_config("curl", foreground="#fdf6e3", font=("Courier", 9, "bold"))  # Cream white CURL
        # self.output_text.tag_config("response", foreground="#859900")  # Olive green responses
        # self.output_text.tag_config("success", foreground="#859900", font=("Courier", 9, "bold"))  # Green success
        # self.output_text.tag_config("error", foreground="#dc322f", font=("Courier", 9, "bold"))  # Red errors
        # self.output_text.tag_config("info", foreground="#b58900")  # Yellow/amber info
        # self.output_text.tag_config("json", foreground="#6c71c4")  # Violet JSON
        # self.output_text.tag_config("task", foreground="#2aa198")  # Cyan task
        # self.output_text.tag_config("default", foreground="#93a1a1")  # Gray default
        
        # SCHEME 6: One Dark (Atom Editor) - Uncomment to use
        # self.output_text.tag_config("header", foreground="#61afef", font=("Courier", 9, "bold"))  # Blue headers
        # self.output_text.tag_config("separator", foreground="#3e4451")  # Gray separators
        # self.output_text.tag_config("curl", foreground="#ffffff", font=("Courier", 9, "bold"))  # White CURL
        # self.output_text.tag_config("response", foreground="#98c379")  # Green responses
        # self.output_text.tag_config("success", foreground="#98c379", font=("Courier", 9, "bold"))  # Green success
        # self.output_text.tag_config("error", foreground="#e06c75", font=("Courier", 9, "bold"))  # Red errors
        # self.output_text.tag_config("info", foreground="#e5c07b")  # Gold info
        # self.output_text.tag_config("json", foreground="#c678dd")  # Purple JSON
        # self.output_text.tag_config("task", foreground="#56b6c2")  # Cyan task
        # self.output_text.tag_config("default", foreground="#abb2bf")  # Light gray default
    
    def log(self, message: str, tag=None):
        """Log message to the output text widget with automatic color detection"""
        self.output_text.config(state="normal")  # Enable editing temporarily
        
        # Auto-detect color tags if not specified
        if tag is None:
            if message.startswith("="*80) or message.startswith("-"*80):
                tag = "separator"
            elif "📡 VD API Demo:" in message or "🚀 Executing:" in message:
                tag = "header"
            elif message.startswith("curl ") or "curl -k" in message:
                tag = "curl"
            elif "📥 Response:" in message or "Status Code:" in message or "Status:" in message:
                tag = "response"
            elif "✅" in message or "Success" in message:
                tag = "success"
            elif "❌" in message or "Error" in message or "Failed" in message:
                tag = "error"
            elif message.startswith("{") or message.startswith("[") or message.strip().startswith('"'):
                tag = "json"
            elif "🔍 Task" in message or "⏳" in message or "Task #" in message:
                tag = "task"
            elif "Method:" in message or "URL:" in message or "Endpoint:" in message or "Data:" in message:
                tag = "info"
            elif "📋 Equivalent CURL Command:" in message or "📋 Comma-Separated" in message:
                tag = "info"
            else:
                tag = "default"
        
        # Insert with appropriate tag
        self.output_text.insert(tk.END, message + "\n", tag)
        self.output_text.see(tk.END)
        self.output_text.config(state="disabled")  # Disable editing again
        self.output_text.update_idletasks()
    
    def clear_log(self):
        """Clear the output log"""
        self.output_text.config(state="normal")  # Enable editing temporarily
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state="disabled")  # Disable editing again
        self.log("📝 Log cleared\n")
    
    def download_log(self):
        """Download the log content to a file with timestamp"""
        from datetime import datetime
        
        # Get current timestamp in the required format: NXTgen-POCbot-DD-MM-YY-HH-MM-SS
        timestamp = datetime.now().strftime("%d-%m-%y-%H-%M-%S")
        filename = f"NXTgen-POCbot-{timestamp}.log"
        
        # Get log content
        log_content = self.output_text.get(1.0, tk.END)
        
        # Save to file
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(log_content)
            
            self.log(f"\n{'='*80}")
            self.log(f"✅ Log downloaded successfully!")
            self.log(f"📁 Filename: {filename}")
            self.log(f"📂 Location: {os.path.abspath(filename)}")
            self.log(f"{'='*80}\n")
        except Exception as e:
            self.log(f"\n❌ Error saving log: {e}\n")
    
    def update_task_number_field(self, task_id: str):
        """Update the task number field in the GUI"""
        self.task_number_var.set(task_id)
    
    def run_api_call(self, api_method_name: str, button_name: str):
        """Run API call in a separate thread"""
        def api_thread():
            # Get current credentials
            creds = {
                'director_ip': self.director_ip_var.get(),
                'username': self.username_var.get(),
                'password': self.password_var.get(),
                'template': self.template_var.get(),
                'device': self.device_var.get(),
                'version': self.version_var.get(),
                'task_number': self.task_number_var.get(),
                'osspack_version': self.osspack_version_var.get(),
                'os_version': self.os_version_var.get(),
                'product': self.product_var.get(),
                'hide_password': self.hide_password_var.get()
            }
            
            # Create VDApiDemo instance
            vd_api = VDApiDemo(
                director_ip=creds['director_ip'],
                username=creds['username'],
                password=creds['password'],
                template_name=creds['template'],
                device_name=creds['device'],
                appliance_name=creds['device'],
                version=creds['version'],
                task_number=creds['task_number'],
                osspack_version=creds['osspack_version'],
                os_version=creds['os_version'],
                product=creds['product'],
                hide_password=creds['hide_password'],
                log_callback=self.log,
                task_number_callback=self.update_task_number_field
            )
            
            self.log(f"\n{'='*80}")
            self.log(f"🚀 Executing: {button_name}")
            self.log(f"{'='*80}\n")
            
            # Get and execute the method
            method = getattr(vd_api, api_method_name)
            method()
        
        # Run in separate thread to prevent GUI freezing
        thread = threading.Thread(target=api_thread, daemon=True)
        thread.start()


def main():
    """Main entry point"""
    root = tk.Tk()
    app = VDApiDemoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()