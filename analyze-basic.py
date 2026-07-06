#!/usr/bin/env python3
"""
Submariner Basic Diagnostic Analyzer
Automated pattern-matching analysis of Submariner diagnostics data
"""

import argparse
import glob
import ipaddress
import json
import os
import re
import subprocess
import sys
import tarfile
from datetime import datetime

import yaml


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class SubmarinerAnalyzer:
    def __init__(self, tarball_path, output_format='terminal'):
        self.tarball_path = tarball_path
        self.output_format = output_format  # 'terminal' or 'slack'
        self.diagnostics_dir = None
        self.findings = []
        self.issues = []
        self.recommendations = []
        self.faulty_states = []  # Track faulty states found
        self.tunnel_status = {}  # Store tunnel status for later analysis
        self.verify_tests_run = False  # Track if verify tests were executed
        self.verify_tests_passed = False  # Track if verify tests passed
        self.routeagent_data = {}  # Store RouteAgent analysis data
        self.network_topology = {}  # Store network topology analysis
        self.collection_errors = []  # Track collection-time errors
        self.collection_failed = False  # Flag if collection had critical errors

    def _print(self, *args, **kwargs):
        """Print only in terminal mode, suppress in slack mode"""
        if self.output_format == 'terminal':
            print(*args, **kwargs)

    def extract_tarball(self):
        """Extract tarball to temporary directory"""
        self._print(f"Extracting {self.tarball_path}...")

        if not os.path.exists(self.tarball_path):
            self._print(
                f"{Colors.FAIL}ERROR: File not found: "
                f"{self.tarball_path}{Colors.ENDC}"
            )
            return False

        try:
            with tarfile.open(self.tarball_path, 'r:gz') as tar:
                # Get the root directory name from tarball
                members = tar.getmembers()
                if not members:
                    self._print(f"{Colors.FAIL}ERROR: Empty tarball{Colors.ENDC}")
                    return False

                root_dir = members[0].name.split('/')[0]
                self.diagnostics_dir = root_dir

                # Extract if not already extracted
                if not os.path.exists(root_dir):
                    # Safe extraction using data filter (Python 3.12+)
                    import sys
                    if sys.version_info >= (3, 12):
                        tar.extractall(filter='data')  # nosec B202 - using data filter
                    else:
                        # Fallback for older Python - validate paths using commonpath
                        for member in tar.getmembers():
                            member_path = os.path.abspath(os.path.join('.', member.name))
                            try:
                                if os.path.commonpath([os.path.abspath('.'), member_path]) != os.path.abspath('.'):
                                    raise Exception(f"Attempted path traversal in tar file: {member.name}")
                            except ValueError as err:
                                # Different drives on Windows or invalid path
                                raise Exception(f"Attempted path traversal in tar file: {member.name}") from err
                        tar.extractall()  # nosec B202 - validated above
                    self._print(f"{Colors.OKGREEN}✓{Colors.ENDC} Extracted to {root_dir}/")
                else:
                    self._print(f"{Colors.OKGREEN}✓{Colors.ENDC} Using existing directory {root_dir}/")

            return True
        except Exception as e:
            self._print(f"{Colors.FAIL}ERROR: Failed to extract tarball: {e}{Colors.ENDC}")
            return False

    def read_file(self, relative_path):
        """Read file content from diagnostics directory"""
        full_path = os.path.join(self.diagnostics_dir, relative_path)
        if not os.path.exists(full_path):
            return None
        try:
            with open(full_path) as f:
                return f.read()
        except OSError:
            return None

    def read_yaml(self, relative_path):
        """Read and parse YAML file"""
        content = self.read_file(relative_path)
        if not content:
            return None
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError:
            return None

    def analyze_manifest(self):
        """Read manifest for metadata"""
        content = self.read_file("manifest.txt")
        if not content:
            return None

        manifest = {}
        for line in content.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                manifest[key.strip()] = value.strip()
        return manifest

    def detect_cni(self, cluster):
        """Detect CNI plugin from Gateway CR or summary.html"""
        # First try Gateway CR (more reliable)
        gateway_cr = self.find_and_read_gateway_cr(cluster)
        if gateway_cr and 'status' in gateway_cr:
            network_plugin = gateway_cr['status'].get('networkPlugin')
            if network_plugin:
                return network_plugin

        # Fallback to summary.html - try literal cluster path first
        summary_html = self.read_file(f"{cluster}/gather/{cluster}/summary.html")

        # If that fails, try using get_cluster_subdirs() mapping
        if not summary_html:
            cluster_subdirs = self.get_cluster_subdirs()
            actual_cluster_name = cluster_subdirs.get(cluster, cluster)
            if actual_cluster_name != cluster:
                summary_html = self.read_file(f"{cluster}/gather/{actual_cluster_name}/summary.html")
        if not summary_html:
            return "unknown"

        # Look for CNI Plugin in HTML table
        import re
        match = re.search(r'<td>CNI Plugin:</td>\s*<td>([^<]+)</td>', summary_html)
        if match:
            return match.group(1).strip()
        return "unknown"

    def detect_globalnet(self, cluster):
        """Detect if Globalnet is enabled from Submariner CR"""
        submariner_cr = self.find_and_read_gateway_cr(cluster)
        if submariner_cr and 'spec' in submariner_cr:
            return submariner_cr['spec'].get('globalCIDR', '') != ''
        return False

    def check_version_compatibility(self):
        """Check for version mismatches between subctl and Submariner"""
        manifest_content = self.read_file("manifest.txt")
        if not manifest_content:
            return

        # Extract version information from manifest
        subctl_version = None
        cluster1_version = None
        cluster2_version = None
        cluster1_version_line = None
        cluster2_version_line = None
        version_mismatch_detected = False
        different_cluster_versions = False

        for line in manifest_content.split('\n'):
            if 'subctl version:' in line:
                match = re.search(r'v([0-9]+\.[0-9]+)', line)
                if match:
                    subctl_version = match.group(1)
            elif 'Cluster1 Submariner version:' in line:
                cluster1_version_line = line
                match = re.search(r'release-([0-9]+\.[0-9]+)', line)
                if match:
                    cluster1_version = match.group(1)
            elif 'Cluster2 Submariner version:' in line:
                cluster2_version_line = line
                match = re.search(r'release-([0-9]+\.[0-9]+)', line)
                if match:
                    cluster2_version = match.group(1)
            elif 'VERSION MISMATCH DETECTED!' in line:
                version_mismatch_detected = True
            elif 'Different Submariner versions between clusters' in line:
                different_cluster_versions = True

        # Check if Submariner is not deployed (version line exists but no actual version)
        cluster1_not_deployed = cluster1_version_line and not cluster1_version
        cluster2_not_deployed = cluster2_version_line and not cluster2_version
        submariner_not_deployed = cluster1_not_deployed or cluster2_not_deployed

        # Display version information and warnings
        if submariner_not_deployed:
            # Submariner not deployed - show critical error
            self._print(f"\n{Colors.BOLD}=== Submariner Deployment Status ==={Colors.ENDC}")

            if cluster1_not_deployed:
                self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Cluster1: Submariner NOT deployed")
            else:
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Cluster1: Submariner deployed (release-{cluster1_version})")

            if cluster2_not_deployed:
                self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Cluster2: Submariner NOT deployed")
            else:
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Cluster2: Submariner deployed (release-{cluster2_version})")

            self._print(f"\n  {Colors.FAIL}{'='*60}{Colors.ENDC}")
            self._print(f"  {Colors.FAIL}CRITICAL: Submariner not deployed on one or both clusters{Colors.ENDC}")
            self._print(f"  {Colors.FAIL}{'='*60}{Colors.ENDC}")
            self._print(f"  {Colors.WARNING}This diagnostic analysis is NOT valid because Submariner{Colors.ENDC}")
            self._print(f"  {Colors.WARNING}components are not running on the cluster(s).{Colors.ENDC}")
            self._print("")
            self._print(f"  {Colors.BOLD}Action required:{Colors.ENDC}")
            self._print("    Deploy Submariner on both clusters first, then re-collect diagnostics.")
            self._print("")
            self._print(f"  {Colors.BOLD}Deployment guide:{Colors.ENDC}")
            self._print("    https://submariner.io/getting-started/")
            self._print(f"  {Colors.FAIL}{'='*60}{Colors.ENDC}")

            self.faulty_states.append("Submariner not deployed on one or both clusters")
            self.recommendations.append("Deploy Submariner on all clusters before collecting diagnostics")

        elif subctl_version or cluster1_version or cluster2_version:
            self._print(f"\n{Colors.BOLD}=== Version Compatibility ==={Colors.ENDC}")
            if subctl_version:
                self._print(f"  subctl version: v{subctl_version}")
            if cluster1_version:
                self._print(f"  Cluster1 Submariner: release-{cluster1_version}")
            if cluster2_version:
                self._print(f"  Cluster2 Submariner: release-{cluster2_version}")

            # Check for mismatches
            if version_mismatch_detected:
                self.faulty_states.append("Version mismatch: subctl and Submariner versions don't match")
                self._print(f"\n  {Colors.FAIL}✗ VERSION MISMATCH DETECTED{Colors.ENDC}")

                if subctl_version and cluster1_version and subctl_version != cluster1_version:
                    self._print(f"    Cluster1: subctl v{subctl_version} vs Submariner release-{cluster1_version}")
                    self.recommendations.append(f"Update subctl to version v{cluster1_version} to match Submariner deployment")

                if subctl_version and cluster2_version and subctl_version != cluster2_version:
                    self._print(f"    Cluster2: subctl v{subctl_version} vs Submariner release-{cluster2_version}")
                    if not (subctl_version and cluster1_version and subctl_version != cluster1_version):
                        self.recommendations.append(f"Update subctl to version v{cluster2_version} to match Submariner deployment")

                self.recommendations.append("Version mismatches can cause unexpected behavior and test failures")

                # Display prominent warning about incorrect results
                self._print(f"\n  {Colors.FAIL}{'='*60}{Colors.ENDC}")
                self._print(f"  {Colors.FAIL}WARNING: Version mismatch could lead to INCORRECT RESULTS{Colors.ENDC}")
                self._print(f"  {Colors.FAIL}{'='*60}{Colors.ENDC}")
                self._print(f"  {Colors.WARNING}The diagnostic analysis below may be misleading or inaccurate due to{Colors.ENDC}")
                self._print(f"  {Colors.WARNING}incompatibility between subctl CLI and deployed Submariner components.{Colors.ENDC}")
                self._print(f"  {Colors.WARNING}Recommend fixing version mismatch before trusting analysis results.{Colors.ENDC}")
                self._print(f"  {Colors.FAIL}{'='*60}{Colors.ENDC}")

            if different_cluster_versions:
                self.faulty_states.append("Different Submariner versions between clusters")
                self._print(f"\n  {Colors.WARNING}⚠ Different Submariner versions between clusters{Colors.ENDC}")
                self._print(f"    Cluster1: release-{cluster1_version}")
                self._print(f"    Cluster2: release-{cluster2_version}")
                self._print("    This is NOT recommended and may cause compatibility issues")
                self.recommendations.append("Update both clusters to use the same Submariner version")

                # Display warning about potential issues
                self._print(f"\n  {Colors.WARNING}{'='*60}{Colors.ENDC}")
                self._print(f"  {Colors.WARNING}WARNING: Different cluster versions may cause issues{Colors.ENDC}")
                self._print(f"  {Colors.WARNING}{'='*60}{Colors.ENDC}")
                self._print(f"  {Colors.WARNING}Running different Submariner versions between clusters is NOT{Colors.ENDC}")
                self._print(f"  {Colors.WARNING}recommended and may lead to tunnel negotiation or compatibility issues.{Colors.ENDC}")
                self._print(f"  {Colors.WARNING}{'='*60}{Colors.ENDC}")

            if not version_mismatch_detected and not different_cluster_versions:
                if cluster1_version and cluster2_version and cluster1_version == cluster2_version:
                    if subctl_version and subctl_version == cluster1_version:
                        self._print(f"  {Colors.OKGREEN}✓ All versions compatible (v{subctl_version}){Colors.ENDC}")

    def check_context_name_handling(self):
        """Check if context names were overlapping and renamed"""
        manifest_content = self.read_file("manifest.txt")
        if not manifest_content:
            return

        # Look for context name handling section
        if "Context Name Handling:" in manifest_content:
            self._print(f"\n{Colors.BOLD}=== Context Name Handling (Informational) ==={Colors.ENDC}")

            # Extract relevant information
            original_cluster1_context = None
            original_cluster2_context = None
            renamed_cluster1_context = None

            for line in manifest_content.split('\n'):
                if 'Original cluster1 context:' in line:
                    original_cluster1_context = line.split(':', 1)[1].strip()
                elif 'Original cluster2 context:' in line:
                    original_cluster2_context = line.split(':', 1)[1].strip()
                elif 'Renamed cluster1 context:' in line:
                    renamed_cluster1_context = line.split(':', 1)[1].strip()

            if original_cluster1_context and original_cluster2_context and original_cluster1_context == original_cluster2_context:
                self._print(f"  {Colors.OKCYAN}ℹ{Colors.ENDC} {Colors.BOLD}HEADS-UP:{Colors.ENDC} Identical context names detected in both kubeconfig files")
                self._print(f"    Both clusters use context name: '{original_cluster1_context}'")
                self._print("")
                self._print(f"  {Colors.BOLD}What this means:{Colors.ENDC}")
                self._print("    • This is NOT a fault with your Submariner deployment")
                self._print("    • However, subctl commands that require 2 contexts might fail, such as:")
                self._print(f"      {Colors.OKCYAN}subctl verify --context <cluster1> --tocontext <cluster2>{Colors.ENDC}")
                self._print(f"      {Colors.OKCYAN}subctl diagnose firewall inter-cluster --context <c1> --remotecontext <c2>{Colors.ENDC}")
                self._print("")
                self._print(f"  {Colors.BOLD}How the collection handled it:{Colors.ENDC}")
                self._print(f"    • Auto-renamed cluster1 context to: '{renamed_cluster1_context}'")
                self._print("    • Used renamed context for all subctl commands during collection")
                self._print("    • Original kubeconfig files remain unchanged")
                self._print("")
                self._print(f"  {Colors.BOLD}If you need to run manual subctl commands:{Colors.ENDC}")
                self._print("    You must rename the context in one of your kubeconfig files:")
                self._print("")
                self._print(f"    {Colors.OKCYAN}# Backup your kubeconfig{Colors.ENDC}")
                self._print("    cp /path/to/kubeconfig /path/to/kubeconfig.backup")
                self._print("")
                self._print(f"    {Colors.OKCYAN}# Rename context{Colors.ENDC}")
                self._print(f"    kubectl config rename-context {original_cluster1_context} cluster1 --kubeconfig=/path/to/kubeconfig")
                self._print("")
                self._print(f"    {Colors.OKCYAN}# Verify{Colors.ENDC}")
                self._print("    kubectl config get-contexts --kubeconfig=/path/to/kubeconfig")

                # Add to recommendations for the final summary
                self.recommendations.append(
                    f"To run manual subctl commands with 2 contexts, rename '{original_cluster1_context}' "
                    f"to unique names in your kubeconfig files (e.g., 'cluster1' and 'cluster2')"
                )

    def check_faulty_states(self):
        """Check for faulty states before starting deep analysis"""
        self._print(f"\n{Colors.BOLD}=== Checking for Faulty States ==={Colors.ENDC}")

        # Check version compatibility first
        self.check_version_compatibility()

        # Check for context name handling
        self.check_context_name_handling()

        # Check tunnel status
        cluster1_show = self.read_file("cluster1/subctl-show-all.txt")
        cluster2_show = self.read_file("cluster2/subctl-show-all.txt")

        if cluster1_show and cluster2_show:
            status1 = self.extract_tunnel_status(cluster1_show, "cluster1")
            status2 = self.extract_tunnel_status(cluster2_show, "cluster2")

            if status1 and status2:
                self.tunnel_status = {
                    'cluster1': status1,
                    'cluster2': status2
                }

                if status1['status'] != 'connected':
                    self.faulty_states.append(f"Cluster1 tunnel: {status1['status']}")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Cluster1 → Cluster2: {status1['status']}")
                else:
                    self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Cluster1 → Cluster2: connected")

                if status2['status'] != 'connected':
                    self.faulty_states.append(f"Cluster2 tunnel: {status2['status']}")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Cluster2 → Cluster1: {status2['status']}")
                else:
                    self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Cluster2 → Cluster1: connected")

        # Check verify tests
        self.check_verify_tests()

        # Check firewall diagnostics
        self.check_firewall_diagnostics()

        # CRITICAL: Check Gateway HA labels early (can cause tunnel issues)
        self.check_gateway_ha_labels_early()

        if not self.faulty_states:
            self._print(f"\n{Colors.OKGREEN}✓ No faulty states detected - Submariner deployment appears healthy{Colors.ENDC}")
            return False
        else:
            self._print(f"\n{Colors.WARNING}Found {len(self.faulty_states)} faulty state(s) - starting deep analysis...{Colors.ENDC}")
            return True

    def check_verify_tests(self):
        """Check subctl verify test results"""
        verify_dir = os.path.join(self.diagnostics_dir, "verify")
        if not os.path.exists(verify_dir):
            return

        connectivity_passed = False
        connectivity_failed = False
        small_packet_passed = False
        small_packet_failed = False
        svc_discovery_passed = False
        tests_found = False

        # Check connectivity tests
        connectivity = self.read_file("verify/connectivity.txt")
        if connectivity and "SKIPPED" not in connectivity:
            tests_found = True
            self.verify_tests_run = True

            # Check if tests were stopped early
            early_stop_match = re.search(r'stopped early after (\d+) consecutive test failures', connectivity)

            # Check for Ginkgo test output (SUCCESS! or failures)
            # Look for pattern like "SUCCESS! -- X Passed | 0 Failed" or "X Failed"
            if "SUCCESS!" in connectivity or (re.search(r'\d+\s+Passed.*0\s+Failed', connectivity)):
                connectivity_passed = True
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Connectivity verification: PASSED")
            elif re.search(r'[1-9]\d*\s+Failed', connectivity) or "FAILURE" in connectivity:
                connectivity_failed = True
                if early_stop_match:
                    num_tests = early_stop_match.group(1)
                    self.faulty_states.append(f"Connectivity verification failed (stopped early after {num_tests} failures)")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Connectivity verification: FAILED (stopped early after {num_tests} failures)")
                else:
                    self.faulty_states.append("Connectivity verification failed")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Connectivity verification: FAILED")
            else:
                # Fallback for older format or errors
                if "FAIL" in connectivity or "error" in connectivity.lower():
                    connectivity_failed = True
                    if early_stop_match:
                        num_tests = early_stop_match.group(1)
                        self.faulty_states.append(f"Connectivity verification failed (stopped early after {num_tests} failures)")
                        self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Connectivity verification: FAILED (stopped early after {num_tests} failures)")
                    else:
                        self.faulty_states.append("Connectivity verification failed")
                        self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Connectivity verification: FAILED")
                elif "PASS" in connectivity:
                    connectivity_passed = True
                    self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Connectivity verification: PASSED")
                else:
                    # Test file exists but no clear result
                    connectivity_failed = True
                    self.faulty_states.append("Connectivity verification inconclusive")
                    self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} Connectivity verification: INCONCLUSIVE")

        # Check small packet tests (MTU testing)
        small_packet = self.read_file("verify/connectivity-small-packet.txt")
        if small_packet and "SMALL PACKET TEST SKIPPED" in small_packet:
            # Check why it was skipped
            if "regular connectivity test passed" in small_packet.lower():
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Small packet verification: SKIPPED (regular test passed, no MTU issue)")
            else:
                self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} Small packet verification: SKIPPED")
        elif small_packet and "SKIPPED" not in small_packet:
            tests_found = True
            self.verify_tests_run = True

            # Check if tests were stopped early
            early_stop_match = re.search(r'stopped early after (\d+) consecutive test failures', small_packet)

            # Check for Ginkgo test output (SUCCESS! or failures)
            if "SUCCESS!" in small_packet or (re.search(r'\d+\s+Passed.*0\s+Failed', small_packet)):
                small_packet_passed = True
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Small packet verification: PASSED")
            elif re.search(r'[1-9]\d*\s+Failed', small_packet) or "FAILURE" in small_packet:
                small_packet_failed = True
                if early_stop_match:
                    num_tests = early_stop_match.group(1)
                    self.faulty_states.append(f"Small packet verification failed (stopped early after {num_tests} failures)")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Small packet verification: FAILED (stopped early after {num_tests} failures)")
                else:
                    self.faulty_states.append("Small packet verification failed")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Small packet verification: FAILED")
            else:
                # Fallback for older format or errors
                if "FAIL" in small_packet or "error" in small_packet.lower():
                    small_packet_failed = True
                    if early_stop_match:
                        num_tests = early_stop_match.group(1)
                        self.faulty_states.append(f"Small packet verification failed (stopped early after {num_tests} failures)")
                        self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Small packet verification: FAILED (stopped early after {num_tests} failures)")
                    else:
                        self.faulty_states.append("Small packet verification failed")
                        self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Small packet verification: FAILED")
                elif "PASS" in small_packet:
                    small_packet_passed = True
                    self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Small packet verification: PASSED")
                else:
                    # Test file exists but no clear result
                    small_packet_failed = True
                    self.faulty_states.append("Small packet verification inconclusive")
                    self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} Small packet verification: INCONCLUSIVE")

        # Check for MTU issue pattern: regular packets fail, small packets pass
        if connectivity_failed and small_packet_passed:
            self._print(f"\n  {Colors.FAIL}✗ MTU ISSUE DETECTED:{Colors.ENDC}")
            self._print("    Regular packets (default size): FAILED")
            self._print("    Small packets (400 bytes): PASSED")
            self._print("    → This indicates an MTU/fragmentation issue caused by Submariner's encapsulation overhead")
            self.faulty_states.append("MTU issue detected (regular packets fail, small packets pass)")
            self.issues.append("MTU/fragmentation issue preventing large packet transmission")
            self.recommendations.insert(0, "Apply TCP MSS clamping: kubectl annotate node <gateway-node> submariner.io/tcp-clamp-mss=<mss-clamp-value>")
            self.recommendations.insert(1, "Restart routeagent pods to apply the changes: kubectl delete pod -n submariner-operator -l app=submariner-routeagent")
            self.recommendations.insert(2, "Recommended MSS value: 1300 (conservative value for most networks)")
            self.recommendations.insert(3, "See official documentation: https://submariner.io/getting-started/architecture/gateway-engine/ (Customize TCP MSS Clamping)")

        # Check service discovery
        svc_discovery = self.read_file("verify/service-discovery.txt")
        if svc_discovery and "SKIPPED" not in svc_discovery:
            tests_found = True
            self.verify_tests_run = True

            # Check if tests were stopped early
            early_stop_match = re.search(r'stopped early after (\d+) consecutive test failures', svc_discovery)

            # Check for Ginkgo test output (SUCCESS! or failures)
            if "SUCCESS!" in svc_discovery or (re.search(r'\d+\s+Passed.*0\s+Failed', svc_discovery)):
                svc_discovery_passed = True
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Service discovery verification: PASSED")
            elif re.search(r'[1-9]\d*\s+Failed', svc_discovery) or "FAILURE" in svc_discovery:
                if early_stop_match:
                    num_tests = early_stop_match.group(1)
                    self.faulty_states.append(f"Service discovery verification failed (stopped early after {num_tests} failures)")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Service discovery verification: FAILED (stopped early after {num_tests} failures)")
                else:
                    self.faulty_states.append("Service discovery verification failed")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Service discovery verification: FAILED")
            else:
                # Fallback for older format or errors
                if "FAIL" in svc_discovery or "error" in svc_discovery.lower():
                    if early_stop_match:
                        num_tests = early_stop_match.group(1)
                        self.faulty_states.append(f"Service discovery verification failed (stopped early after {num_tests} failures)")
                        self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Service discovery verification: FAILED (stopped early after {num_tests} failures)")
                    else:
                        self.faulty_states.append("Service discovery verification failed")
                        self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Service discovery verification: FAILED")
                elif "PASS" in svc_discovery:
                    svc_discovery_passed = True
                    self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Service discovery verification: PASSED")
                else:
                    # Test file exists but no clear result
                    self.faulty_states.append("Service discovery verification inconclusive")
                    self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} Service discovery verification: INCONCLUSIVE")

        # Check for OVNK SNAT issue pattern
        # Diagnostic workflow:
        # 1. Regular connectivity fails
        # 2. Small packet size also fails (ruling out MTU issue)
        # 3. CNI is OVN-Kubernetes
        # 4. Tests with --skip-src-ip-check pass
        # This pattern indicates the known OVNK SNAT bug affecting Submariner
        skip_src_ip_check = self.read_file("verify/connectivity-skip-src-ip-check.txt")
        if skip_src_ip_check:
            skip_src_ip_passed = False

            # Check if skip-src-ip-check test passed
            if "SUCCESS!" in skip_src_ip_check or (re.search(r'\d+\s+Passed.*0\s+Failed', skip_src_ip_check)):
                skip_src_ip_passed = True
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Connectivity with --skip-src-ip-check: PASSED")
            elif re.search(r'[1-9]\d*\s+Failed', skip_src_ip_check) or "FAILURE" in skip_src_ip_check or "FAIL" in skip_src_ip_check:
                self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Connectivity with --skip-src-ip-check: FAILED")

            # Detect OVNK SNAT issue:
            # - Regular connectivity failed
            # - Small packet test also failed (not MTU issue)
            # - CNI is OVN-Kubernetes
            # - skip-src-ip-check passed
            if connectivity_failed and skip_src_ip_passed:
                # Detect CNI to confirm OVNK
                cni_cluster1 = self.detect_cni("cluster1")
                cni_cluster2 = self.detect_cni("cluster2")

                # Check if either cluster uses OVNK
                is_ovnk = (cni_cluster1 == "OVNKubernetes" or cni_cluster2 == "OVNKubernetes")

                # Check if small packet test also failed (not MTU issue)
                # If small packet passed, it's an MTU issue (already handled above)
                # If small packet also failed, and OVNK is in use, this could be the SNAT issue
                is_not_mtu_issue = small_packet_failed or not small_packet_passed

                if is_ovnk and is_not_mtu_issue:
                    self._print(f"\n  {Colors.FAIL}✗ KNOWN OVNK SNAT ISSUE DETECTED:{Colors.ENDC}")
                    self._print("    Regular connectivity tests: FAILED")
                    self._print("    Small packet tests: FAILED (not MTU issue)")
                    self._print("    Connectivity with --skip-src-ip-check: PASSED")
                    self._print(f"    CNI detected: Cluster1={cni_cluster1}, Cluster2={cni_cluster2}")
                    self._print("    → This pattern indicates a known OVNK SNAT bug affecting Submariner")
                    self.faulty_states.append("Known OVNK SNAT issue detected (connectivity fails, --skip-src-ip-check passes)")
                    self.issues.append(f"OVNK CNI SNAT bug prevents Submariner connectivity (CNI: {cni_cluster1}/{cni_cluster2})")
                    self.recommendations.insert(0, "Issue could be related to this known issue:")
                    self.recommendations.insert(1, "https://github.com/submariner-io/submariner/issues/3307#issuecomment-2653220140")
                    self.recommendations.insert(2, "Check if your OVNK/OpenShift version includes the fix for this known issue")
                    self.recommendations.insert(3, "For assistance, reach out to the Submariner community on Slack (#submariner-users) or file an issue at github.com/submariner-io/submariner")
                elif not is_not_mtu_issue:
                    # Small packet passed but regular failed - this is MTU (already handled)
                    # Skip additional OVNK reporting
                    pass
                else:
                    # OVNK not detected but skip-src-ip-check helped
                    self._print(f"\n  {Colors.WARNING}⚠ Source IP verification issue detected:{Colors.ENDC}")
                    self._print("    Regular connectivity tests: FAILED")
                    self._print("    Connectivity with --skip-src-ip-check: PASSED")
                    self._print(f"    CNI detected: Cluster1={cni_cluster1}, Cluster2={cni_cluster2}")
                    self._print("    → Source IP verification is failing, but not using OVNK")
                    self.faulty_states.append("Source IP verification issue (connectivity fails, --skip-src-ip-check passes)")
                    self.issues.append("Source IP is being modified during packet transit")
                    self.recommendations.append("Investigate NAT or source IP rewriting between clusters")

        # Set verify_tests_passed only if ALL tests that ran passed
        if tests_found:
            # All tests must pass for verify_tests_passed to be True
            all_passed = True
            if connectivity and "SKIPPED" not in connectivity and not connectivity_passed:
                all_passed = False
            if small_packet and "SKIPPED" not in small_packet and not small_packet_passed:
                all_passed = False
            if svc_discovery and "SKIPPED" not in svc_discovery and not svc_discovery_passed:
                all_passed = False

            self.verify_tests_passed = all_passed

    def check_firewall_diagnostics(self):
        """
        Check firewall diagnostics results (inter-cluster and intra-cluster)

        Inter-cluster: Only runs when at least one tunnel is NOT connected AND using UDP encapsulation (VxLAN or IPSec NAT-T)
        Intra-cluster: Only runs when CNI is NOT OVN-Kubernetes (checked per cluster)

        Also cross-references:
        - tcpdump data (for UDP traffic patterns)
        - IPsec counters from gather data (for IPsec tunnel analysis)
        """
        firewall_dir = os.path.join(self.diagnostics_dir, "firewall")
        if not os.path.exists(firewall_dir):
            return


        # Detect NAT-T port from Submariner CR (default 4500)
        natt_port = 4500  # default
        submariner_yaml = self.read_yaml("cluster1/gather/cluster1/submariners_submariner-operator_submariner.yaml")
        if submariner_yaml and 'spec' in submariner_yaml and 'ceIPSecNATTPort' in submariner_yaml['spec']:
            natt_port = submariner_yaml['spec']['ceIPSecNATTPort']

        # Check inter-cluster firewall diagnostics
        # Prerequisites: At least one tunnel NOT connected + UDP encapsulation (VxLAN or IPSec NAT-T)
        inter_cluster = self.read_file("firewall/firewall-inter-cluster.txt")
        if inter_cluster:
            self._print(f"\n{Colors.BOLD}=== Firewall Inter-Cluster Diagnostics ==={Colors.ENDC}")
            self._print("  Prerequisites: Tunnel not connected + UDP encapsulation (VxLAN/IPSec NAT-T)")

            # Check for successful completion
            if "Tunnels can be established" in inter_cluster and "✓" in inter_cluster:
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Inter-cluster firewall: PASSED")
                self._print("    UDP ports are open - firewall is NOT blocking tunnel traffic")
                self.recommendations.append("Firewall is OK - investigate other tunnel issues: routing, IPsec config, or endpoint reachability")

                # Cross-reference with IPsec counters if available
                self.recommendations.append("Check IPsec counters in gather data (ipsec-trafficstatus.log) to verify traffic flow")
            elif "CONTEXT: This test was run because:" in inter_cluster:
                # Test ran - check for failures
                if "error" in inter_cluster.lower() or "fail" in inter_cluster.lower() or "cannot" in inter_cluster.lower() or "timed out" in inter_cluster.lower():
                    self.faulty_states.append("Inter-cluster firewall blocking UDP traffic")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Inter-cluster firewall: FAILED")
                    self._print("    UDP ports blocked by firewall/security groups")

                    # Cross-reference with tcpdump data
                    tcpdump_dir = os.path.join(self.diagnostics_dir, "tcpdump")
                    if os.path.exists(tcpdump_dir):
                        self._print(f"    {Colors.WARNING}Additional data:{Colors.ENDC} Check tcpdump/ for UDP traffic patterns")
                        self._print(f"      - Look for outbound UDP packets on port {natt_port} (NAT-T)")
                        self._print("      - Check if UDP packets are egressing but not ingressing")

                    # Reference IPsec counters
                    self._print(f"    {Colors.WARNING}Additional data:{Colors.ENDC} Check IPsec counters in gather/")
                    self._print("      - cluster*/gather/cluster*/ipsec-trafficstatus.log")
                    self._print("      - Look for 0 bytes in/out indicating no traffic flow")

                    self.recommendations.append(f"Fix inter-cluster firewall: allow UDP traffic on NAT-T port {natt_port} between gateway nodes")
                    self.recommendations.append("Cloud environments: Check security group rules between gateway node IPs")
                    self.recommendations.append(f"On-premise: Verify firewall allows UDP {natt_port} or ESP (protocol 50) depending on cable driver config")
                    self.recommendations.append(f"Cross-check tcpdump data: verify UDP packets on port {natt_port} are flowing in both directions")
                    self.recommendations.append("Check IPsec traffic counters: ipsec-trafficstatus.log should show non-zero bytes if traffic flowing")

                    # Extract specific error
                    error_match = re.search(r'(error|Error|ERROR|FAILED|timeout)[^\n]*', inter_cluster)
                    if error_match:
                        self._print(f"    Error: {error_match.group(0)}")
                else:
                    self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Inter-cluster firewall: PASSED")
                    self.recommendations.append("Firewall OK - check other tunnel issues (routing, IPsec, endpoints)")
                    self.recommendations.append("Verify IPsec counters in ipsec-trafficstatus.log show traffic flowing")

        # Check intra-cluster firewall diagnostics for cluster1
        # Prerequisites: CNI is NOT OVN-Kubernetes
        # Expected symptoms if failed: RouteAgent failures + verify test failures from non-gateway pods
        intra_cluster1 = self.read_file("firewall/firewall-intra-cluster-cluster1.txt")
        if intra_cluster1:
            self._print(f"\n{Colors.BOLD}=== Firewall Intra-Cluster Diagnostics (Cluster1) ==={Colors.ENDC}")
            self._print("  Prerequisites: CNI is NOT OVN-Kubernetes")

            # Check for successful completion
            if "firewall configuration allows intra-cluster VXLAN traffic" in intra_cluster1 and "✓" in intra_cluster1:
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Intra-cluster firewall (cluster1): PASSED")

                # Check tcpdump packet count
                packet_match = re.search(r'(\d+)\s+packets captured', intra_cluster1)
                if packet_match:
                    packet_count = int(packet_match.group(1))
                    if packet_count > 0:
                        self._print(f"    {packet_count} packets on vx-submariner - VXLAN traffic flowing")
                    else:
                        self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} 0 packets captured (might be low traffic, not necessarily firewall issue)")
            elif "CONTEXT: This test was run because:" in intra_cluster1:
                # Test ran - check for failures
                if "error" in intra_cluster1.lower() or "fail" in intra_cluster1.lower():
                    self.faulty_states.append("Intra-cluster firewall blocking VXLAN on cluster1")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Intra-cluster firewall (cluster1): FAILED")
                    self._print("    VXLAN traffic blocked on vx-submariner interface")
                    self._print(f"    {Colors.WARNING}Expected symptoms:{Colors.ENDC}")
                    self._print("      • RouteAgent failures on cluster1")
                    self._print("      • subctl verify tests fail when pods scheduled on non-gateway nodes")
                    self.recommendations.append("Fix intra-cluster firewall on cluster1: allow VXLAN traffic on vx-submariner interface")
                    self.recommendations.append("Verify RouteAgent status on cluster1")
                    self.recommendations.append("Check verify tests: failures from non-gateway pods indicate intra-cluster firewall issues")

        # Check intra-cluster firewall diagnostics for cluster2
        # Prerequisites: CNI is NOT OVN-Kubernetes
        intra_cluster2 = self.read_file("firewall/firewall-intra-cluster-cluster2.txt")
        if intra_cluster2:
            self._print(f"\n{Colors.BOLD}=== Firewall Intra-Cluster Diagnostics (Cluster2) ==={Colors.ENDC}")
            self._print("  Prerequisites: CNI is NOT OVN-Kubernetes")

            # Check for successful completion
            if "firewall configuration allows intra-cluster VXLAN traffic" in intra_cluster2 and "✓" in intra_cluster2:
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Intra-cluster firewall (cluster2): PASSED")

                # Check tcpdump packet count
                packet_match = re.search(r'(\d+)\s+packets captured', intra_cluster2)
                if packet_match:
                    packet_count = int(packet_match.group(1))
                    if packet_count > 0:
                        self._print(f"    {packet_count} packets on vx-submariner - VXLAN traffic flowing")
                    else:
                        self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} 0 packets captured (might be low traffic, not necessarily firewall issue)")
            elif "CONTEXT: This test was run because:" in intra_cluster2:
                # Test ran - check for failures
                if "error" in intra_cluster2.lower() or "fail" in intra_cluster2.lower():
                    self.faulty_states.append("Intra-cluster firewall blocking VXLAN on cluster2")
                    self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Intra-cluster firewall (cluster2): FAILED")
                    self._print("    VXLAN traffic blocked on vx-submariner interface")
                    self._print(f"    {Colors.WARNING}Expected symptoms:{Colors.ENDC}")
                    self._print("      • RouteAgent failures on cluster2")
                    self._print("      • subctl verify tests fail when pods scheduled on non-gateway nodes")
                    self.recommendations.append("Fix intra-cluster firewall on cluster2: allow VXLAN traffic on vx-submariner interface")
                    self.recommendations.append("Verify RouteAgent status on cluster2")
                    self.recommendations.append("Check verify tests: failures from non-gateway pods indicate intra-cluster firewall issues")

    def analyze_tunnel_status(self):
        """Analyze tunnel connectivity status in detail"""
        self._print(f"\n{Colors.BOLD}=== Analyzing Tunnel Status ==={Colors.ENDC}")

        if not self.tunnel_status:
            cluster1_show = self.read_file("cluster1/subctl-show-all.txt")
            cluster2_show = self.read_file("cluster2/subctl-show-all.txt")

            if not cluster1_show or not cluster2_show:
                self.issues.append("Missing subctl show output files")
                return

            # Parse tunnel status from cluster1
            status1 = self.extract_tunnel_status(cluster1_show, "cluster1")
            status2 = self.extract_tunnel_status(cluster2_show, "cluster2")

            if not status1 or not status2:
                self.issues.append("Could not parse tunnel status")
                return

            self.tunnel_status = {
                'cluster1': status1,
                'cluster2': status2
            }

        status1 = self.tunnel_status['cluster1']
        status2 = self.tunnel_status['cluster2']

        self._print(f"  Cluster1 → Cluster2: {self.colorize_status(status1['status'])}")
        self._print(f"  Cluster2 → Cluster1: {self.colorize_status(status2['status'])}")

        self.findings.append(f"Cluster1 status: {status1['status']}")
        self.findings.append(f"Cluster2 status: {status2['status']}")

        # Analyze tunnel issues
        if status1['status'] == 'connected' and status2['status'] == 'connected':
            self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Tunnels connected on both clusters")
        else:
            # Check for asymmetric tunnel status (one connected, one not)
            if (status1['status'] == 'connected' and status2['status'] != 'connected') or \
               (status2['status'] == 'connected' and status1['status'] != 'connected'):
                # Detect CNI to provide more specific guidance
                cni_cluster1 = self.detect_cni("cluster1")
                cni_cluster2 = self.detect_cni("cluster2")
                is_ovnk = ("OVNKubernetes" in [cni_cluster1, cni_cluster2])

                # Determine which cluster is degraded and its actual status
                degraded_cluster = "Cluster1" if status1['status'] != 'connected' else "Cluster2"
                degraded_status = status1['status'] if status1['status'] != 'connected' else status2['status']

                self._print(f"\n  {Colors.WARNING}⚠ ASYMMETRIC TUNNEL STATUS DETECTED{Colors.ENDC}")
                self._print(f"    One tunnel shows 'connected' while {degraded_cluster} shows '{degraded_status}'")
                self._print(f"    CNI detected: Cluster1={cni_cluster1}, Cluster2={cni_cluster2}")
                self._print("    This pattern could indicate:")

                if is_ovnk:
                    self._print("      • SNAT issues affecting health check packets (OVN-K local gateway mode is known to cause this)")
                    self._print("      • Routing issues on one cluster's gateway node")
                    self._print("      • Firewall/infrastructure blocking traffic asymmetrically (less likely)")
                else:
                    self._print("      • Routing issues on one cluster's gateway node")
                    self._print("      • Firewall/infrastructure blocking traffic asymmetrically")
                    self._print("      • CNI configuration differences between clusters")

                self.issues.append("Asymmetric tunnel status - one connected, one not (possible SNAT/routing/firewall issue)")

                if is_ovnk:
                    self.recommendations.append(f"Worth checking for SNAT issues: Review nftables/iptables masquerade rules on {degraded_cluster} (status: {degraded_status}; OVN-K local gateway mode can cause SNAT issues)")
                else:
                    self.recommendations.append(f"Check for routing issues: Review routing configuration on {degraded_cluster} (status: {degraded_status})")

                self.recommendations.append(f"Check for firewall issues: Verify return traffic is allowed from {degraded_cluster} (status: {degraded_status})")

                # Only recommend reviewing skip-src-ip-check results if they exist
                if self.read_file("verify/connectivity-skip-src-ip-check.txt"):
                    self.recommendations.append("Review connectivity verification results with --skip-src-ip-check flag")
                elif is_ovnk:
                    self.recommendations.append("Consider rerunning connectivity verification with --skip-src-ip-check to confirm whether source-IP rewriting is involved")

            if status1['status'] != 'connected':
                self.issues.append(f"Cluster1 tunnel status: {status1['status']}")
            if status2['status'] != 'connected':
                self.issues.append(f"Cluster2 tunnel status: {status2['status']}")

            # Detect blocking type
            self.detect_blocking_type()

    def extract_tunnel_status(self, show_output, cluster_name):
        """Extract tunnel status from subctl show output"""
        lines = show_output.split('\n')
        for i, line in enumerate(lines):
            if 'Showing Connections' in line:
                # Look for the connection line (skip header)
                for j in range(i+1, min(i+5, len(lines))):
                    if lines[j].strip() and not lines[j].startswith('GATEWAY'):
                        parts = lines[j].split()
                        if len(parts) >= 7:
                            return {
                                'gateway': parts[0],
                                'cluster': parts[1],
                                'remote_ip': parts[2],
                                'nat': parts[3],
                                'cable_driver': parts[4],
                                'status': parts[-2]  # Second to last field is STATUS
                            }
        return None

    def detect_blocking_type(self):
        """Detect if ESP or UDP is being blocked"""
        self._print(f"\n{Colors.BOLD}=== Detecting Blocking Type ==={Colors.ENDC}")

        # Read Gateway CRs
        gateway1 = self.find_and_read_gateway_cr("cluster1")
        gateway2 = self.find_and_read_gateway_cr("cluster2")

        if not gateway1 and not gateway2:
            self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} Could not read Gateway CRs")
            self._print("     Possible cause: subctl gather failed (check collection.log for details)")
            return

        # Analyze cluster1
        if gateway1:
            self.analyze_gateway_blocking(gateway1, "cluster1")

        # Analyze cluster2
        if gateway2:
            self.analyze_gateway_blocking(gateway2, "cluster2")

    def check_collection_errors(self):
        """Check collection.log for critical errors that prevented data collection"""
        collection_log_path = os.path.join(self.diagnostics_dir, "collection.log")
        if not os.path.exists(collection_log_path):
            return  # No collection.log (old diagnostic format)

        collection_log = self.read_file("collection.log")
        if not collection_log:
            return

        errors_found = []

        # Check for subctl gather failures
        if "Error creating directory" in collection_log and "Nom de répertoire non valide" in collection_log:
            errors_found.append("subctl gather failed: Invalid directory name (Windows path issue with colons)")
            errors_found.append("  → Context names with colons (:) cause errors on Windows")
            errors_found.append("  → Re-collect from Linux, or use context names without special characters")
        elif "Error creating directory" in collection_log:
            errors_found.append("subctl gather failed: Error creating directory")

        # Check for tcpdump collection failures
        if "Failed to deploy tcpdump DaemonSet" in collection_log:
            errors_found.append("tcpdump collection failed: Could not deploy DaemonSet")
        if "tcpdump pod not found" in collection_log:
            errors_found.append("tcpdump collection failed: Pod not found on gateway node")
        if "Failed to extract files" in collection_log:
            errors_found.append("tcpdump collection failed: Could not extract pcap/analysis files")

        # Check for pod readiness timeouts
        if "Pod did not become ready within 30s" in collection_log:
            errors_found.append("tcpdump pod readiness timeout (may indicate image pull or scheduling issues)")

        if errors_found:
            # Store errors in state
            self.collection_errors = errors_found
            self.collection_failed = True

            self._print(f"\n{Colors.FAIL}{'='*60}{Colors.ENDC}")
            self._print(f"{Colors.FAIL}⚠ DATA COLLECTION ERRORS DETECTED{Colors.ENDC}")
            self._print(f"{Colors.FAIL}{'='*60}{Colors.ENDC}")
            self._print(f"\n{Colors.WARNING}The following errors occurred during data collection:{Colors.ENDC}\n")
            for error in errors_found:
                self._print(f"  • {error}")
            self._print(f"\n{Colors.WARNING}Analysis results may be incomplete or inaccurate.{Colors.ENDC}")
            self._print(f"{Colors.WARNING}Check collection.log for full details.{Colors.ENDC}")
            self._print(f"{Colors.FAIL}{'='*60}{Colors.ENDC}\n")

    def find_and_read_gateway_cr(self, cluster):
        """Find and read the Gateway CR YAML"""
        gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather")
        if not os.path.exists(gather_dir):
            return None

        # Navigate through nested subdirectories (can be cluster/gather/name/k8s-id/)
        current_dir = gather_dir
        depth = 0

        while depth < 4:
            all_files = os.listdir(current_dir)

            # Look for submariner CR YAML in current directory
            for file in all_files:
                if file.startswith("submariners_") and file.endswith(".yaml"):
                    relative_path = os.path.relpath(os.path.join(current_dir, file), self.diagnostics_dir)
                    return self.read_yaml(relative_path)

            # If not found, go deeper
            subdirs = [d for d in all_files if os.path.isdir(os.path.join(current_dir, d))]
            if not subdirs:
                break

            current_dir = os.path.join(current_dir, subdirs[0])
            depth += 1

        return None

    def find_and_read_routeagent_crs(self, cluster):
        """
        Find and read RouteAgent CRs from both possible locations:
        1. cluster/routeagents.yaml (cluster root - preferred)
        2. cluster/gather/<name>/routeagents_*.yaml (gather subdirectories - fallback)

        Returns a list of RouteAgent CR dictionaries
        """
        # Try cluster root first (preferred location)
        routeagents_file = os.path.join(self.diagnostics_dir, cluster, "routeagents.yaml")
        if os.path.exists(routeagents_file):
            routeagents_yaml = self.read_yaml(os.path.join(cluster, "routeagents.yaml"))
            if routeagents_yaml:
                # Check if it's a List with items or a single resource
                if routeagents_yaml.get('kind') == 'List':
                    return routeagents_yaml.get('items', [])
                else:
                    return [routeagents_yaml]

        # Fallback: try gather subdirectories
        gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather")
        if not os.path.exists(gather_dir):
            return []

        # Navigate through nested subdirectories
        current_dir = gather_dir
        depth = 0

        while depth < 4:
            all_files = os.listdir(current_dir)

            # Look for routeagent YAML files in current directory
            for file in all_files:
                if file.startswith("routeagents_") and file.endswith(".yaml"):
                    relative_path = os.path.relpath(os.path.join(current_dir, file), self.diagnostics_dir)
                    ra_yaml = self.read_yaml(relative_path)
                    if ra_yaml:
                        if ra_yaml.get('kind') == 'List':
                            return ra_yaml.get('items', [])
                        else:
                            return [ra_yaml]

            # If not found, go deeper
            subdirs = [d for d in all_files if os.path.isdir(os.path.join(current_dir, d))]
            if not subdirs:
                break

            current_dir = os.path.join(current_dir, subdirs[0])
            depth += 1

        return []

    def analyze_gateway_blocking(self, gateway_cr, cluster_name):
        """Analyze Gateway CR for blocking patterns"""
        if not gateway_cr or 'status' not in gateway_cr:
            return

        status = gateway_cr.get('status', {})
        gateways = status.get('gateways', [])

        # Check if we have asymmetric tunnel status
        is_asymmetric = False
        other_cluster_connected = False
        current_cluster_connected = False
        if self.tunnel_status:
            status1 = self.tunnel_status.get('cluster1', {}).get('status')
            status2 = self.tunnel_status.get('cluster2', {}).get('status')

            # Asymmetric if one is connected and the other is not
            is_asymmetric = (status1 == 'connected' and status2 != 'connected') or \
                           (status2 == 'connected' and status1 != 'connected')

            # Check if the OTHER cluster and CURRENT cluster are connected
            if cluster_name == 'cluster1':
                current_cluster_connected = (status1 == 'connected')
                other_cluster_connected = (status2 == 'connected')
            else:
                current_cluster_connected = (status2 == 'connected')
                other_cluster_connected = (status1 == 'connected')

        for gw in gateways:
            connections = gw.get('connections', [])
            for conn in connections:
                endpoint = conn.get('endpoint', {})
                backend = endpoint.get('backend', '')
                private_ip = endpoint.get('private_ip', '')
                public_ip = endpoint.get('public_ip', '')
                using_ip = conn.get('usingIP', '')
                conn_status = conn.get('status', '')

                if conn_status != 'connected' and backend == 'libreswan':
                    # If asymmetric (other cluster connected), be more cautious
                    # This suggests SNAT/routing issue rather than simple firewall block
                    if is_asymmetric and other_cluster_connected and not current_cluster_connected:
                        # Detect CNI to provide more specific guidance
                        cni = self.detect_cni(cluster_name)
                        is_ovnk = (cni == "OVNKubernetes")

                        # Don't conclude infrastructure/firewall - already flagged as asymmetric
                        # Just note the technical details
                        if using_ip == private_ip:
                            self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster_name}: Tunnel not connected (using private IP - ESP protocol)")
                            self._print(f"    Using IP: {using_ip} (ESP - IP protocol 50)")
                            self._print(f"    CNI: {cni}")
                            if is_ovnk:
                                self._print("    → Asymmetric status could suggest SNAT issue (OVN-K local gateway mode worth checking)")
                                self._print("    → Review nftables masquerade rules and routing configuration")
                            else:
                                self._print("    → Asymmetric status suggests routing issue (see recommendations above)")
                                self._print("    → Review routing configuration and return path")
                        elif using_ip == public_ip:
                            self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster_name}: Tunnel not connected (using public IP - NAT-T)")
                            self._print(f"    Using IP: {using_ip} (NAT-T - UDP encapsulation)")
                            self._print(f"    CNI: {cni}")
                            if is_ovnk:
                                self._print("    → Asymmetric status could suggest SNAT issue (OVN-K local gateway mode worth checking)")
                                self._print("    → Review return path routing and NAT configuration")
                            else:
                                self._print("    → Asymmetric status suggests routing issue (see recommendations above)")
                                self._print("    → Review return path routing and NAT configuration")
                    elif is_asymmetric and current_cluster_connected:
                        # The aggregate tunnel status for this cluster is connected; avoid
                        # classifying stale/passive connection entries as infrastructure failures.
                        continue
                    else:
                        # Both tunnels down OR no asymmetry detected - likely infrastructure issue
                        if using_ip == private_ip:
                            self.issues.append(f"{cluster_name}: Possible infrastructure/firewall issue preventing IPsec tunnel")
                            self.recommendations.append(
                                f"{cluster_name}: Verify infrastructure configuration, consider UDP encapsulation as alternative"
                            )
                            self._print(f"  {Colors.FAIL}✗{Colors.ENDC} {cluster_name}: Possible infrastructure/firewall blocking IPsec tunnel")
                            self._print(f"    Using IP: {using_ip} (private IP - suggests ESP protocol (IP protocol 50))")
                            self._print("    → Verify all required Submariner ports/protocols are allowed in your infrastructure")
                            self._print("    → Alternative: Enable UDP encapsulation if ESP is blocked")

                        # UDP blocking pattern
                        elif using_ip == public_ip:
                            self.issues.append(f"{cluster_name}: Possible UDP port blocking at infrastructure level")
                            self.recommendations.append(
                                f"{cluster_name}: Verify firewall allows UDP ports 500/4500, consider VxLAN as alternative"
                            )
                            self._print(f"  {Colors.FAIL}✗{Colors.ENDC} {cluster_name}: Possible UDP port blocking at infrastructure level")
                            self._print(f"    Using IP: {using_ip} (public IP - UDP encapsulation)")
                            self._print("    → Verify UDP ports 500 and 4500 are allowed in firewall/security groups")
                            self._print("    → Alternative: Consider VxLAN cable driver if UDP is blocked")

    def check_loadbalancer_service(self, cluster_name):
        """Check LoadBalancer service configuration for hosted clusters"""
        # First check if this is a hosted cluster deployment
        submariner_cr = self.find_and_read_gateway_cr(cluster_name)
        if not submariner_cr or 'spec' not in submariner_cr:
            return None

        spec = submariner_cr.get('spec', {})
        hosted_cluster = spec.get('hostedCluster', False)
        lb_enabled = spec.get('loadBalancerEnabled', False)

        # Only check LoadBalancer service for hosted clusters with LB enabled
        if not (hosted_cluster and lb_enabled):
            return None

        # Find and read the submariner-gateway service manifest
        gather_dir = os.path.join(self.diagnostics_dir, cluster_name, "gather")
        if not os.path.exists(gather_dir):
            return None

        for subdir in os.listdir(gather_dir):
            subdir_path = os.path.join(gather_dir, subdir)
            if os.path.isdir(subdir_path):
                service_file = "services_submariner-operator_submariner-gateway.yaml"
                service_path = os.path.join(subdir_path, service_file)
                if os.path.exists(service_path):
                    service_yaml = self.read_yaml(os.path.join(cluster_name, "gather", subdir, service_file))
                    if service_yaml:
                        return service_yaml

        return None

    def analyze_loadbalancer_config(self):
        """Analyze load balancer service configuration for hosted clusters"""
        self._print(f"\n{Colors.BOLD}=== Checking Load Balancer Configuration ==={Colors.ENDC}")

        for cluster_name in ['cluster1', 'cluster2']:
            service = self.check_loadbalancer_service(cluster_name)
            if not service:
                continue  # Not a hosted cluster or service not found

            self._print(f"\n  {Colors.BOLD}{cluster_name}:{Colors.ENDC}")

            spec = service.get('spec', {})
            status = service.get('status', {})

            # Check service type
            service_type = spec.get('type', '')
            if service_type == 'LoadBalancer':
                self._print("    ✓ Service type: LoadBalancer")
            else:
                self._print(f"    {Colors.FAIL}✗{Colors.ENDC} Service type: {service_type} (expected LoadBalancer)")
                self.issues.append(f"{cluster_name}: Service type is not LoadBalancer")

            # Check externalTrafficPolicy (CRITICAL for hosted clusters)
            external_policy = spec.get('externalTrafficPolicy', '')
            if external_policy == 'Cluster':
                self._print("    ✓ externalTrafficPolicy: Cluster (correct for hosted clusters)")
            elif external_policy == 'Local':
                self._print(f"    {Colors.FAIL}✗{Colors.ENDC} externalTrafficPolicy: Local (INCORRECT for hosted clusters)")
                self._print("      → MUST be 'Cluster' for hosted cluster deployments")
                self._print("      → Reference: https://github.com/submariner-io/submariner-operator/commit/f14c74e0c8180a64e7f38a7a82afeedd45940147")
                self.issues.append(f"{cluster_name}: externalTrafficPolicy is 'Local' - must be 'Cluster' for hosted clusters")
                self.recommendations.append(
                    f"{cluster_name}: Update submariner-gateway service to use externalTrafficPolicy: Cluster"
                )
            else:
                self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} externalTrafficPolicy: {external_policy}")

            # Check load balancer IP assignment
            lb_ingress = status.get('loadBalancer', {}).get('ingress', [])
            if lb_ingress:
                lb_ip = lb_ingress[0].get('ip', '')
                self._print(f"    ✓ Load balancer IP assigned: {lb_ip}")
            else:
                self._print(f"    {Colors.FAIL}✗{Colors.ENDC} No load balancer IP assigned")
                self.issues.append(f"{cluster_name}: No load balancer IP assigned")

            # Check UDP ports
            ports = spec.get('ports', [])
            required_ports = {4490: 'natt-discovery', 4500: 'cable-encaps'}
            found_ports = {}

            for port_spec in ports:
                port_num = port_spec.get('port')
                port_name = port_spec.get('name', '')
                protocol = port_spec.get('protocol', '')

                if port_num in required_ports and protocol == 'UDP':
                    found_ports[port_num] = port_name

            for port_num, expected_name in required_ports.items():
                if port_num in found_ports:
                    self._print(f"    ✓ UDP port {port_num} ({expected_name}) exposed")
                else:
                    self._print(f"    {Colors.FAIL}✗{Colors.ENDC} UDP port {port_num} ({expected_name}) not found")
                    self.issues.append(f"{cluster_name}: Missing UDP port {port_num} ({expected_name})")

    def analyze_tcpdump(self):
        """Analyze tcpdump data if available"""
        tcpdump_dir = os.path.join(self.diagnostics_dir, "tcpdump")
        if not os.path.exists(tcpdump_dir):
            return

        self._print(f"\n{Colors.BOLD}=== Analyzing Packet Captures ==={Colors.ENDC}")

        # Check if LoadBalancer is enabled (affects tcpdump interpretation)
        lb_enabled_cluster1 = self.check_loadbalancer_enabled('cluster1')
        lb_enabled_cluster2 = self.check_loadbalancer_enabled('cluster2')
        using_loadbalancer = lb_enabled_cluster1 or lb_enabled_cluster2

        if using_loadbalancer:
            self._print(f"  {Colors.BOLD}Note:{Colors.ENDC} LoadBalancer service detected - tcpdump interpretation adjusted")
            self._print("        Incoming traffic arrives on NodePort, not service port 4500")

        # Find analysis files with glob pattern
        import glob
        cluster1_files = glob.glob(os.path.join(tcpdump_dir, "cluster1-gateway-*-analysis.txt"))
        cluster2_files = glob.glob(os.path.join(tcpdump_dir, "cluster2-gateway-*-analysis.txt"))

        cluster1_analysis = None
        cluster2_analysis = None

        if cluster1_files:
            cluster1_analysis = self.read_file(os.path.relpath(cluster1_files[0], self.diagnostics_dir))
        if cluster2_files:
            cluster2_analysis = self.read_file(os.path.relpath(cluster2_files[0], self.diagnostics_dir))

        if not cluster1_analysis and not cluster2_analysis:
            self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} No tcpdump analysis files found")
            return

        # Detect protocol from capture filter
        protocol_info = self.detect_protocol_from_tcpdump(cluster1_analysis or cluster2_analysis)

        # Check if capture includes ICMP (new collection format)
        capture_filter = self.extract_capture_filter(cluster1_analysis or cluster2_analysis)
        has_icmp_capture = capture_filter and 'icmp' in capture_filter.lower()

        # Extract packet counts and directions
        packets1_total = self.extract_packet_count(cluster1_analysis) if cluster1_analysis else 0
        packets2_total = self.extract_packet_count(cluster2_analysis) if cluster2_analysis else 0

        # Check for bidirectional traffic (presence of "In" direction packets)
        packets1_in = self.check_packet_direction(cluster1_analysis, "In") if cluster1_analysis else False
        packets1_out = self.check_packet_direction(cluster1_analysis, "Out") if cluster1_analysis else False
        packets2_in = self.check_packet_direction(cluster2_analysis, "In") if cluster2_analysis else False
        packets2_out = self.check_packet_direction(cluster2_analysis, "Out") if cluster2_analysis else False

        self._print(f"  Cluster1 gateway: {packets1_total} packets captured")
        if packets1_total > 0:
            direction = []
            if packets1_out:
                direction.append("Out")
            if packets1_in:
                direction.append("In")
            self._print(f"    Direction: {', '.join(direction) if direction else 'Unknown'}")

        self._print(f"  Cluster2 gateway: {packets2_total} packets captured")
        if packets2_total > 0:
            direction = []
            if packets2_out:
                direction.append("Out")
            if packets2_in:
                direction.append("In")
            self._print(f"    Direction: {', '.join(direction) if direction else 'Unknown'}")

        # Analyze bidirectional traffic patterns
        if packets1_total > 0 and packets2_total > 0:
            # Both clusters sending packets
            if packets1_out and not packets1_in and packets2_out and not packets2_in:
                # Both sending, neither receiving - check if this is LoadBalancer-related
                if using_loadbalancer and protocol_info['type'] == 'udp':
                    # Extract NodePort packet counts (only if analysis files exist)
                    nodeport_packets1 = self.extract_nodeport_packet_count(cluster1_analysis) if cluster1_analysis else 0
                    nodeport_packets2 = self.extract_nodeport_packet_count(cluster2_analysis) if cluster2_analysis else 0

                    # Check if this is new enhanced capture (has NodePort stats)
                    has_nodeport_stats = (nodeport_packets1 > 0 or nodeport_packets2 > 0 or
                                        (cluster1_analysis and 'NodePort packets' in cluster1_analysis) or
                                        (cluster2_analysis and 'NodePort packets' in cluster2_analysis))

                    if not has_nodeport_stats:
                        # Old tcpdump format without NodePort capture
                        self._print(f"\n  {Colors.WARNING}⚠ PATTERN DETECTED:{Colors.ENDC}")
                        self._print("    Outgoing UDP packets detected, no incoming on port 4500")
                        self._print("    → LoadBalancer service is enabled - incoming traffic arrives on NodePort")
                        self._print("    → Cannot reliably determine infrastructure blocking from tcpdump alone")
                        self._print(f"\n  {Colors.WARNING}Note:{Colors.ENDC} Old tcpdump format - recommend re-collecting with enhanced version")

                        if has_icmp_capture:
                            self._print(f"\n  {Colors.BOLD}Analysis:{Colors.ENDC}")
                            self._print("    Capture filter includes ICMP - check if health check pings arrive")
                        else:
                            self._print(f"\n  {Colors.BOLD}Analysis:{Colors.ENDC}")
                            self._print("    Old capture filter (no ICMP) - cannot determine if traffic arrives")

                        # Check firewall test results as fallback
                        firewall_results = self.check_firewall_test_results()
                        if firewall_results:
                            self._print(f"\n  {Colors.BOLD}Firewall Test Results:{Colors.ENDC}")
                            if firewall_results.get('passed'):
                                self._print(f"    {Colors.OKGREEN}✓{Colors.ENDC} Firewall inter-cluster test PASSED")
                                self._print("    → Infrastructure is NOT blocking UDP traffic")
                                self.findings.append("Infrastructure allows UDP traffic (firewall test passed)")
                            else:
                                self._print(f"    {Colors.FAIL}✗{Colors.ENDC} Firewall inter-cluster test FAILED")
                                self._print("    → Appears to be infrastructure blocking UDP traffic")
                                self.issues.append(f"Infrastructure appears to be blocking {protocol_info['description']}")
                        else:
                            self._print(f"\n  {Colors.WARNING}Note:{Colors.ENDC} No firewall test results available")

                        self.recommendations.append("Re-collect diagnostics to get enhanced NodePort analysis")
                else:
                    # Not using LoadBalancer or using ESP - original logic applies
                    self.issues.append(f"CRITICAL: Both clusters sending tunnel packets but neither receiving → Appears to be infrastructure blocking {protocol_info['description']} in both directions")

                    # Build recommendations based on protocol type
                    if protocol_info['type'] == 'esp':
                        self.recommendations.append(f"Verify Submariner prerequisites - ensure {protocol_info['description']} is allowed between gateway nodes")
                        self.recommendations.append("Enable UDP encapsulation (ceIPSecForceUDPEncaps: true) as workaround if ESP is blocked but UDP port 4500 is allowed")
                    elif protocol_info['type'] == 'udp':
                        self.recommendations.append(f"Verify Submariner prerequisites - ensure {protocol_info['description']} is allowed between gateway nodes")
                    else:
                        self.recommendations.append("Verify Submariner prerequisites - ensure required protocols are allowed between gateway nodes")

                    self._print(f"\n  {Colors.FAIL}✗ CRITICAL FINDING:{Colors.ENDC}")
                    self._print("    Both clusters sending packets but NEITHER receiving")
                    self._print(f"    → It seems that infrastructure is blocking {protocol_info['description']} in BOTH directions")
                    self._print("    → Packets appear to leave source but not arrive at destination")
                    self._print(f"\n  {Colors.BOLD}Recommended Investigation:{Colors.ENDC}")
                    self._print(f"    1. Verify infrastructure allows {protocol_info['description']} between gateway nodes")
                    self._print("    2. Check firewall/security groups/network policies")
                    if protocol_info['type'] == 'esp':
                        self._print("    3. Try UDP encapsulation as workaround if ESP is blocked")
                    self._print("    📖 Submariner Prerequisites: https://submariner.io/operations/deployment/prerequisites/")
            elif packets1_in and packets1_out and packets2_in and packets2_out:
                # Bidirectional traffic working
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Bidirectional packet flow detected")
                self.findings.append("Bidirectional tunnel traffic flowing correctly")
        elif packets1_total > 0 and packets2_total == 0:
            # Cluster1 sending, cluster2 not
            self.issues.append(f"Cluster1 sending packets but Cluster2 not receiving → Appears to be unidirectional infrastructure blocking {protocol_info['description']}")
            self.recommendations.append(f"Verify firewall allows {protocol_info['description']} from Cluster1 to Cluster2")
            self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Packets leaving cluster1 but NOT reaching cluster2")
            self._print(f"    → Appears to be unidirectional infrastructure blocking {protocol_info['description']} (cluster1 → cluster2)")
        elif packets1_total == 0 and packets2_total > 0:
            # Cluster2 sending, cluster1 not
            self.issues.append(f"Cluster2 sending packets but Cluster1 not receiving → Appears to be unidirectional infrastructure blocking {protocol_info['description']}")
            self.recommendations.append(f"Verify firewall allows {protocol_info['description']} from Cluster2 to Cluster1")
            self._print(f"  {Colors.FAIL}✗{Colors.ENDC} Packets leaving cluster2 but NOT reaching cluster1")
            self._print(f"    → Appears to be unidirectional infrastructure blocking {protocol_info['description']} (cluster2 → cluster1)")
        elif packets1_total == 0 and packets2_total == 0:
            # No packets at all - check if LoadBalancer deployment has NodePort traffic
            if using_loadbalancer and protocol_info['type'] == 'udp':
                # Extract NodePort packet counts (only if analysis files exist)
                nodeport_packets1 = self.extract_nodeport_packet_count(cluster1_analysis) if cluster1_analysis else 0
                nodeport_packets2 = self.extract_nodeport_packet_count(cluster2_analysis) if cluster2_analysis else 0

                # Check if this is new enhanced capture (has NodePort stats)
                has_nodeport_stats = (nodeport_packets1 > 0 or nodeport_packets2 > 0 or
                                    (cluster1_analysis and 'NodePort packets' in cluster1_analysis) or
                                    (cluster2_analysis and 'NodePort packets' in cluster2_analysis))

                if has_nodeport_stats:
                    # New enhanced tcpdump with NodePort capture
                    self._print(f"\n  {Colors.BOLD}LoadBalancer Traffic Analysis:{Colors.ENDC}")

                    ovn_issue_found = False
                    lb_issue_found = False

                    # Analyze Cluster 1 (only if analysis file exists)
                    if cluster1_analysis:
                        if nodeport_packets1 > 0:
                            self._print(f"  {Colors.FAIL}✗ Cluster1:{Colors.ENDC}")
                            self._print(f"    NodePort traffic: {nodeport_packets1} packets arriving")
                            self._print("    Gateway pod traffic: 0 packets")
                            self._print(f"    → {Colors.FAIL}OVN NOT forwarding NodePort -> gateway pod{Colors.ENDC}")
                            self.faulty_states.append("Cluster1: OVN forwarding failure (NodePort -> pod)")
                            ovn_issue_found = True
                        elif nodeport_packets1 == 0:
                            self._print(f"  {Colors.FAIL}✗ Cluster1:{Colors.ENDC}")
                            self._print("    NodePort traffic: 0 packets")
                            self._print("    Gateway pod traffic: 0 packets")
                            self._print(f"    → {Colors.FAIL}LoadBalancer not forwarding or firewall blocking{Colors.ENDC}")
                            self.faulty_states.append("Cluster1: LoadBalancer/firewall issue")
                            lb_issue_found = True

                    # Analyze Cluster 2 (only if analysis file exists)
                    if cluster2_analysis:
                        if nodeport_packets2 > 0:
                            self._print(f"  {Colors.FAIL}✗ Cluster2:{Colors.ENDC}")
                            self._print(f"    NodePort traffic: {nodeport_packets2} packets arriving")
                            self._print("    Gateway pod traffic: 0 packets")
                            self._print(f"    → {Colors.FAIL}OVN NOT forwarding NodePort -> gateway pod{Colors.ENDC}")
                            self.faulty_states.append("Cluster2: OVN forwarding failure (NodePort -> pod)")
                            ovn_issue_found = True
                        elif nodeport_packets2 == 0:
                            self._print(f"  {Colors.FAIL}✗ Cluster2:{Colors.ENDC}")
                            self._print("    NodePort traffic: 0 packets")
                            self._print("    Gateway pod traffic: 0 packets")
                            self._print(f"    → {Colors.FAIL}LoadBalancer not forwarding or firewall blocking{Colors.ENDC}")
                            self.faulty_states.append("Cluster2: LoadBalancer/firewall issue")
                            lb_issue_found = True

                    # Report failure point
                    if ovn_issue_found:
                        self._print(f"\n  {Colors.BOLD}Traffic Path Issue:{Colors.ENDC}")
                        self._print("    Failure appears to be in: NodePort → Gateway Pod segment")
                        self._print("    Traffic arrives at NodePorts but doesn't reach gateway pod")
                        self._print("    This segment is handled by the CNI (OVN/networking layer)")
                        self.recommendations.append("Traffic path failure: NodePort → Gateway Pod segment")
                        self.recommendations.append("  Investigation needed: CNI/OVN forwarding from NodePort to pod")

                    if lb_issue_found:
                        self._print(f"\n  {Colors.BOLD}Traffic Path Issue:{Colors.ENDC}")
                        self._print("    Failure appears to be in: LoadBalancer → NodePort segment")
                        self._print("    No traffic arriving at NodePorts from LoadBalancer")
                        self._print("    This segment involves LB configuration, firewall, and security groups")
                        self.recommendations.append("Traffic path failure: LoadBalancer → NodePort segment")
                        self.recommendations.append("  Investigation needed: LB backend pool, security groups, firewall rules")
                    return  # Skip generic "no packets" message below

            # Generic no-packets message (non-LB or old tcpdump format)
            self.issues.append("No tunnel packets captured on either cluster → Gateway not sending traffic")
            self.recommendations.append("Review gateway pod logs for cable driver initialization errors")
            self._print(f"  {Colors.FAIL}✗{Colors.ENDC} No packets captured on either cluster")
            self._print("    → Gateways not sending tunnel traffic - check gateway logs")

    def check_loadbalancer_enabled(self, cluster_name):
        """Check if LoadBalancer service is enabled from Submariner CR"""
        # Use existing find_and_read_gateway_cr which handles both single-level
        # and nested directory layouts
        submariner_cr = self.find_and_read_gateway_cr(cluster_name)
        if submariner_cr:
            spec = submariner_cr.get('spec', {})
            return spec.get('loadBalancerEnabled', False)
        return False

    def check_firewall_test_results(self):
        """Check if firewall inter-cluster test results are available and passed"""
        firewall_file = os.path.join(self.diagnostics_dir, "firewall", "firewall-inter-cluster.txt")
        if not os.path.exists(firewall_file):
            return None

        content = self.read_file("firewall/firewall-inter-cluster.txt")
        if not content:
            return None

        # Look for test result
        if "Tunnels can be established" in content and "✓" in content:
            return {'passed': True}
        elif "error" in content.lower() or "fail" in content.lower() or "cannot" in content.lower() or "timed out" in content.lower():
            return {'passed': False}

        return None

    def extract_capture_filter(self, analysis_content):
        """Extract capture filter from tcpdump analysis"""
        if not analysis_content:
            return None
        filter_match = re.search(r'Capture Filter.*?:\s*(.+)', analysis_content)
        return filter_match.group(1).strip() if filter_match else None

    def detect_protocol_from_tcpdump(self, analysis_content):
        """Detect protocol from tcpdump capture filter"""
        if not analysis_content:
            return {'type': 'unknown', 'description': 'tunnel traffic'}

        # Look for tunnel-specific capture filter line (new format)
        filter_match = re.search(r'Capture Filter \(tunnel\):\s*(.+)', analysis_content)
        if not filter_match:
            # Fallback to old format for backwards compatibility
            filter_match = re.search(r'Capture Filter:\s*(.+)', analysis_content)

        if not filter_match:
            return {'type': 'unknown', 'description': 'tunnel traffic'}

        filter_str = filter_match.group(1).strip()

        if 'proto 50' in filter_str:
            return {'type': 'esp', 'description': 'ESP (IP protocol 50)'}
        elif 'udp port' in filter_str:
            port_match = re.search(r'udp port (\d+)', filter_str)
            port = port_match.group(1) if port_match else '4500'
            return {'type': 'udp', 'description': f'UDP port {port}'}
        else:
            return {'type': 'unknown', 'description': 'tunnel traffic'}

    def check_packet_direction(self, analysis_content, direction):
        """Check if packets in a specific direction (In/Out) exist"""
        if not analysis_content:
            return False
        # Only inspect the tunnel packet section; ICMP summaries are diagnostic
        # noise for tunnel-direction inference.
        tunnel_section = analysis_content
        start_marker = "FIRST 50 TUNNEL PACKETS (detailed):"
        end_marker = "UNIQUE SOURCE -> DESTINATION PAIRS"
        if start_marker in analysis_content:
            tunnel_section = analysis_content.split(start_marker, 1)[1]
            if end_marker in tunnel_section:
                tunnel_section = tunnel_section.split(end_marker, 1)[0]

        # Look for direction indicator in packet details
        return f" {direction} " in tunnel_section or f"wlp0s20f3 {direction}" in tunnel_section

    def extract_packet_count(self, analysis_content):
        """Extract tunnel packet count from tcpdump analysis (excluding ICMP)"""
        if not analysis_content:
            return 0
        # Try to get tunnel-specific packet count first (new format)
        match = re.search(r'Tunnel packets.*?:\s+(\d+)', analysis_content)
        if match:
            return int(match.group(1))
        # Fallback to total packets for backwards compatibility
        match = re.search(r'Total packets captured:\s+(\d+)', analysis_content)
        if match:
            return int(match.group(1))
        return 0

    def extract_nodeport_packet_count(self, analysis_content):
        """Extract NodePort packet count from tcpdump analysis (LoadBalancer deployments)"""
        if not analysis_content:
            return 0
        match = re.search(r'NodePort packets.*?:\s+(\d+)', analysis_content)
        if match:
            return int(match.group(1))
        return 0


    def analyze_pod_health(self):
        """Check pod status"""
        self._print(f"\n{Colors.BOLD}=== Analyzing Pod Health ==={Colors.ENDC}")

        for cluster in ['cluster1', 'cluster2']:
            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather")
            if not os.path.exists(gather_dir):
                continue

            # Find pods YAML
            for subdir in os.listdir(gather_dir):
                subdir_path = os.path.join(gather_dir, subdir)
                if os.path.isdir(subdir_path):
                    for file in os.listdir(subdir_path):
                        if file.startswith("pods_") and file.endswith(".yaml"):
                            pods_yaml = self.read_yaml(os.path.join(cluster, "gather", subdir, file))
                            if pods_yaml and 'items' in pods_yaml:
                                self.check_pod_status(pods_yaml['items'], cluster)

    def check_pod_status(self, pods, cluster_name):
        """Check status of individual pods"""
        unhealthy = []
        for pod in pods:
            metadata = pod.get('metadata', {})
            status = pod.get('status', {})

            pod_name = metadata.get('name', 'unknown')
            phase = status.get('phase', 'Unknown')

            if phase not in ['Running', 'Succeeded']:
                unhealthy.append(f"{pod_name}: {phase}")

            # Check container status
            container_statuses = status.get('containerStatuses', [])
            for cs in container_statuses:
                if not cs.get('ready', False):
                    state = cs.get('state', {})
                    if 'waiting' in state:
                        reason = state['waiting'].get('reason', 'Unknown')
                        unhealthy.append(f"{pod_name}: Container not ready ({reason})")

        if unhealthy:
            self._print(f"  {Colors.FAIL}✗{Colors.ENDC} {cluster_name}: Unhealthy pods found:")
            for issue in unhealthy:
                self._print(f"    - {issue}")
            self.issues.extend([f"{cluster_name}: {issue}" for issue in unhealthy])
        else:
            self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {cluster_name}: All pods healthy")

    def get_gateway_status(self, cluster, actual_cluster_name):
        """Get gateway-to-gateway connectivity status from Submariner CR"""
        gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)
        if not os.path.exists(gather_dir):
            return None

        # Look for submariner CR YAML
        for file in os.listdir(gather_dir):
            if file.startswith("submariners_submariner-operator_submariner") and file.endswith(".yaml"):
                submariner_cr = self.read_yaml(os.path.join(cluster, "gather", actual_cluster_name, file))
                if submariner_cr:
                    # Get gateway status from CR
                    gateways = submariner_cr.get('status', {}).get('gateways', [])
                    if gateways:
                        # Look for active gateway
                        for gw in gateways:
                            if gw.get('haStatus') == 'active':
                                connections = gw.get('connections', [])
                                if connections:
                                    # Return first connection status
                                    return {
                                        'status': connections[0].get('status', 'unknown'),
                                        'gateway_node': gw.get('localEndpoint', {}).get('hostname', 'unknown'),
                                        'remote_ip': connections[0].get('endpoint', {}).get('private_ip', 'unknown')
                                    }
        return None

    def check_gateway_ha_labels_early(self):
        """Early check for Gateway HA status and Endpoint consistency"""
        gateway_data = {}

        for cluster in ['cluster1', 'cluster2']:
            # Read Gateway CR (authoritative source for HA state)
            gateway_cr = self.find_and_read_gateway_cr(cluster)
            if not gateway_cr or 'status' not in gateway_cr:
                continue

            gateways = gateway_cr.get('status', {}).get('gateways', [])

            # Count active gateways in CR (this is the critical check)
            active_gateways = [gw for gw in gateways if gw.get('haStatus') == 'active']
            passive_gateways = [gw for gw in gateways if gw.get('haStatus') == 'passive']

            gateway_data[cluster] = {
                'active_count': len(active_gateways),
                'passive_count': len(passive_gateways),
                'gateways': gateways
            }

            # CRITICAL: Only ONE Gateway resource should have haStatus: active
            if len(active_gateways) != 1:
                self.faulty_states.append(f"{cluster}: {len(active_gateways)} Gateway resources with haStatus='active' (expected 1)")
                self._print(f"  {Colors.FAIL}✗{Colors.ENDC} {cluster}: CRITICAL - {len(active_gateways)} Gateway resources report haStatus='active' (expected 1)")
            else:
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {cluster}: Gateway CR shows 1 active gateway")

        # Check Endpoint visibility across clusters
        if len(gateway_data) == 2:
            cluster1_endpoints = set()
            cluster2_endpoints = set()

            for gw in gateway_data.get('cluster1', {}).get('gateways', []):
                for conn in gw.get('connections', []):
                    endpoint = conn.get('endpoint', {})
                    cluster_id = endpoint.get('cluster_id', '')
                    if cluster_id:
                        cluster1_endpoints.add(cluster_id)

            for gw in gateway_data.get('cluster2', {}).get('gateways', []):
                for conn in gw.get('connections', []):
                    endpoint = conn.get('endpoint', {})
                    cluster_id = endpoint.get('cluster_id', '')
                    if cluster_id:
                        cluster2_endpoints.add(cluster_id)

            # Verify endpoints - both clusters should have endpoint connections
            if cluster1_endpoints and cluster2_endpoints:
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Endpoint resources present on both clusters")
            elif not cluster1_endpoints and not cluster2_endpoints:
                self.faulty_states.append("No endpoint connections found on either cluster")
                self._print(f"  {Colors.FAIL}✗{Colors.ENDC} No endpoint connections found on either cluster")
            else:
                missing_cluster = "cluster1" if not cluster1_endpoints else "cluster2"
                self.faulty_states.append(f"{missing_cluster}: No endpoint connections found")
                self._print(f"  {Colors.FAIL}✗{Colors.ENDC} {missing_cluster}: No endpoint connections found")

    def analyze_gateway_ha_labels(self):
        """Check for multiple active gateway pods (HA label synchronization bug)"""
        self._print(f"\n{Colors.BOLD}=== Analyzing Gateway HA Labels ==={Colors.ENDC}")

        for cluster in ['cluster1', 'cluster2']:
            cluster_dir = os.path.join(self.diagnostics_dir, cluster)
            if not os.path.exists(cluster_dir):
                continue

            # Find the gather subdirectory
            gather_base = os.path.join(cluster_dir, "gather")
            if not os.path.exists(gather_base):
                continue

            # Navigate through nested subdirectories to find the actual gather data
            # Structure can be: cluster/gather/acm-name/k8s-id/ or cluster/gather/cluster-name/
            gather_dir = None
            current_dir = gather_base
            depth = 0

            while depth < 4:
                # Check if current directory contains YAML files
                all_files = os.listdir(current_dir)
                yaml_files = [f for f in all_files if f.endswith('.yaml')]

                if yaml_files:
                    gather_dir = current_dir
                    break

                # Get subdirectories
                subdirs = [d for d in all_files if os.path.isdir(os.path.join(current_dir, d))]

                if not subdirs:
                    # No more subdirs, check current dir for YAMLs one more time
                    if yaml_files:
                        gather_dir = current_dir
                    break

                # Move to first subdir
                current_dir = os.path.join(current_dir, subdirs[0])
                depth += 1

            if not gather_dir:
                continue

            # Read Gateway CR to get expected HA state
            gateway_cr = None
            for file in os.listdir(gather_dir):
                if file.startswith("submariners_submariner-operator_submariner") and file.endswith(".yaml"):
                    # Use relative path from diagnostics_dir
                    relative_path = os.path.relpath(os.path.join(gather_dir, file), self.diagnostics_dir)
                    gateway_cr = self.read_yaml(relative_path)
                    break

            if not gateway_cr:
                continue

            # Get LoadBalancer configuration from Gateway CR spec
            spec = gateway_cr.get('spec', {})
            lb_enabled = spec.get('loadBalancerEnabled', False)
            using_loadbalancer = lb_enabled

            # Get expected HA state from Gateway CR
            gateways = gateway_cr.get('status', {}).get('gateways', [])
            expected_active_count = sum(1 for gw in gateways if gw.get('haStatus') == 'active')
            expected_passive_count = sum(1 for gw in gateways if gw.get('haStatus') == 'passive')

            # Get active node from Gateway CR
            expected_active_node = None
            expected_passive_nodes = []
            for gw in gateways:
                if gw.get('haStatus') == 'active':
                    expected_active_node = gw.get('localEndpoint', {}).get('hostname', 'unknown')
                elif gw.get('haStatus') == 'passive':
                    expected_passive_nodes.append(gw.get('localEndpoint', {}).get('hostname', 'unknown'))

            # Read gateway pod YAMLs to check actual labels
            active_pods = []
            passive_pods = []

            for file in os.listdir(gather_dir):
                if file.startswith("pods_submariner-operator_submariner-gateway") and file.endswith(".yaml"):
                    # Use relative path from diagnostics_dir
                    relative_path = os.path.relpath(os.path.join(gather_dir, file), self.diagnostics_dir)
                    pod_yaml = self.read_yaml(relative_path)
                    if pod_yaml:
                        labels = pod_yaml.get('metadata', {}).get('labels', {})
                        pod_name = pod_yaml.get('metadata', {}).get('name', 'unknown')
                        node_name = pod_yaml.get('spec', {}).get('nodeName', 'unknown')
                        ha_label = labels.get('gateway.submariner.io/status', 'unknown')

                        if ha_label == 'active':
                            active_pods.append((pod_name, node_name))
                        elif ha_label == 'passive':
                            passive_pods.append((pod_name, node_name))

            # Check for mismatch
            if len(active_pods) > 1:
                # Determine severity based on LoadBalancer usage
                if using_loadbalancer:
                    severity = "CRITICAL"
                    severity_color = Colors.FAIL
                else:
                    severity = "MINOR"
                    severity_color = Colors.WARNING

                self._print(f"  {severity_color}{severity} - Pod label issue detected:{Colors.ENDC} {cluster}: {len(active_pods)} pods labeled 'active'")
                self._print(f"    Gateway CR (source of truth): {expected_active_count} active, {expected_passive_count} passive")
                self._print(f"    Pod labels (out of sync): {len(active_pods)} active, {len(passive_pods)} passive")
                self._print(f"    LoadBalancer service enabled: {'YES' if using_loadbalancer else 'NO'}")
                self._print(f"    Severity: {severity}")
                self._print("\n    Pods labeled 'active':")
                for pod_name, node_name in active_pods:
                    # Check if this is the expected active node
                    expected = " (expected active per Gateway CR)" if node_name == expected_active_node else " (should be passive per Gateway CR)"
                    self._print(f"      - {pod_name} on node {node_name}{expected}")

                if using_loadbalancer:
                    # CRITICAL: LoadBalancer is routing to multiple pods
                    self._print(f"\n  {Colors.FAIL}CRITICAL IMPACT:{Colors.ENDC}")
                    self._print(f"    - LoadBalancer service routes to ALL {len(active_pods)} pods with label 'active'")
                    self._print("    - Only 1 pod has actual tunnel connection (per Gateway CR)")
                    self._print(f"    - Result: ~{100 // len(active_pods)}% packet loss, random tunnel failures")
                    self._print(f"\n  {Colors.WARNING}IMMEDIATE FIX:{Colors.ENDC}")

                    # Identify which pods need label correction
                    for pod_name, node_name in active_pods:
                        if node_name != expected_active_node:
                            self._print(f"    kubectl label pod -n submariner-operator {pod_name} \\")
                            self._print("      gateway.submariner.io/status=passive --overwrite")

                    self._print(f"\n  {Colors.WARNING}WORKAROUND (if issue recurs):{Colors.ENDC}")
                    self._print("    Change externalTrafficPolicy from 'Local' to 'Cluster':")
                    self._print("    kubectl patch service -n submariner-operator submariner-gateway \\")
                    self._print("      --type merge -p '{\"spec\": {\"externalTrafficPolicy\": \"Cluster\"}}'")

                    self._print(f"\n  {Colors.WARNING}RECOMMENDED:{Colors.ENDC}")
                    self._print("    1. Collect operator logs for HA election analysis:")
                    self._print("       kubectl logs -n submariner-operator deployment/submariner-operator > operator.log")
                    self._print("    2. Collect gateway pod logs from ALL gateway pods:")
                    for pod_name, _node_name in active_pods:
                        self._print(f"       kubectl logs -n submariner-operator {pod_name} > {pod_name}.log")
                    for pod_name, _node_name in passive_pods:
                        self._print(f"       kubectl logs -n submariner-operator {pod_name} > {pod_name}.log")
                    self._print("    3. File a bug report with Submariner project:")
                    self._print("       https://github.com/submariner-io/submariner/issues")
                    self._print("       Title: Gateway HA label sync with LoadBalancer")
                    self._print("       Include: Gateway CR, pod YAMLs, operator logs, gateway logs")
                    self._print(f"       Release version: {gateway_cr.get('status', {}).get('version', 'unknown')}")

                    self.faulty_states.append(f"{cluster}: Multiple active gateway pods with LoadBalancer (HA label sync bug)")
                    self.issues.append(f"{cluster}: CRITICAL - {len(active_pods)} gateway pods labeled 'active' with LoadBalancer enabled (~{100 // len(active_pods)}% packet loss)")
                    self.recommendations.append(f"{cluster}: Fix pod labels immediately - LoadBalancer traffic splitting causing packet loss")
                    self.recommendations.append(f"{cluster}: File bug with Submariner - HA election race condition with LoadBalancer")
                else:
                    # MINOR: No LoadBalancer, Gateway CR is used for HA logic
                    self._print(f"\n  {Colors.WARNING}Impact:{Colors.ENDC}")
                    self._print("    - MINOR issue (cosmetic)")
                    self._print("    - Gateway CR is used for HA logic, not pod labels")
                    self._print("    - No traffic impact (LoadBalancer service not enabled)")
                    self._print("    - Pod labels should sync eventually")

                    self._print(f"\n  {Colors.WARNING}Recommendation:{Colors.ENDC}")
                    self._print("    - Monitor pod labels - they should sync automatically")
                    self._print("    - If labels don't sync within 5 minutes, investigate operator logs")

                    self.faulty_states.append(f"{cluster}: Multiple active gateway pod labels (MINOR - no LoadBalancer)")
                    self.issues.append(f"{cluster}: MINOR - {len(active_pods)} gateway pods labeled 'active' (cosmetic, no traffic impact)")
                    self.recommendations.append(f"{cluster}: Monitor pod labels - should sync automatically (no urgent action needed)")

            elif len(active_pods) == 1:
                active_pod, active_node = active_pods[0]
                if active_node == expected_active_node:
                    self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {cluster}: Gateway HA labels correct (1 active pod on expected node)")
                else:
                    self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster}: Active pod on unexpected node")
                    self._print(f"    Expected active node: {expected_active_node}")
                    self._print(f"    Actual active pod: {active_pod} on {active_node}")
            else:
                self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster}: No active gateway pods found")

    def analyze_routeagents(self):
        """Analyze RouteAgent resources to detect connectivity issues"""
        self._print(f"\n{Colors.BOLD}=== Analyzing RouteAgent Resources ==={Colors.ENDC}")

        # Get cluster subdirectory mapping (may be empty if gather failed)
        cluster_subdirs = self.get_cluster_subdirs()

        for cluster in ['cluster1', 'cluster2']:
            # Get the actual cluster name (e.g., sitea-mgmt1, siteb-mgmt1)
            # This may be None if gather failed - that's OK, we can still read standalone files
            actual_cluster_name = cluster_subdirs.get(cluster) if cluster_subdirs else None

            # Get gateway status first (gateway-to-gateway connectivity)
            # Use tunnel_status as fallback when actual_cluster_name is None
            gateway_status = None
            if actual_cluster_name:
                gateway_status = self.get_gateway_status(cluster, actual_cluster_name)
            elif self.tunnel_status and cluster in self.tunnel_status:
                # Fallback: use tunnel_status data
                gateway_status = self.tunnel_status[cluster]

            # Read RouteAgent CRs using unified method that handles both layouts
            agents = self.find_and_read_routeagent_crs(cluster)

            if not agents:
                # RouteAgent resources were added in recent Submariner versions (last 2-3 releases)
                # If not found, this could be an older version
                self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster}: No RouteAgent resources (older Submariner version or not collected)")
                continue

            # Analyze each RouteAgent
            error_agents = []
            connected_agents = []
            gateway_agents = []
            pattern_detected = False
            control_plane_failures = []

            for agent in agents:
                # Each agent is a single RouteAgent CR, not wrapped in items list
                name = agent.get('metadata', {}).get('name', 'unknown')
                status_obj = agent.get('status', {})
                remote_endpoints = status_obj.get('remoteEndpoints', [])

                if not remote_endpoints:
                    continue

                # Check first remote endpoint status
                endpoint_status = remote_endpoints[0].get('status', '')
                status_msg = remote_endpoints[0].get('statusMessage', '')

                if endpoint_status == 'connected':
                    connected_agents.append(name)
                elif endpoint_status == 'none':
                    # Gateway nodes don't perform health checks
                    gateway_agents.append(name)
                elif endpoint_status == 'error':
                    error_agents.append((name, status_msg))

                    # Detect if it's a control plane node by checking common naming patterns
                    if any(pattern in name.lower() for pattern in ['cp-', 'control', 'master']):
                        control_plane_failures.append((name, status_msg))

            # Store data for later use
            self.routeagent_data[cluster] = {
                'total': len(agents),
                'connected': len(connected_agents),
                'errors': len(error_agents),
                'gateways': len(gateway_agents)
            }

            # Report findings
            self._print(f"  {cluster}: {len(agents)} RouteAgents found")
            self._print(f"    Connected: {len(connected_agents)}")
            self._print(f"    Gateway nodes: {len(gateway_agents)} (health check not performed)")

            # CRITICAL CHECK: Pattern 2 - Gateway error + RouteAgent connected
            # This indicates tunnel datapath is actually working!
            if gateway_status and connected_agents:
                gw_status = gateway_status.get('status', 'unknown')
                if gw_status == 'error' and len(connected_agents) > 0:
                    self._print(f"\n  {Colors.BOLD}🔍 CRITICAL PATTERN DETECTED:{Colors.ENDC}")
                    self._print(f"    {Colors.FAIL}✗{Colors.ENDC} Gateway health check: {Colors.FAIL}ERROR{Colors.ENDC}")
                    self._print(f"    {Colors.OKGREEN}✓{Colors.ENDC} RouteAgent health check: {Colors.OKGREEN}CONNECTED{Colors.ENDC} ({len(connected_agents)} nodes)")
                    self._print(f"\n  {Colors.BOLD}Analysis:{Colors.ENDC}")
                    self._print(f"    → Tunnel datapath is {Colors.OKGREEN}ACTUALLY WORKING{Colors.ENDC}!")
                    self._print("    → Gateway health check failure is misleading")
                    self._print("    → RouteAgent tests full path: WorkerNode → LocalGW → RemoteGW")
                    self._print("    → Most likely cause: Gateway health check IP configuration issue")
                    self._print(f"\n  {Colors.BOLD}Recommendation:{Colors.ENDC}")
                    self._print("    - Verify health check IPs are correctly configured")
                    self._print("    - Check if health check IP exists on gateway node (ip-a.log)")
                    self._print("    - Investigate why gateway pod health check fails despite datapath working")
                    self._print(f"    - {Colors.OKGREEN}Do NOT waste time on infrastructure blocking investigation{Colors.ENDC}")

                    self.findings.append(f"{cluster}: Tunnel datapath is working (RouteAgent proves it)")
                    self.recommendations.append(
                        f"{cluster}: Gateway health check failure is misleading - verify health check IP configuration"
                    )
                    # Don't add this to issues since it's actually working!

            if error_agents:
                self._print(f"    {Colors.FAIL}Errors: {len(error_agents)}{Colors.ENDC}")

                # Check gateway-to-gateway connectivity status
                if gateway_status:
                    gw_status = gateway_status.get('status', 'unknown')
                    gw_node = gateway_status.get('gateway_node', 'unknown')
                    self._print(f"\n    Gateway-to-Gateway connectivity: {self.colorize_status(gw_status)}")
                    self._print(f"    Gateway node: {gw_node}")

                    # Correlate gateway status with RouteAgent failures
                    if gw_status == 'connected' and error_agents:
                        self._print(f"\n  {Colors.BOLD}🔍 ROOT CAUSE IDENTIFIED:{Colors.ENDC}")
                        self._print(f"    ✓ Gateway → Remote Gateway: {Colors.OKGREEN}CONNECTED{Colors.ENDC}")
                        self._print(f"    ✗ Non-gateway nodes → Remote Gateway: {Colors.FAIL}FAILED{Colors.ENDC}")
                        self._print(f"\n    {Colors.WARNING}Diagnosis:{Colors.ENDC} This is an INTRA-cluster routing issue")
                        self._print("    - Inter-cluster connectivity is working (gateway tunnel connected)")
                        self._print("    - Problem: Non-gateway nodes cannot reach the remote gateway IP")
                        self._print("    - This indicates the faulty segment is within the LOCAL cluster:")
                        self._print("      Non-gateway nodes → Local gateway node's selected IP")

                # Detect pattern: all control plane nodes failing
                if control_plane_failures and len(control_plane_failures) >= 2:
                    pattern_detected = True
                    self._print(f"\n  {Colors.WARNING}⚠ PATTERN DETECTED:{Colors.ENDC} Multiple control plane nodes failing")

                    for node_name, msg in control_plane_failures[:3]:  # Show first 3
                        self._print(f"    - {node_name}")
                        if "ping" in msg.lower():
                            # Extract IP being pinged
                            import re
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', msg)
                            if ip_match:
                                failed_ip = ip_match.group(1)
                                self._print(f"      Cannot ping: {failed_ip}")

                    # Only add generic recommendations if we didn't already identify root cause
                    if not gateway_status or gateway_status.get('status') != 'connected':
                        self.faulty_states.append(f"{cluster}: Control plane nodes cannot reach remote gateway")
                        self.recommendations.append(
                            f"{cluster}: Check network connectivity from control plane to gateway nodes"
                        )
                        self.recommendations.append(
                            f"{cluster}: Verify routing rules allow traffic from control planes to gateway IP"
                        )
                    else:
                        self.faulty_states.append(f"{cluster}: Control planes cannot reach gateway IP (intra-cluster routing issue)")
                        self.recommendations.append(
                            f"{cluster}: INTRA-CLUSTER ISSUE - Verify control planes can reach local gateway node's IP"
                        )
                        self.recommendations.append(
                            f"{cluster}: Check routing tables on control plane nodes to gateway subnet"
                        )
                        self.recommendations.append(
                            f"{cluster}: Verify firewall rules allow control plane → gateway node traffic"
                        )

                # Show sample errors if pattern not detected
                if not pattern_detected:
                    for node_name, msg in error_agents[:2]:
                        self._print(f"    - {node_name}: {msg[:80]}")
                    if len(error_agents) > 2:
                        self._print(f"    ... and {len(error_agents) - 2} more")

                self.issues.append(f"{cluster}: {len(error_agents)} RouteAgent(s) with errors")

    def get_cluster_subdirs(self):
        """Get sorted list of cluster subdirectories from gather/

        Since subctl gather collects from both clusters, we map:
        - cluster1 -> first subdirectory alphabetically
        - cluster2 -> second subdirectory alphabetically
        """
        # Check cluster1/gather for subdirectories
        gather_dir = os.path.join(self.diagnostics_dir, "cluster1", "gather")
        if not os.path.exists(gather_dir):
            return {}

        subdirs = sorted([d for d in os.listdir(gather_dir)
                         if os.path.isdir(os.path.join(gather_dir, d))])

        if len(subdirs) >= 2:
            return {
                'cluster1': subdirs[0],
                'cluster2': subdirs[1]
            }
        elif len(subdirs) == 1:
            # Only one subdirectory - use it for both
            return {
                'cluster1': subdirs[0],
                'cluster2': subdirs[0]
            }
        return {}

    def analyze_network_topology(self):
        """Analyze network topology to detect flat vs non-flat networking

        Only runs if RouteAgent errors were detected, as topology analysis
        is only relevant when there are connectivity issues.
        """
        # Check if any RouteAgent errors were detected
        has_errors = False
        for cluster_data in self.routeagent_data.values():
            if cluster_data.get('errors', 0) > 0:
                has_errors = True
                break

        if not has_errors:
            # Skip topology analysis if no RouteAgent errors
            return

        self._print(f"\n{Colors.BOLD}=== Analyzing Network Topology ==={Colors.ENDC}")
        self._print("  (Running due to RouteAgent connectivity failures detected)")

        # Get cluster subdirectory mapping
        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs:
            self._print(f"  {Colors.WARNING}Could not determine cluster subdirectories{Colors.ENDC}")
            return

        for cluster in ['cluster1', 'cluster2']:
            # Get the actual cluster name (e.g., sitea-mgmt1, siteb-mgmt1)
            actual_cluster_name = cluster_subdirs.get(cluster)
            if not actual_cluster_name:
                self._print(f"  {cluster}: {Colors.WARNING}Could not determine cluster name{Colors.ENDC}")
                continue

            # Collect node IPs from pod YAML files (status.hostIP)
            cluster_ips = set()
            node_to_ip = {}

            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather")
            if not os.path.exists(gather_dir):
                self._print(f"  {cluster}: {Colors.WARNING}No gather data found{Colors.ENDC}")
                continue

            # Only look in the subdirectory matching this cluster's name
            cluster_gather_dir = os.path.join(gather_dir, actual_cluster_name)
            if not os.path.exists(cluster_gather_dir):
                self._print(f"  {cluster}: {Colors.WARNING}No gather data for {actual_cluster_name}{Colors.ENDC}")
                continue

            # Look for pod YAML files which contain hostIP information
            for file in os.listdir(cluster_gather_dir):
                if file.startswith("pods_") and file.endswith(".yaml"):
                    pods_yaml = self.read_yaml(os.path.join(cluster, "gather", actual_cluster_name, file))
                    if pods_yaml and isinstance(pods_yaml, dict):
                        # Handle both single pod and list of pods
                        pod_list = pods_yaml.get('items', [pods_yaml]) if 'items' in pods_yaml else [pods_yaml]

                        for pod in pod_list:
                            if not isinstance(pod, dict):
                                continue

                            # Get hostIP from pod status
                            host_ip = pod.get('status', {}).get('hostIP')
                            node_name = pod.get('spec', {}).get('nodeName')

                            if host_ip:
                                cluster_ips.add(host_ip)
                                if node_name:
                                    node_to_ip[node_name] = host_ip

            if not cluster_ips:
                self._print(f"  {cluster}: {Colors.WARNING}No node IP information found{Colors.ENDC}")
                continue

            # Auto-detect network topology by trying common subnet masks
            # Try masks in order: /24 (most common), /22, /20, /16
            common_masks = [24, 22, 20, 16]
            topology_detected = False

            for subnet_mask in common_masks:
                ip_subnets = set()
                subnet_to_ips = {}

                for ip in cluster_ips:
                    try:
                        # Calculate network prefix based on subnet mask
                        ipaddress.ip_address(ip)
                        network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
                        network_str = str(network)

                        ip_subnets.add(network_str)
                        if network_str not in subnet_to_ips:
                            subnet_to_ips[network_str] = []
                        subnet_to_ips[network_str].append(ip)
                    except ValueError:
                        # Skip invalid IPs
                        continue

                # Report findings if multiple subnets detected at this mask
                if len(ip_subnets) > 1 and not topology_detected:
                    topology_detected = True
                    self._print(f"  {cluster}: {Colors.WARNING}Multiple subnets detected{Colors.ENDC}")
                    self._print(f"    Node IPs span {len(ip_subnets)} different /{subnet_mask} subnets:")
                    for subnet in sorted(ip_subnets):
                        num_ips = len(subnet_to_ips[subnet])
                        self._print(f"    - {subnet} ({num_ips} node{'s' if num_ips > 1 else ''})")

                    self._print(f"\n    {Colors.BOLD}Note:{Colors.ENDC} This indicates non-flat networking (nodes in different /{subnet_mask} networks).")
                    self._print("    Investigate network topology and routing between these subnets.")

                    # Only add as issue if we also detected RouteAgent failures
                    if self.routeagent_data.get(cluster, {}).get('errors', 0) > 0:
                        self.issues.append(f"{cluster}: Multiple /{subnet_mask} subnets with RouteAgent connectivity errors")
                        self.recommendations.append(
                            f"{cluster}: Non-flat networking detected - verify routing between /{subnet_mask} subnets"
                        )
                        self.recommendations.append(
                            f"{cluster}: Ensure nodes can route traffic between: {', '.join(sorted(ip_subnets))}"
                        )

                    self.network_topology[cluster] = {
                        'total_ips': len(cluster_ips),
                        'total_nodes': len(node_to_ip),
                        'subnets': len(ip_subnets),
                        'subnet_mask': subnet_mask,
                        'is_flat': False
                    }
                    break

            # If all masks show single subnet, it's flat networking
            if not topology_detected:
                self._print(f"  {cluster}: {Colors.OKGREEN}Flat networking detected{Colors.ENDC}")
                # Show at /24 level for reference
                network = ipaddress.ip_network(f"{list(cluster_ips)[0]}/24", strict=False)
                self._print("    All node IPs within same network scope")

                self.network_topology[cluster] = {
                    'total_ips': len(cluster_ips),
                    'total_nodes': len(node_to_ip),
                    'subnets': 1,
                    'is_flat': True
                }

    def analyze_logs(self):
        """Analyze pod logs for errors and warnings"""
        self._print(f"\n{Colors.BOLD}=== Analyzing Pod Logs ==={Colors.ENDC}")

        for cluster in ['cluster1', 'cluster2']:
            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather")
            if not os.path.exists(gather_dir):
                continue

            # Find log files
            for subdir in os.listdir(gather_dir):
                subdir_path = os.path.join(gather_dir, subdir)
                if os.path.isdir(subdir_path):
                    # Look for gateway and routeagent logs
                    gateway_logs = []
                    routeagent_logs = []

                    for file in os.listdir(subdir_path):
                        if 'submariner-gateway' in file and file.endswith('.log'):
                            gateway_logs.append(os.path.join(cluster, "gather", subdir, file))
                        elif 'submariner-routeagent' in file and file.endswith('.log'):
                            routeagent_logs.append(os.path.join(cluster, "gather", subdir, file))

                    # Analyze gateway logs
                    for log_path in gateway_logs:
                        self.analyze_log_file(log_path, cluster, "gateway")

                    # Analyze routeagent logs
                    for log_path in routeagent_logs:
                        self.analyze_log_file(log_path, cluster, "routeagent")

    def analyze_log_file(self, log_path, cluster_name, component):
        """Analyze a single log file for significant errors"""
        content = self.read_file(log_path)
        if not content:
            return

        errors = []

        # Skip health check ping failures and cleanup errors as they're symptoms not root causes
        skip_patterns = [
            'Failed to successfully ping',
            'healthChecker timed out',
            'health check.*timeout',
            'ping.*timeout',
            'error clearing chain',  # Transient cleanup errors (e.g., "Device or resource busy")
            'error deleting chain',  # Transient cleanup errors during endpoint removal
        ]

        # Significant error patterns to look for
        significant_patterns = [
            (r'unrecognized option.*--encapsulation', 'Libreswan version incompatibility - whack does not recognize --encapsulation flag'),
            (r'whack:.*unrecognized option', 'Libreswan whack command failed - unknown option'),
            (r'error exit status 33.*whack', 'Libreswan whack error - command line parsing failed'),
            (r'CREATE_CHILD_SA failed', 'IPsec tunnel negotiation failed'),
            (r'TS_UNACCEPTABLE', 'Traffic selector negotiation failed'),
            (r'IKE.*failed', 'IKE negotiation failed'),
            (r'route.*failed', 'Route installation failed'),
            (r'iptables.*failed', 'Iptables rule installation failed'),
            (r'Failed to.*cable', 'Cable driver error'),
            (r'NAT.*discovery.*timeout', 'NAT discovery timeout'),
            (r'connection.*refused', 'Connection refused'),
            (r'authentication failed', 'Authentication failed'),
        ]

        # Search for significant errors
        for line in content.split('\n'):
            # Skip if it matches a skip pattern
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in skip_patterns):
                continue

            # Check for significant error patterns
            for pattern, description in significant_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    errors.append((description, line.strip()))
                    break

        # Report significant errors (limit to first 3 to avoid spam)
        if errors:
            self._print(f"  {Colors.FAIL}⚠{Colors.ENDC} {cluster_name}/{component}: Found significant errors in logs:")

            # Check for libreswan version incompatibility
            libreswan_errors = [e for e in errors if 'libreswan' in e[0].lower() or 'whack' in e[0].lower()]

            for i, (description, line) in enumerate(errors[:3]):
                # Truncate very long lines
                if len(line) > 120:
                    line = line[:117] + "..."
                self._print(f"    {i+1}. {description}")
                self._print(f"       {line}")
            if len(errors) > 3:
                self._print(f"    ... and {len(errors) - 3} more errors")

            self.issues.append(f"{cluster_name}/{component}: Found {len(errors)} significant error(s) in logs")

            # Provide specific guidance for libreswan errors
            if libreswan_errors:
                self.issues.append(f"{cluster_name}/{component}: Libreswan version compatibility issue detected")

                # Search GitHub for known issues/fixes
                self._print(f"\n  {Colors.BOLD}Searching GitHub for known issues...{Colors.ENDC}")
                github_results = self.search_github_for_bug("libreswan encapsulation",
                                                             "Libreswan encapsulation flag incompatibility")

                if github_results and github_results['found_fix']:
                    # Fix exists!
                    self._print(f"  {Colors.OKGREEN}✓ Known issue - FIX AVAILABLE{Colors.ENDC}")

                    # Show relevant PRs
                    if github_results['prs']:
                        pr = github_results['prs'][0]  # Most recent/relevant
                        self._print(f"    Fix: {pr['title']}")
                        self._print(f"    PR: {pr['url']}")
                        self._print(f"    Merged: {pr['mergedAt'][:10]}")

                    # Show relevant issues
                    if github_results['issues']:
                        issue = github_results['issues'][0]
                        self._print(f"    Issue: {issue['title']}")
                        self._print(f"    URL: {issue['url']}")
                        self._print(f"    Status: {issue['state']}")

                    self.recommendations.insert(0, f"{Colors.FAIL}KNOWN BUG - FIX AVAILABLE:{Colors.ENDC} Libreswan version incompatibility")
                    self.recommendations.insert(1, f"Upgrade to latest Submariner build (fix merged: {github_results['prs'][0]['mergedAt'][:10]})" if github_results['prs'] else "Upgrade to latest Submariner build")
                    self.recommendations.insert(2, f"GitHub: {github_results['prs'][0]['url']}" if github_results['prs'] else f"GitHub: {github_results['issues'][0]['url']}" if github_results['issues'] else "GitHub: https://github.com/submariner-io/submariner/issues")
                    self.recommendations.insert(3, "Workaround: Switch to VxLAN cable driver if upgrade not immediately possible")
                elif github_results and github_results['issues']:
                    # Issue reported but no fix yet
                    self._print(f"  {Colors.WARNING}⚠ Known issue - NO FIX YET{Colors.ENDC}")
                    issue = github_results['issues'][0]
                    self._print(f"    Issue: {issue['title']}")
                    self._print(f"    URL: {issue['url']}")
                    self._print(f"    Status: {issue['state']}")

                    self.recommendations.insert(0, f"{Colors.FAIL}KNOWN BUG:{Colors.ENDC} {cluster_name} - Libreswan version incompatibility")
                    self.recommendations.insert(1, f"Track issue: {issue['url']}")
                    self.recommendations.insert(2, "Workaround: Switch to VxLAN cable driver")
                    self.recommendations.insert(3, "Contact Submariner - Slack: https://kubernetes.slack.com/archives/C010RJV694M")
                else:
                    # No GitHub results (either gh CLI not available or new bug)
                    if github_results is None:
                        self._print(f"  {Colors.WARNING}(GitHub CLI not available - skipping online search){Colors.ENDC}")

                    self.recommendations.insert(0, f"{Colors.FAIL}CRITICAL:{Colors.ENDC} {cluster_name} - Libreswan version incompatibility - this is a Submariner software bug")
                    self.recommendations.insert(1, "Contact Submariner experts - Slack: https://kubernetes.slack.com/archives/C010RJV694M")
                    self.recommendations.insert(2, "Open GitHub issue: https://github.com/submariner-io/submariner/issues")
                    self.recommendations.insert(3, "Provide diagnostic tarball and mention libreswan version incompatibility with --encapsulation flag")
            else:
                self.recommendations.append(
                    f"{cluster_name}/{component}: Review pod logs for detailed error messages"
                )

    def search_github_for_bug(self, search_terms, bug_description):
        """Search GitHub issues and PRs for known bugs

        Args:
            search_terms: String to search for (e.g., "libreswan encapsulation")
            bug_description: Human-readable description of the bug

        Returns:
            dict with 'issues' and 'prs' lists, or None if gh CLI not available
        """
        try:
            # Check if gh CLI is available
            result = subprocess.run(['gh', '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

        results = {'issues': [], 'prs': [], 'found_fix': False}

        try:
            # Search for issues
            issue_cmd = [
                'gh', 'issue', 'list',
                '--repo', 'submariner-io/submariner',
                '--search', search_terms,
                '--state', 'all',
                '--limit', '5',
                '--json', 'number,title,state,url'
            ]
            issue_result = subprocess.run(issue_cmd, capture_output=True, text=True, timeout=10)
            if issue_result.returncode == 0:
                results['issues'] = json.loads(issue_result.stdout)

            # Search for PRs
            pr_cmd = [
                'gh', 'pr', 'list',
                '--repo', 'submariner-io/submariner',
                '--search', search_terms,
                '--state', 'merged',
                '--limit', '5',
                '--json', 'number,title,mergedAt,url'
            ]
            pr_result = subprocess.run(pr_cmd, capture_output=True, text=True, timeout=10)
            if pr_result.returncode == 0:
                results['prs'] = json.loads(pr_result.stdout)
                # Check if any PRs found (indicates fix exists)
                if results['prs']:
                    results['found_fix'] = True

        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return None

        return results if (results['issues'] or results['prs']) else None

    def colorize_status(self, status):
        """Add color to status based on value"""
        if status == 'connected':
            return f"{Colors.OKGREEN}{status}{Colors.ENDC}"
        elif status == 'error':
            return f"{Colors.FAIL}{status}{Colors.ENDC}"
        else:
            return f"{Colors.WARNING}{status}{Colors.ENDC}"

    def _strip_colors(self, text):
        """Remove ANSI color codes from text"""
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', text)

    def generate_slack_report(self):
        """Generate condensed report for Slack (clean, no colors, ~50-60 lines)"""
        output = []

        output.append("🤖 **Submariner Diagnostics Analysis**")
        output.append("")
        output.append(f"📁 File: {os.path.basename(self.tarball_path)}")
        output.append(f"🕐 Analyzed: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        output.append("")

        # Critical warnings first
        has_not_deployed = any("not deployed" in fault.lower() for fault in self.faulty_states)
        has_version_mismatch = (
            any("version mismatch" in fault.lower() for fault in self.faulty_states)
            or any("different submariner versions" in fault.lower() for fault in self.faulty_states)
        )

        if has_not_deployed:
            output.append("⚠️ **CRITICAL: SUBMARINER NOT DEPLOYED**")
            output.append("Analysis is NOT VALID - no Submariner components found")
            output.append("")
        elif has_version_mismatch:
            output.append("⚠️ **WARNING: VERSION MISMATCH DETECTED**")
            output.append("Analysis results may be INCORRECT or MISLEADING")
            output.append("")

        # Datapath segmentation analysis (if RouteAgent data available)
        if hasattr(self, 'routeagent_data') and self.routeagent_data and self.tunnel_status:
            for cluster in ['cluster1', 'cluster2']:
                if cluster not in self.routeagent_data:
                    continue

                ra_data = self.routeagent_data[cluster]
                gw_status = self.tunnel_status.get(cluster, {}).get('status', 'unknown')

                # Check for the local routing failure pattern
                if gw_status == 'connected' and ra_data.get('errors', 0) > 0:
                    output.append("🔍 **ROOT CAUSE ANALYSIS:**")
                    output.append("✓ Gateway → Remote Gateway: CONNECTED")
                    output.append("✗ Non-gateway nodes → Remote Gateway: FAILED")
                    output.append("")
                    output.append("**Datapath Segmentation:**")
                    output.append("```")
                    output.append("Full path: Non-GW → Local-GW → Remote-GW")
                    output.append("           └─ Segment 1 ─┘  └─ Segment 2 ─┘")
                    output.append("```")
                    output.append("• Segment 2 (GW → GW): ✓ HEALTHY (tunnel connected)")
                    output.append(f"• Segment 1 (Non-GW → GW): ✗ FAILING ({ra_data.get('errors', 0)} nodes)")
                    output.append("")
                    output.append("**Diagnosis:** INTRA-cluster routing issue")
                    output.append("• Inter-cluster tunnel working")
                    output.append("• Problem: Non-gateway nodes cannot reach local gateway")
                    output.append("")

                    # Check if OVN-K and validation was done
                    ovn_issues = [issue for issue in self.issues if 'OVN' in issue and cluster in issue]
                    if not ovn_issues and hasattr(self, 'network_topology'):
                        # OVN config appears correct
                        output.append("🔧 **OVN-K CONFIGURATION:**")
                        output.append("✓ Submariner configured OVN-Kubernetes correctly:")
                        output.append("  • IP rules present (rule 150 for remote CIDR)")
                        output.append("  • OVN router policies present (priority 20000)")
                        output.append("  • OVN static routes present on gateway")
                        output.append("")
                        output.append("**Conclusion:** Most likely infrastructure or OVN-K platform issue")
                        output.append("")

                    # Network topology
                    if cluster in self.network_topology:
                        topo = self.network_topology[cluster]
                        if isinstance(topo, dict) and 'subnets' in topo and isinstance(topo['subnets'], dict) and len(topo['subnets']) > 1:
                            output.append("📊 **NETWORK TOPOLOGY:**")
                            output.append("⚠️ Non-flat networking detected")
                            for subnet, count in sorted(topo['subnets'].items()):
                                output.append(f"  • {subnet} ({count} nodes)")
                            output.append("")

                    break  # Only show for first cluster with this pattern

        # Check for other critical patterns if local routing wasn't detected
        if not any("ROOT CAUSE ANALYSIS" in line for line in output):
            # Check for tunnel failures
            if self.tunnel_status:
                status1 = self.tunnel_status.get('cluster1', {}).get('status', 'unknown')
                status2 = self.tunnel_status.get('cluster2', {}).get('status', 'unknown')

                # Asymmetric tunnel
                if (status1 == 'connected' and status2 != 'connected') or (status2 == 'connected' and status1 != 'connected'):
                    output.append("🔍 **ROOT CAUSE ANALYSIS:**")
                    output.append("⚠️ **ASYMMETRIC TUNNEL STATUS DETECTED**")
                    output.append(f"• Cluster1 → Cluster2: {status1.upper()}")
                    output.append(f"• Cluster2 → Cluster1: {status2.upper()}")
                    output.append("")

                    # Check for mixed RouteAgent pattern on the error cluster
                    error_cluster = 'cluster2' if status2 != 'connected' else 'cluster1'
                    ra_data_error = self.routeagent_data.get(error_cluster, {})
                    connected_count = ra_data_error.get('connected', 0)
                    error_count = ra_data_error.get('errors', 0)

                    # If SOME workers connected on error cluster = NOT infrastructure blocking
                    if connected_count > 0 and error_count > 0:
                        output.append("**Critical Finding:**")
                        output.append(f"• {error_cluster}: {connected_count} workers CAN reach remote cluster")
                        output.append(f"• {error_cluster}: {error_count} worker(s) CANNOT reach remote cluster")
                        output.append("")
                        output.append("**Diagnosis:** Node-specific routing/SNAT issue")
                        output.append("• NOT infrastructure/firewall blocking (some nodes work)")
                        output.append("• Likely cause: Gateway node or specific workers have routing misconfiguration")
                        output.append("• Check routing tables on failing nodes")
                        output.append("")
                    else:
                        output.append("**Possible causes:**")
                        output.append("• SNAT/routing issue (one direction failing)")
                        output.append("• Firewall blocking return traffic")
                        output.append("• OVN-K local gateway mode issue (if using OVN-K)")
                        output.append("")

                # Both tunnels down
                elif status1 != 'connected' and status2 != 'connected':
                    output.append("🔍 **ROOT CAUSE ANALYSIS:**")
                    output.append("✗ **TUNNEL NOT CONNECTED (both clusters)**")
                    output.append(f"• Cluster1 → Cluster2: {status1.upper()}")
                    output.append(f"• Cluster2 → Cluster1: {status2.upper()}")
                    output.append("")
                    output.append("**Likely cause:** Infrastructure/firewall blocking tunnel traffic")
                    output.append("")

            # Check for MTU issues
            if hasattr(self, 'verify_tests_run') and self.verify_tests_run:
                mtu_issue = any("MTU issue detected" in fault.lower() or "mtu" in issue.lower()
                               for fault in self.faulty_states for issue in self.issues)
                if mtu_issue:
                    output.append("🔍 **ROOT CAUSE ANALYSIS:**")
                    output.append("📦 **MTU/FRAGMENTATION ISSUE DETECTED**")
                    output.append("• Regular packets: FAILED")
                    output.append("• Small packets (400 bytes): PASSED")
                    output.append("")
                    output.append("**Diagnosis:** Submariner encapsulation overhead exceeds MTU")
                    output.append("**Solution:** Apply TCP MSS clamping")
                    output.append("")

            # Check for Gateway HA issues
            if hasattr(self, 'faulty_states'):
                ha_issue = any("multiple active" in fault.lower() or "gateway ha" in fault.lower()
                              for fault in self.faulty_states)
                if ha_issue:
                    output.append("🔍 **ROOT CAUSE ANALYSIS:**")
                    output.append("⚠️ **GATEWAY HA ISSUE DETECTED**")
                    output.append("• Multiple active gateway pods found")
                    output.append("")
                    output.append("**Impact:** ~50% packet loss (random failures)")
                    output.append("**Cause:** HA label mismatch")
                    output.append("")

        # Status summary
        if not self.faulty_states and not self.issues:
            output.append("✅ **STATUS: HEALTHY**")
            output.append("  • All tunnels connected")
            output.append("  • No significant errors detected")
            if self.verify_tests_run and self.verify_tests_passed:
                output.append("  • Verification tests passed")
            output.append("")
        elif self.issues:
            output.append("⚠️ **ISSUES DETECTED:**")
            for issue in self.issues[:5]:  # Top 5 issues only
                clean_issue = self._strip_colors(issue)
                output.append(f"  • {clean_issue}")
            if len(self.issues) > 5:
                output.append(f"  ... and {len(self.issues) - 5} more (see full analysis)")
            output.append("")

        # Top recommendations
        if self.recommendations:
            output.append("💡 **RECOMMENDATIONS:**")
            seen = set()
            unique_recs = [rec for rec in self.recommendations if rec not in seen and not seen.add(rec)]
            for i, rec in enumerate(unique_recs[:5], 1):  # Top 5 recommendations
                clean_rec = self._strip_colors(rec)
                output.append(f"{i}. {clean_rec}")
            if len(unique_recs) > 5:
                output.append(f"... and {len(unique_recs) - 5} more (see full output)")
            output.append("")

        # Footer
        output.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        output.append("📖 Docs: https://submariner.io/operations/troubleshooting/")
        output.append("📋 For full analysis, run script with --format terminal")

        print("\n".join(output))

    def generate_report(self):
        """Generate final analysis report"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}ANALYSIS SUMMARY{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}")

        # Check for version issues and display prominent warning at top
        has_not_deployed = any("not deployed" in fault.lower() for fault in self.faulty_states)
        has_version_mismatch = (
            any("version mismatch" in fault.lower() for fault in self.faulty_states)
            or any("different submariner versions" in fault.lower() for fault in self.faulty_states)
        )

        if has_not_deployed:
            print(f"\n{Colors.FAIL}╔{'═'*58}╗{Colors.ENDC}")
            print(f"{Colors.FAIL}║  ⚠ CRITICAL: SUBMARINER NOT DEPLOYED                    ║{Colors.ENDC}")
            print(f"{Colors.FAIL}║  Analysis is NOT VALID - no Submariner components found ║{Colors.ENDC}")
            print(f"{Colors.FAIL}╚{'═'*58}╝{Colors.ENDC}")
            print(f"{Colors.WARNING}Deploy Submariner on both clusters before collecting diagnostics.{Colors.ENDC}\n")
        elif has_version_mismatch:
            print(f"\n{Colors.FAIL}╔{'═'*58}╗{Colors.ENDC}")
            print(f"{Colors.FAIL}║  ⚠ WARNING: VERSION MISMATCH DETECTED                   ║{Colors.ENDC}")
            print(f"{Colors.FAIL}║  Analysis results below may be INCORRECT or MISLEADING  ║{Colors.ENDC}")
            print(f"{Colors.FAIL}╚{'═'*58}╝{Colors.ENDC}")
            print(f"{Colors.WARNING}Recommend fixing version compatibility before trusting this analysis.{Colors.ENDC}\n")

        if not self.faulty_states and not self.issues:
            # Healthy state (only possible if verify tests weren't run or if they passed)
            print(f"\n{Colors.OKGREEN}{'✓'*3} SUBMARINER DEPLOYMENT APPEARS HEALTHY {'✓'*3}{Colors.ENDC}")
            print(f"\n{Colors.OKGREEN}No faulty states detected:{Colors.ENDC}")
            print("  ✓ All tunnels in 'connected' state")

            # Provide detailed verify test status
            if self.verify_tests_run and self.verify_tests_passed:
                print("  ✓ Verification tests passed - comprehensive datapath validated")
                print("    (Tests cover all connectivity paths: local pod ↔ remote pod on gateway/non-gateway nodes)")
            else:
                # Tests not run
                print("  • Verification tests not run (tunnels healthy but datapath not fully validated)")

            print("  ✓ No significant errors in pod logs")

            if self.verify_tests_run and self.verify_tests_passed:
                print(f"\n{Colors.BOLD}Status:{Colors.ENDC} Submariner is functioning correctly - tunnels connected and datapath validated")
            else:
                print(f"\n{Colors.BOLD}Status:{Colors.ENDC} Submariner tunnels appear healthy")
                print(f"{Colors.BOLD}Note:{Colors.ENDC} Run 'subctl verify' for comprehensive datapath validation")
        elif not self.issues:
            # Faulty states found but no specific issues identified
            print(f"\n{Colors.WARNING}Faulty States Detected ({len(self.faulty_states)}):{Colors.ENDC}")
            for fault in self.faulty_states:
                print(f"  • {fault}")
            print(f"\n{Colors.WARNING}Note: Could not identify specific root causes.{Colors.ENDC}")
            print("Consider using advanced AI analysis for deeper investigation.")
        else:
            # Issues found
            print(f"\n{Colors.FAIL}Issues Detected ({len(self.issues)}):{Colors.ENDC}")
            for issue in self.issues:
                print(f"  • {issue}")

        if self.recommendations:
            print(f"\n{Colors.BOLD}Recommendations:{Colors.ENDC}")
            # Remove duplicates while preserving order
            seen = set()
            unique_recs = []
            for rec in self.recommendations:
                if rec not in seen:
                    seen.add(rec)
                    unique_recs.append(rec)

            for i, rec in enumerate(unique_recs, 1):
                # Highlight kubectl commands in cyan
                formatted_rec = re.sub(
                    r'(kubectl [^"\n]+)',
                    f'{Colors.OKCYAN}\\1{Colors.ENDC}',
                    rec
                )
                print(f"  {i}. {formatted_rec}")

        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")

        if self.faulty_states or self.issues:
            print(f"\n{Colors.WARNING}IMPORTANT NOTE:{Colors.ENDC}")
            print("  📖 Verify Submariner Prerequisites:")
            print("     https://submariner.io/operations/deployment/prerequisites/")
            print("")
            print("  • Try the recommended solutions in order")
            print("  • If issues persist, contact Submariner community:")
            print("    - Submariner Slack: https://kubernetes.slack.com/archives/C010RJV694M")
            print("    - GitHub Issues: https://github.com/submariner-io/submariner/issues")

        print(f"\n{Colors.BOLD}For deeper AI-powered analysis:{Colors.ENDC}")
        print("  See README.md for instructions on setting up advanced AI analysis")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

    def check_api_server_health(self):
        """Check for API server rate limiter errors in Gateway pod logs"""
        self._print(f"\n{Colors.BOLD}=== Checking API Server Health ==={Colors.ENDC}")

        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs:
            return

        for cluster in ['cluster1', 'cluster2']:
            actual_cluster_name = cluster_subdirs.get(cluster)
            if not actual_cluster_name:
                continue

            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)
            if not os.path.exists(gather_dir):
                continue

            # Find Gateway pod logs
            gateway_logs = []
            for file in os.listdir(gather_dir):
                if "submariner-gateway-" in file and file.endswith("-submariner-gateway.log"):
                    gateway_logs.append(os.path.join(cluster, "gather", actual_cluster_name, file))

            if not gateway_logs:
                continue

            # Check for rate limiter errors
            rate_limiter_errors = 0
            for log_file in gateway_logs:
                content = self.read_file(log_file)
                if content:
                    rate_limiter_errors += content.count("rate limiter Wait returned an error")

            if rate_limiter_errors > 0:
                self.issues.append(f"{cluster}: API server showing {rate_limiter_errors} rate limiter errors")
                self._print(f"  {Colors.FAIL}✗{Colors.ENDC} {cluster}: Found {rate_limiter_errors} API server rate limiter errors")
                self._print("    → This could indicate API server performance/stability issues")
                self.recommendations.append(f"{cluster}: Consider checking API server health with 'oc adm top nodes', control plane resource utilization, and API server logs")
            else:
                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {cluster}: No API server rate limiter errors detected")

    def check_ip_rule_consistency(self):
        """Check for IP rule differences between clusters, especially fwmark 0x3f0"""
        self._print(f"\n{Colors.BOLD}=== Checking IP Rule Consistency ==={Colors.ENDC}")

        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs:
            return

        fwmark_0x3f0_clusters = []

        for cluster in ['cluster1', 'cluster2']:
            actual_cluster_name = cluster_subdirs.get(cluster)
            if not actual_cluster_name:
                continue

            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)
            if not os.path.exists(gather_dir):
                continue

            # Find ip-rules.log files
            has_fwmark_rule = False
            node_count = 0
            affected_nodes = []

            for file in os.listdir(gather_dir):
                if file.endswith("_ip-rules.log"):
                    node_count += 1
                    node_name = file.replace("_ip-rules.log", "")
                    content = self.read_file(os.path.join(cluster, "gather", actual_cluster_name, file))
                    if content and "fwmark 0x3f0" in content:
                        has_fwmark_rule = True
                        affected_nodes.append(node_name)

            if has_fwmark_rule:
                fwmark_0x3f0_clusters.append({
                    'cluster': cluster,
                    'nodes': affected_nodes,
                    'total_nodes': node_count
                })

        # Report findings
        if len(fwmark_0x3f0_clusters) == 1:
            cluster_info = fwmark_0x3f0_clusters[0]
            cluster_name = cluster_info['cluster']
            self._print(f"  {Colors.FAIL}✗{Colors.ENDC} IP rule inconsistency detected!")
            self._print(f"    {cluster_name}: Has 'fwmark 0x3f0' rule on {len(cluster_info['nodes'])}/{cluster_info['total_nodes']} nodes")

            other_cluster = 'cluster2' if cluster_name == 'cluster1' else 'cluster1'
            self._print(f"    {other_cluster}: Does NOT have this rule")

            self.issues.append(f"{cluster_name}: Has extra IP rule 'fwmark 0x3f0' that {other_cluster} doesn't have")
            self._print(f"\n    {Colors.WARNING}Possible Impact:{Colors.ENDC} Gateway pod traffic may be marked with fwmark 0x3f0,")
            self._print("    which could cause packets to bypass table 150 routes and use main table instead.")
            self._print("    This might lead to 'source IP = 0.0.0.0' errors in health check pings.")
            self.recommendations.append(f"{cluster_name}: Consider investigating why 'ip rule fwmark 0x3f0' exists - it appears to be added by OVN-Kubernetes or NetworkPolicy")

        elif len(fwmark_0x3f0_clusters) == 2:
            self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Both clusters have 'fwmark 0x3f0' rule (consistent)")
        else:
            self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} Neither cluster has 'fwmark 0x3f0' rule (consistent)")

    def check_ovn_routing(self):
        """
        Check OVN routing configuration for Submariner.

        Submariner uses two types of routing in OVN:
        1. Gateway nodes: OVN router policies + static routes (via ovn-k8s-mp0 interface)
        2. Non-gateway nodes: OVN router policies only (via transit switch IP)

        Reference: https://github.com/submariner-io/enhancements/blob/devel/seps/SEP-0027-ovn-interconnect.md
        """
        self._print(f"\n{Colors.BOLD}=== Checking OVN Routing Configuration ==={Colors.ENDC}")

        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs:
            return

        for cluster in ['cluster1', 'cluster2']:
            actual_cluster_name = cluster_subdirs.get(cluster)
            if not actual_cluster_name:
                continue

            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)
            if not os.path.exists(gather_dir):
                continue

            # Get remote cluster CIDRs from GatewayRoute first, then fall back to Submariner CR
            remote_cidrs = set()

            # Read Submariner CR from the same resolved gather directory
            gateway_cr = None
            for file in os.listdir(gather_dir):
                if file.startswith("submariners_") and file.endswith(".yaml"):
                    gateway_cr = self.read_yaml(os.path.join(cluster, "gather", actual_cluster_name, file))
                    break

            # Aggregate remote CIDRs from every GatewayRoute CR in the bundle
            for file in os.listdir(gather_dir):
                if not file.startswith("gatewayroutes_"):
                    continue
                gateway_route_content = self.read_file(os.path.join(cluster, "gather", actual_cluster_name, file))
                if not gateway_route_content:
                    continue
                try:
                    gateway_route = yaml.safe_load(gateway_route_content)
                    if gateway_route and 'spec' in gateway_route:
                        remote_cidrs.update(gateway_route['spec'].get('remoteCIDRs', []))
                except (yaml.YAMLError, ValueError) as exc:
                    self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster}: failed to parse {file}: {exc}")

            # Fall back to Submariner CR if no GatewayRoute found
            if not remote_cidrs:
                if gateway_cr and 'status' in gateway_cr:
                    for gw in gateway_cr['status'].get('gateways', []):
                        for conn in gw.get('connections', []):
                            remote_cidrs.update(conn.get('endpoint', {}).get('subnets', []))

            if not remote_cidrs:
                self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster}: no remote CIDRs found for OVN route validation")
                continue

            # Get active gateway node hostname from Gateway CR
            active_gateway_node = None
            if gateway_cr and 'status' in gateway_cr:
                gateways = gateway_cr['status'].get('gateways', [])
                for gw in gateways:
                    if gw.get('haStatus') == 'active':
                        active_gateway_node = gw.get('localEndpoint', {}).get('hostname')
                        break

            # Check OVN router policies (should exist on ALL nodes)
            policies_checked = False
            for file in os.listdir(gather_dir):
                if file.endswith("_ovn_lr_ovn_cluster_router_policies.log"):
                    policies_content = self.read_file(os.path.join(cluster, "gather", actual_cluster_name, file))
                    if policies_content:
                        policies_checked = True
                        node_name = file.replace("_ovn_lr_ovn_cluster_router_policies.log", "")
                        # Check for Submariner router policies (priority 20000)
                        for cidr in remote_cidrs:
                            policy_match = f"ip4.dst == {cidr}"
                            # Check that both the CIDR and exact priority 20000 appear on the same line
                            found = False
                            for line in policies_content.splitlines():
                                if policy_match in line and re.search(r'\b20000\b', line):
                                    found = True
                                    break
                            if found:
                                self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {cluster}/{node_name}: OVN router policy found for {cidr}")
                            else:
                                self._print(f"  {Colors.FAIL}✗{Colors.ENDC} {cluster}/{node_name}: OVN router policy MISSING for {cidr}")
                                self.issues.append(f"{cluster}/{node_name}: OVN router policy missing for {cidr}")

            if not policies_checked:
                self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster}: no OVN router policy logs found")

            # Check OVN static routes (should ONLY exist on gateway nodes)
            if active_gateway_node:
                gateway_routes_file = f"{active_gateway_node}_ovn_lr_ovn_cluster_router_routes.log"
                gateway_routes_path = os.path.join(cluster, "gather", actual_cluster_name, gateway_routes_file)
                routes_content = self.read_file(gateway_routes_path)

                if routes_content:
                    for cidr in remote_cidrs:
                        if cidr in routes_content:
                            self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {cluster}: OVN static route found for {cidr} on gateway node")
                        else:
                            self._print(f"  {Colors.FAIL}✗{Colors.ENDC} {cluster}: OVN static route MISSING for {cidr} on gateway node")
                            self.issues.append(f"{cluster}: OVN static route missing for {cidr} on gateway node")
                else:
                    self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster}: Could not read OVN routes from gateway node {active_gateway_node}")
            else:
                self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster}: Could not determine active gateway node")

    def validate_ovnk_configuration(self):
        """
        Cross-validate OVN-K configuration: IP rules, table 150, OVN policies, and CRs.

        If Gateway=connected and RouteAgent=error, verify Submariner configured OVN-K correctly.
        """
        # Only run this if we have OVN-K CNI and local routing issue detected
        if not hasattr(self, 'routeagent_data'):
            return

        for cluster in ['cluster1', 'cluster2']:
            if cluster not in self.routeagent_data:
                continue

            ra_data = self.routeagent_data[cluster]

            # Check if we have the pattern: Gateway connected + RouteAgent errors
            gw_status = self.tunnel_status.get(cluster, {}).get('status', "unknown")
            if gw_status != "connected" or ra_data.get('errors', 0) == 0:
                continue  # Skip if not the right pattern

            self._print(f"\n{Colors.BOLD}=== OVN-K Configuration Validation for {cluster} ==={Colors.ENDC}")
            self._print(f"  {Colors.OKCYAN}Pattern detected:{Colors.ENDC} Gateway connected + RouteAgent errors")
            self._print(f"  {Colors.OKCYAN}Validating:{Colors.ENDC} Submariner OVN-K configuration")

            # Summarize what THIS validation method checked
            # (Note: check_main_table_routes runs separately in the main analysis flow)
            self._print(f"\n  {Colors.BOLD}OVN-K Validation Summary:{Colors.ENDC}")
            self._print("    ✓ OVN Logical Router Policies checked")
            self._print("    ✓ Submariner CRs: GatewayRoute/NonGatewayRoute present")
            self._print("    (IP rules and table 150 validated separately)")

            # Check if we found any OVN issues
            ovn_issues = [issue for issue in self.issues if 'OVN' in issue and cluster in issue]

            if not ovn_issues:
                self._print(f"\n  {Colors.OKGREEN}✓ All expected Submariner OVN-K configuration appears correct{Colors.ENDC}")
                self._print(f"\n  {Colors.BOLD}Analysis:{Colors.ENDC}")
                self._print("    • Submariner configured OVN-Kubernetes as expected")
                self._print("    • IP rules, table 150, and OVN policies all present")
                self._print("    • Most likely an infrastructure or OVN-K platform issue")
                self._print(f"\n  {Colors.BOLD}Recommendation:{Colors.ENDC}")
                self._print("    Contact Submariner community with these findings:")
                self._print("    - https://kubernetes.slack.com/archives/C010RJV694M")
                self._print("    - https://github.com/submariner-io/submariner/issues")
            else:
                self._print(f"\n  {Colors.FAIL}✗ Found {len(ovn_issues)} OVN configuration issue(s){Colors.ENDC}")
                for issue in ovn_issues[:3]:  # Show first 3
                    self._print(f"    - {issue}")

    def analyze_nftables(self):
        """
        Analyze nftables rules for Submariner datapath issues.

        CRITICAL: Only runs when datapath is broken:
        - Gateway CR status = error, OR
        - RouteAgent CR status = error, OR
        - Connectivity verification failed

        Checks:
        1. Globalnet SNAT rules (Submariner 0.22+)
        2. OVN-K mgmtport SNAT exemptions
        3. MSS clamping packet counters
        """
        # Check if datapath is broken
        datapath_broken = False

        # Check tunnel status (any non-connected status is considered broken)
        for cluster in ['cluster1', 'cluster2']:
            gw_status = self.tunnel_status.get(cluster, {}).get('status', 'unknown')
            if gw_status != 'connected':
                datapath_broken = True
                break

        # Check RouteAgent status
        if hasattr(self, 'routeagent_data'):
            for cluster in ['cluster1', 'cluster2']:
                if cluster in self.routeagent_data:
                    if self.routeagent_data[cluster].get('errors', 0) > 0:
                        datapath_broken = True
                        break

        # Check connectivity verification failures
        if hasattr(self, 'faulty_states'):
            for fault in self.faulty_states:
                if 'connectivity verification failed' in fault.lower():
                    datapath_broken = True
                    break

        # Early exit if datapath is healthy
        if not datapath_broken:
            return

        self._print(f"\n{Colors.BOLD}=== Analyzing nftables Rules (Submariner 0.22+) ==={Colors.ENDC}")
        self._print(f"  {Colors.OKBLUE}ℹ{Colors.ENDC} Checking nftables because datapath issues detected")

        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs:
            return

        for cluster in ['cluster1', 'cluster2']:
            actual_cluster_name = cluster_subdirs.get(cluster)
            if not actual_cluster_name:
                continue

            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)
            if not os.path.exists(gather_dir):
                continue

            self._print(f"\n  Checking {cluster}:")

            # Find nftables files
            nftables_files = glob.glob(os.path.join(gather_dir, "*_nftables.log"))
            if not nftables_files:
                self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} No nftables files found (pre-0.22 or collection failed)")
                continue

            # Check if globalnet is enabled
            globalnet_enabled = self.detect_globalnet(cluster)

            # Analyze gateway node nftables
            # Get active gateway node from Gateway CR
            gateway_node = None
            gateway_cr = self.find_and_read_gateway_cr(cluster)
            if gateway_cr and 'status' in gateway_cr:
                gateways = gateway_cr['status'].get('gateways', [])
                for gw in gateways:
                    if gw.get('haStatus') == 'active':
                        gateway_node = gw.get('localEndpoint', {}).get('hostname')
                        break

            if gateway_node:
                # Validate gateway_node to prevent path traversal
                # Only allow alphanumeric, hyphens, underscores, and dots
                if not re.match(r'^[a-zA-Z0-9._-]+$', gateway_node):
                    self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} Invalid gateway node name: {gateway_node}")
                else:
                    self._print(f"    Analyzing gateway node: {gateway_node}")
                    gateway_nft_file = os.path.join(gather_dir, f"{gateway_node}_nftables.log")

                    # Verify the resolved path is within gather_dir (prevent traversal)
                    real_gather_dir = os.path.realpath(gather_dir)
                    real_nft_file = os.path.realpath(gateway_nft_file)
                    if not real_nft_file.startswith(real_gather_dir):
                        self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} Path traversal attempt detected")
                    elif os.path.exists(gateway_nft_file):
                        self._analyze_nftables_file(gateway_nft_file, cluster, gateway_node,
                                                    globalnet_enabled, is_gateway=True)

            # Check OVN-K SNAT exemptions on all nodes if OVN-K
            cni = self.detect_cni(cluster)
            if "OVN" in cni:
                self._check_ovn_snat_exemptions(gather_dir, cluster)

    def _analyze_nftables_file(self, nft_file, cluster, node_name, globalnet_enabled, is_gateway=False):
        """Parse and analyze a single nftables file."""
        try:
            with open(nft_file, encoding='utf-8') as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} Failed to read nftables file from {node_name}: {e}")
            return

        # Check 1: Globalnet SNAT rules (only on gateway, only if globalnet enabled)
        if is_gateway and globalnet_enabled:
            self._check_globalnet_snat(content, cluster, node_name)

        # Check 2: MSS clamping
        if is_gateway:
            self._check_mss_clamping(content, cluster, node_name)

    def _check_globalnet_snat(self, nft_content, cluster, node_name):
        """Check for globalnet SNAT rules in SUBMARINER-POSTROUTING chain."""
        # Find SUBMARINER-POSTROUTING chain
        postrouting_match = re.search(r'chain SUBMARINER-POSTROUTING \{([^}]+)\}', nft_content, re.DOTALL)
        if not postrouting_match:
            self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} SUBMARINER-POSTROUTING chain not found")
            return

        chain_content = postrouting_match.group(1)

        # Look for SNAT rules (format: "snat to X.X.X.X" or "snat ip to X.X.X.X")
        snat_rules = re.findall(r'snat (?:ip )?to (\S+)', chain_content)

        if not snat_rules:
            self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} No globalnet SNAT rules found (globalnet enabled but no SNAT)")
            self.issues.append(f"{cluster}: Globalnet enabled but no SNAT rules in nftables")
            return

        # Check for 0.0.0.0 SNAT (the bug we're trying to catch!)
        for snat_ip in snat_rules:
            if snat_ip == "0.0.0.0":
                self._print(f"    {Colors.FAIL}✗{Colors.ENDC} Globalnet SNAT to 0.0.0.0 detected!")
                self.issues.append(f"{cluster}: Globalnet SNAT IP is 0.0.0.0 (source IP allocation failed)")
            else:
                self._print(f"    {Colors.OKGREEN}✓{Colors.ENDC} Globalnet SNAT to {snat_ip}")

        # Check packet counters
        counter_match = re.search(r'snat.*counter packets (\d+) bytes', chain_content)
        if counter_match:
            packets = int(counter_match.group(1))
            if packets == 0:
                self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} Globalnet SNAT rule exists but 0 packets matched")
                self._print("      → Likely: Traffic not reaching nftables (check IP rules)")

    def _check_mss_clamping(self, nft_content, cluster, node_name):
        """Check MSS clamping packet counters."""
        # Find SUBMARINER-POSTROUTING-MSS chain
        mss_match = re.search(r'chain SUBMARINER-POSTROUTING-MSS \{([^}]+)\}', nft_content, re.DOTALL)
        if not mss_match:
            return  # MSS clamping chain not found (optional feature)

        chain_content = mss_match.group(1)

        # Extract packet counters
        counters = re.findall(r'counter packets (\d+) bytes', chain_content)
        if counters:
            total_packets = sum(int(c) for c in counters)
            if total_packets > 0:
                self._print(f"    {Colors.OKGREEN}✓{Colors.ENDC} MSS clamping active ({total_packets} SYN packets clamped)")

    def _check_ovn_snat_exemptions(self, gather_dir, cluster):
        """Check OVN-K mgmtport SNAT exemptions for Submariner CIDRs on all nodes."""
        self._print(f"\n    {Colors.BOLD}OVN-K SNAT Exemption Check:{Colors.ENDC}")

        # Get remote cluster CIDRs that should be exempted
        remote_cidrs = self._get_remote_cidrs(cluster)
        if not remote_cidrs:
            self._print(f"      {Colors.WARNING}⚠{Colors.ENDC} No remote CIDRs found")
            return

        self._print(f"      Checking CIDRs: {', '.join(remote_cidrs)}")

        # Find all nftables files (check all nodes, not just gateway)
        nftables_files = glob.glob(os.path.join(gather_dir, "*_nftables.log"))
        if not nftables_files:
            self._print(f"      {Colors.WARNING}⚠{Colors.ENDC} No nftables files found")
            return

        nodes_checked = 0
        node_issues = {}

        for nft_file in nftables_files:
            node_name = os.path.basename(nft_file).replace('_nftables.log', '')

            try:
                with open(nft_file, encoding='utf-8') as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            # Find mgmtport-no-snat-subnets-v4 set
            snat_exempt_match = re.search(
                r'set mgmtport-no-snat-subnets-v4 \{[^}]*elements = \{([^}]+)\}',
                content, re.DOTALL
            )

            if not snat_exempt_match:
                # OVN-K set not found - treat as missing configuration
                node_issues[node_name] = ["mgmtport-no-snat-subnets-v4 set not found"]
                self._print(f"      {Colors.WARNING}⚠{Colors.ENDC} {node_name}: mgmtport-no-snat-subnets-v4 set not found")
                continue

            nodes_checked += 1
            exempt_content = snat_exempt_match.group(1)

            # Check each remote CIDR on this node
            missing_exemptions = []
            for cidr in remote_cidrs:
                if cidr not in exempt_content:
                    missing_exemptions.append(cidr)

            if missing_exemptions:
                node_issues[node_name] = missing_exemptions
                self._print(f"      {Colors.FAIL}✗{Colors.ENDC} {node_name}: Missing exemptions: {', '.join(missing_exemptions)}")

        if nodes_checked == 0 and not node_issues:
            self._print(f"      {Colors.WARNING}⚠{Colors.ENDC} No OVN-K SNAT configuration found")
        elif not node_issues:
            self._print(f"      {Colors.OKGREEN}✓{Colors.ENDC} All {nodes_checked} node(s) have correct SNAT exemptions")

        if node_issues:
            for node_name, missing in node_issues.items():
                self.issues.append(
                    f"{cluster}/{node_name}: Remote CIDRs not exempted from OVN mgmtport SNAT: {', '.join(missing)}"
                )
            self._print(f"      {Colors.FAIL}→{Colors.ENDC} OVN will SNAT Submariner traffic (breaks tunnel)")

    def _get_remote_cidrs(self, cluster):
        """Get remote cluster CIDRs (pod + service + globalnet if enabled)."""
        # Use the same logic as check_ovn_routing() to get remote CIDRs
        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs or cluster not in cluster_subdirs:
            return []

        actual_cluster_name = cluster_subdirs[cluster]
        gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)

        remote_cidrs = set()

        # Get from GatewayRoute CRs (most reliable)
        gateway_routes_pattern = os.path.join(gather_dir, "gatewayroutes_*.yaml")
        gateway_routes_files = glob.glob(gateway_routes_pattern)
        if gateway_routes_files:
            for gr_file in gateway_routes_files:
                # Convert absolute path to relative path for read_yaml
                rel_path = os.path.relpath(gr_file, self.diagnostics_dir)
                gateway_route = self.read_yaml(rel_path)
                if gateway_route and 'spec' in gateway_route:
                    remote_cidrs.update(gateway_route['spec'].get('remoteCIDRs', []))

        # Fallback: Get from Gateway CR connections
        if not remote_cidrs:
            gateway_rel_path = os.path.join(cluster, "gather", actual_cluster_name, "gateway.yaml")
            gateway_cr = self.read_yaml(gateway_rel_path)
            if gateway_cr and 'status' in gateway_cr:
                connections = gateway_cr['status'].get('connections', [])
                for conn in connections:
                    remote_cidrs.update(conn.get('endpoint', {}).get('subnets', []))

        # Add globalnet CIDR if enabled
        globalnet_cidr = self.get_remote_globalnet_cidr(cluster)
        if globalnet_cidr:
            remote_cidrs.add(globalnet_cidr)

        return list(remote_cidrs)

    def check_ovn_local_gateway_mode_issue(self):
        """
        Check for known OVN-Kubernetes local gateway mode health check issue.

        Detection criteria:
        1. CNI is OVN-Kubernetes AND local gateway mode is detected
        2. Gateway CR shows status: error with "Failed to successfully ping"
        3. (Optional) RouteAgent CR shows status: connected despite Gateway error

        Reference: https://github.com/submariner-io/submariner/issues/3857
        """
        self._print(f"\n{Colors.BOLD}=== Checking for OVN-K Local Gateway Mode Issue ==={Colors.ENDC}")

        # Detect CNI for both clusters
        cni_cluster1 = self.detect_cni("cluster1")
        cni_cluster2 = self.detect_cni("cluster2")

        if "OVN" not in cni_cluster1 and "OVN" not in cni_cluster2:
            self._print(f"  {Colors.OKBLUE}ℹ{Colors.ENDC} CNI is not OVN-Kubernetes - skipping OVN local gateway mode check")
            return

        # Method 1: Check for breth0 interface on ALL nodes
        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs:
            return

        for cluster in ['cluster1', 'cluster2']:
            actual_cluster_name = cluster_subdirs.get(cluster)
            if not actual_cluster_name:
                continue

            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)
            if not os.path.exists(gather_dir):
                continue

            self._print(f"\n  Checking {cluster}...")

            # Count nodes with breth0
            breth0_count = 0
            total_nodes = 0
            ip_a_files = []

            for file in os.listdir(gather_dir):
                if file.endswith("_ip-a.log"):
                    total_nodes += 1
                    ip_a_files.append(file)
                    content = self.read_file(os.path.join(cluster, "gather", actual_cluster_name, file))
                    if content and re.search(r'^\d+: breth0:', content, re.MULTILINE):
                        breth0_count += 1

            # Determine gateway mode (local mode = all nodes have breth0)
            if total_nodes == 0:
                self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} Could not determine node count")
                continue

            is_local_mode = (breth0_count == total_nodes)

            if is_local_mode:
                self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} OVN-K gateway mode: LOCAL")
                self._print(f"      - All {total_nodes} nodes have breth0 interface")

                # Check Gateway CR status directly
                gateway_status = 'unknown'
                gateway_message = ''
                gateway_files = [f for f in os.listdir(gather_dir) if f.startswith("gateways_")]
                for gw_file in gateway_files:
                    gw_content = self.read_file(os.path.join(cluster, "gather", actual_cluster_name, gw_file))
                    if gw_content:
                        try:
                            gw_yaml = yaml.safe_load(gw_content)
                            if gw_yaml and 'status' in gw_yaml and 'connections' in gw_yaml['status']:
                                connections = gw_yaml['status']['connections']
                                if isinstance(connections, list) and len(connections) > 0 and isinstance(connections[0], dict):
                                    gateway_status = connections[0].get('status', 'unknown')
                                    gateway_message = connections[0].get('statusMessage', '')
                                    break
                        except yaml.YAMLError:
                            continue

                # Check RouteAgent status using unified method
                routeagent_status = None
                agents = self.find_and_read_routeagent_crs(cluster)
                for ra_yaml in agents:
                    if ra_yaml and 'status' in ra_yaml:
                        remote_endpoints = ra_yaml['status'].get('remoteEndpoints', [])
                        if isinstance(remote_endpoints, list) and remote_endpoints and isinstance(remote_endpoints[0], dict):
                            routeagent_status = remote_endpoints[0].get('status', None)
                            if routeagent_status:
                                break

                # Check for the issue pattern
                has_ping_failure = gateway_status == 'error' and 'ping' in str(gateway_message).lower()
                has_ra_connected = routeagent_status == 'connected'

                if has_ping_failure:
                    self._print(f"    {Colors.FAIL}✗{Colors.ENDC} Gateway status: {gateway_status}")
                    self._print(f"      Message: {gateway_message}")

                    if has_ra_connected:
                        self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} RouteAgent status: {routeagent_status} (discrepancy!)")

                    # Check if globalnet is enabled
                    has_globalnet = self.detect_globalnet(cluster)

                    self._print(f"\n    {Colors.WARNING}⚠ POSSIBLE KNOWN ISSUE DETECTED:{Colors.ENDC}")
                    self._print("      This configuration appears similar to a known issue with")
                    self._print("      OVN-Kubernetes in local gateway mode.")
                    self._print("")
                    self._print(f"      {Colors.BOLD}References:{Colors.ENDC}")
                    self._print("      • Issue: https://github.com/submariner-io/submariner/issues/3857")

                    if not has_globalnet:
                        self._print("      • Community workaround: https://github.com/yboaron/submariner-workarounds/")
                        self._print("        tree/main/ovn-local-gateway-health-check")
                        self._print("")
                        self._print(f"      {Colors.BOLD}Important:{Colors.ENDC} This is a community workaround, not an official fix.")
                        self._print("      Review and test thoroughly before applying.")
                    else:
                        self._print("")
                        self._print(f"      {Colors.BOLD}Note:{Colors.ENDC} Globalnet is enabled - community workaround is NOT applicable.")
                        self._print("      The workaround only works with non-globalnet deployments.")

                    self.faulty_states.append(f"{cluster}: Possible OVN-K local gateway mode issue (health check failure)")
                    self.issues.append(f"{cluster}: Configuration might be affected by OVN-K local gateway mode issue (#3857)")

                    if not has_globalnet:
                        self.recommendations.append(f"{cluster}: Review known issue submariner-io/submariner#3857 and evaluate community workaround")
                    else:
                        self.recommendations.append(f"{cluster}: Review known issue submariner-io/submariner#3857 (note: Globalnet enabled - community workaround not applicable)")
                elif gateway_status == 'connected':
                    self._print(f"    {Colors.OKGREEN}✓{Colors.ENDC} Gateway status: {gateway_status}")
                else:
                    self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} Gateway status: {gateway_status} (but not 'ping' failure pattern)")
            else:
                self._print(f"    {Colors.OKBLUE}ℹ{Colors.ENDC} OVN-K gateway mode: SHARED (or not detected)")
                self._print(f"      - {breth0_count}/{total_nodes} nodes have breth0 interface")

    def verify_ovnk_host_networking(self):
        """
        Verify OVN-K host networking configuration for pinger failures.

        Performs 3 routing checks on ALL nodes:
        1. IP rule 150 exists for remote Globalnet CIDR
        2. Table 150 has default route via ovn-k8s-mp0
        3. ovn-k8s-mp0 interface is UP with IP assigned

        Detects:
        - Missing table 150 routes (most common issue)
        - 0.0.0.0 source errors in gateway logs
        - Configuration differences between gateway and worker nodes
        """
        # Only run for OVN-K with RouteAgent errors
        if not hasattr(self, 'routeagent_data'):
            return

        cni_cluster1 = self.detect_cni("cluster1")
        cni_cluster2 = self.detect_cni("cluster2")

        if "OVN" not in cni_cluster1 and "OVN" not in cni_cluster2:
            return

        self._print(f"\n{Colors.BOLD}=== OVN-K Host Networking Verification ==={Colors.ENDC}")

        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs:
            return

        for cluster in ['cluster1', 'cluster2']:
            # Only check if we have RouteAgent errors
            ra_data = self.routeagent_data.get(cluster, {})
            if ra_data.get('errors', 0) == 0:
                continue

            actual_cluster_name = cluster_subdirs.get(cluster)
            if not actual_cluster_name:
                continue

            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)
            if not os.path.exists(gather_dir):
                continue

            self._print(f"\n  {Colors.BOLD}Checking {cluster}:{Colors.ENDC}")

            # Get remote Globalnet CIDR (what IP rule 150 should match)
            remote_globalnet_cidr = self.get_remote_globalnet_cidr(cluster)

            # Get active gateway node
            gateway_node = None
            gateway_files = [f for f in os.listdir(gather_dir) if f.startswith("gateways_")]
            for gw_file in gateway_files:
                gw_content = self.read_file(os.path.join(cluster, "gather", actual_cluster_name, gw_file))
                if gw_content:
                    try:
                        gw_yaml = yaml.safe_load(gw_content)
                        if gw_yaml and gw_yaml.get('status', {}).get('haStatus') == 'active':
                            gateway_node = gw_yaml.get('metadata', {}).get('name')
                            break
                    except yaml.YAMLError:
                        continue

            # Verify configuration on all nodes
            node_results = {}
            for file in os.listdir(gather_dir):
                if file.endswith("_ip-rules.log"):
                    node_name = file.replace("_ip-rules.log", "")
                    is_gateway = (node_name == gateway_node)

                    result = self.verify_node_host_networking(
                        cluster, actual_cluster_name, node_name,
                        remote_globalnet_cidr, is_gateway
                    )
                    node_results[node_name] = result

            # Analyze results
            self.analyze_host_networking_results(cluster, node_results, gateway_node)

            # Check gateway logs for 0.0.0.0 source error
            self.check_gateway_logs_for_source_error(cluster, actual_cluster_name)

    def verify_node_host_networking(self, cluster, actual_cluster_name, node_name,
                                      remote_cidr, is_gateway):
        """
        Verify routing checks on a single node.

        NOTE: Our collection script supplements subctl gather by collecting table 150
        from all nodes (subctl gather only collects from gateway nodes).

        Returns dict with check results.
        """
        gather_dir = os.path.join(cluster, "gather", actual_cluster_name)

        result = {
            'node_name': node_name,
            'is_gateway': is_gateway,
            'check1_ip_rule': False,
            'check2_table150': False,
            'check3_ovnk8smp0': False,
            'details': {}
        }

        # Check 1: IP rule 150
        ip_rules_content = self.read_file(os.path.join(gather_dir, f"{node_name}_ip-rules.log"))
        if ip_rules_content and remote_cidr:
            # Look for: "150:	from all to 242.1.0.0/16 lookup 150"
            if re.search(rf'150:.*to {re.escape(remote_cidr)}.*lookup 150', ip_rules_content):
                result['check1_ip_rule'] = True
                result['details']['ip_rule'] = f"Found: to {remote_cidr} lookup 150"
            else:
                result['details']['ip_rule'] = f"Missing: to {remote_cidr} lookup 150"

        # Check 2: Table 150 route
        table150_content = self.read_file(os.path.join(gather_dir, f"{node_name}_ip-routes-table150.log"))
        if table150_content:
            # Look for: "default via X.X.X.X dev ovn-k8s-mp0"
            match = re.search(r'default via ([\d.]+) dev ovn-k8s-mp0', table150_content)
            if match:
                result['check2_table150'] = True
                nexthop = match.group(1)
                result['details']['table150'] = f"Found: default via {nexthop} dev ovn-k8s-mp0"
            else:
                result['details']['table150'] = "Missing: No route in table 150"
        else:
            result['details']['table150'] = "Missing: Table 150 file not found (likely empty table)"

        # Check 3: ovn-k8s-mp0 interface
        ip_a_content = self.read_file(os.path.join(gather_dir, f"{node_name}_ip-a.log"))
        if ip_a_content:
            # Look for ovn-k8s-mp0 with UP state
            interface_match = re.search(r'^\d+: ovn-k8s-mp0:.*<.*UP.*>', ip_a_content, re.MULTILINE)
            # Look for inet address (may be several lines after interface line)
            ip_match = re.search(r'inet ([\d.]+)/\d+ .*scope global ovn-k8s-mp0', ip_a_content, re.MULTILINE)

            if interface_match and ip_match:
                result['check3_ovnk8smp0'] = True
                ip_addr = ip_match.group(1)
                result['details']['ovnk8smp0'] = f"UP with IP {ip_addr}"
            elif interface_match:
                result['details']['ovnk8smp0'] = "UP but no IP assigned"
            else:
                result['details']['ovnk8smp0'] = "Missing or DOWN"

        return result

    def analyze_ovnk_pinger_tcpdump(self, cluster, failed_nodes):
        """
        Analyze OVN-K pinger tcpdump files to identify which datapath segment failed.

        Segments:
        - Segment 1 (local routing): Non-GW node → ovn-k8s-mp0 (table 150 + IP rules)
        - Segment 2 (OVN datapath): ovn-k8s-mp0 → br-ex (OVN routing)
        - Segment 3 (tunnel): br-ex → remote cluster (IPsec/ESP)

        Tcpdump checkpoints:
        - ovn-k8s-mp0: Entry/exit point for OVN datapath
        - br-ex: Physical network interface (gateway only)
        - any: Complete view (both send and receive)
        """
        ovnk_pinger_dir = os.path.join(self.diagnostics_dir, "ovnk-pinger")

        if not os.path.exists(ovnk_pinger_dir):
            return

        # Check if any pcap files exist and are non-empty
        pcap_files = [f for f in os.listdir(ovnk_pinger_dir) if f.endswith('.pcap')]
        if not pcap_files:
            return

        # Check for worker node tcpdump (most diagnostic)
        worker_ovnk8smp0_files = [f for f in pcap_files if 'worker' in f and 'ovnk8smp0' in f]
        worker_any_files = [f for f in pcap_files if 'worker' in f and '-any.pcap' in f]

        if not worker_ovnk8smp0_files and not worker_any_files:
            return

        self._print(f"\n    {Colors.BOLD}OVN-K Pinger Tcpdump Analysis:{Colors.ENDC}")

        # Analyze worker captures
        for pcap in worker_ovnk8smp0_files:
            # Skip gateway captures (filename starts with clusterX-gateway-)
            if '-gateway-' in pcap:
                continue

            pcap_path = os.path.join(ovnk_pinger_dir, pcap)
            file_size = os.path.getsize(pcap_path)

            # Extract node name from filename: cluster1-worker-nodename-checkpoint.pcap
            parts = pcap.replace('.pcap', '').split('-')
            node_name = '-'.join(parts[2:-1]) if len(parts) > 3 else 'unknown'

            if file_size == 0:
                self._print(f"      {Colors.FAIL}✗{Colors.ENDC} Worker {node_name}: NO packets on ovn-k8s-mp0")
                self._print(f"        {Colors.BOLD}Segment 1 FAILED:{Colors.ENDC} Traffic not reaching OVN datapath")
                self._print(f"        {Colors.WARNING}Cause:{Colors.ENDC} Table 150 route missing or IP rules misconfigured")
            else:
                self._print(f"      {Colors.OKGREEN}✓{Colors.ENDC} Worker {node_name}: Packets captured on ovn-k8s-mp0 ({file_size} bytes)")
                self._print("        Segment 1 appears healthy (traffic reaching OVN)")

                # Check 'any' interface to see if packets go beyond ovn-k8s-mp0
                any_pcap = pcap.replace('ovnk8smp0', 'any')
                if any_pcap in worker_any_files:
                    any_path = os.path.join(ovnk_pinger_dir, any_pcap)
                    any_size = os.path.getsize(any_path)
                    if any_size > file_size:
                        self._print("        Segment 2/3: Additional analysis needed (packets on 'any' interface)")

        # NOTE: We only capture ovn-k8s-mp0 and 'any' - no br-ex (platform-specific)
        # Gateway analysis would check 'any' interface for tunnel traffic if needed

    def analyze_host_networking_results(self, cluster, node_results, gateway_node):
        """
        Analyze host networking check results and report findings.

        NOTE: Our collection script supplements subctl to collect table 150 from all nodes.
        """
        if not node_results:
            self._print(f"    {Colors.WARNING}⚠{Colors.ENDC} No node data found")
            return

        # Categorize nodes
        gateway_result = None
        worker_results = []

        for _node_name, result in node_results.items():
            if result['is_gateway']:
                gateway_result = result
            else:
                worker_results.append(result)

        # Count failures per check
        check1_failures = []
        check2_failures = []
        check3_failures = []

        all_results = [gateway_result] + worker_results if gateway_result else worker_results

        for result in all_results:
            if result:
                if not result['check1_ip_rule']:
                    check1_failures.append(result['node_name'])
                if not result['check2_table150']:
                    check2_failures.append(result['node_name'])
                if not result['check3_ovnk8smp0']:
                    check3_failures.append(result['node_name'])

        # Report findings
        total_nodes = len(all_results)
        gateway_count = 1 if gateway_result else 0
        worker_count = len(worker_results)

        self._print(f"\n    {Colors.BOLD}Host Networking Checks ({total_nodes} nodes: {gateway_count} gateway, {worker_count} workers):{Colors.ENDC}")

        # Check 1 summary
        if check1_failures:
            self._print(f"    {Colors.FAIL}✗{Colors.ENDC} Check 1 (IP rule 150): {len(check1_failures)}/{total_nodes} nodes missing")
            for node in check1_failures[:3]:
                self._print(f"      - {node}")
            if len(check1_failures) > 3:
                self._print(f"      ... and {len(check1_failures) - 3} more")
        else:
            self._print(f"    {Colors.OKGREEN}✓{Colors.ENDC} Check 1 (IP rule 150): All nodes configured")

        # Check 2 summary (all nodes now)
        if check2_failures:
            self._print(f"    {Colors.FAIL}✗{Colors.ENDC} Check 2 (Table 150 route): {len(check2_failures)}/{total_nodes} nodes missing")

            # Show gateway vs workers breakdown
            gateway_missing = gateway_result and not gateway_result['check2_table150']
            workers_missing = [r for r in worker_results if not r['check2_table150']]

            if gateway_missing:
                self._print(f"      {Colors.FAIL}Gateway ({gateway_node}): MISSING{Colors.ENDC}")
            if workers_missing:
                self._print(f"      Workers: {len(workers_missing)} missing")
                for worker in workers_missing[:2]:
                    self._print(f"        - {worker['node_name']}")
                if len(workers_missing) > 2:
                    self._print(f"        ... and {len(workers_missing) - 2} more")

            # This is critical failure
            self._print(f"\n    {Colors.FAIL}🔍 ROOT CAUSE IDENTIFIED:{Colors.ENDC}")
            self._print(f"      Table 150 route is MISSING on {len(check2_failures)} node(s)")
            self._print("      This prevents host networking traffic from reaching OVN datapath")

            self.faulty_states.append(f"{cluster}: Table 150 route missing on {len(check2_failures)} nodes")
            self.issues.append(f"{cluster}: OVN-K host networking misconfiguration (table 150)")
            self.recommendations.append(
                f"{cluster}: Investigate why Submariner failed to configure table 150 routes"
            )
            self.recommendations.append(
                f"{cluster}: Check RouteAgent logs for 'error adding submariner default route' errors"
            )

            # Analyze OVN-K pinger tcpdump if available
            self.analyze_ovnk_pinger_tcpdump(cluster, check2_failures)

        # Check 3 summary
        if check3_failures:
            self._print(f"    {Colors.FAIL}✗{Colors.ENDC} Check 3 (ovn-k8s-mp0 interface): {len(check3_failures)}/{total_nodes} nodes have issues")
            for node in check3_failures[:3]:
                self._print(f"      - {node}")
            if len(check3_failures) > 3:
                self._print(f"      ... and {len(check3_failures) - 3} more")

            self.issues.append(f"{cluster}: ovn-k8s-mp0 interface issues on {len(check3_failures)} nodes")
        else:
            self._print(f"    {Colors.OKGREEN}✓{Colors.ENDC} Check 3 (ovn-k8s-mp0 interface): All nodes UP with IP")

    def check_gateway_logs_for_source_error(self, cluster, actual_cluster_name):
        """
        Check gateway logs for 0.0.0.0 source address error.

        Pattern: "write ip 0.0.0.0->242.X.X.X: sendmsg: object is remote"
        """
        gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)

        if not os.path.exists(gather_dir):
            return

        # Find gateway pod logs
        gateway_log_files = [f for f in os.listdir(gather_dir)
                             if f.startswith("logs_submariner-gateway-")]

        for log_file in gateway_log_files:
            log_content = self.read_file(os.path.join(cluster, "gather", actual_cluster_name, log_file))
            if log_content:
                # Search for 0.0.0.0 source error
                error_match = re.search(
                    r'write ip 0\.0\.0\.0->([\d.]+):.*sendmsg.*remote',
                    log_content
                )
                if error_match:
                    dest_ip = error_match.group(1)
                    self._print(f"\n    {Colors.FAIL}🔍 CRITICAL ERROR DETECTED in gateway logs:{Colors.ENDC}")
                    self._print(f"      Error: 'write ip 0.0.0.0->{dest_ip}: sendmsg: object is remote'")
                    self._print(f"\n      {Colors.WARNING}Diagnosis:{Colors.ENDC}")
                    self._print("      Source IP = 0.0.0.0 indicates routing failure")
                    self._print("      Kernel could not select source IP from ovn-k8s-mp0")
                    self._print("      Most likely: Table 150 route missing OR ovn-k8s-mp0 has no IP")

                    self.faulty_states.append(f"{cluster}: Gateway cannot send packets (0.0.0.0 source)")
                    self.issues.append(f"{cluster}: Gateway routing failure (0.0.0.0 source IP)")
                    break

    def get_remote_globalnet_cidr(self, cluster):
        """
        Get remote cluster's Globalnet CIDR (what IP rule 150 should match).

        Returns CIDR string like "242.1.0.0/16" or None if not found.
        """
        # Try to extract from IP rules on any node (they all should have same remote CIDR)
        cluster_subdirs = self.get_cluster_subdirs()
        actual_cluster_name = cluster_subdirs.get(cluster)
        if not actual_cluster_name:
            return None

        gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)

        if not os.path.exists(gather_dir):
            return None

        for file in os.listdir(gather_dir):
            if file.endswith("_ip-rules.log"):
                content = self.read_file(os.path.join(cluster, "gather", actual_cluster_name, file))
                if content:
                    # Look for: "150:	from all to 242.1.0.0/16 lookup 150"
                    match = re.search(r'150:.*to ([\d.]+/\d+).*lookup 150', content)
                    if match:
                        return match.group(1)

        return None

    def check_main_table_routes(self):
        """Check if main routing table has routes to remote cluster CIDRs"""
        self._print(f"\n{Colors.BOLD}=== Checking Main Routing Table ==={Colors.ENDC}")

        cluster_subdirs = self.get_cluster_subdirs()
        if not cluster_subdirs:
            return

        for cluster in ['cluster1', 'cluster2']:
            actual_cluster_name = cluster_subdirs.get(cluster)
            if not actual_cluster_name:
                continue

            gather_dir = os.path.join(self.diagnostics_dir, cluster, "gather", actual_cluster_name)
            if not os.path.exists(gather_dir):
                continue

            # Get remote cluster CIDRs from Gateway CR
            gateway_cr = self.find_and_read_gateway_cr(cluster)
            if not gateway_cr or 'status' not in gateway_cr:
                continue

            remote_cidrs = set()
            gateways = gateway_cr['status'].get('gateways', [])
            for gw in gateways:
                connections = gw.get('connections', [])
                for conn in connections:
                    endpoint = conn.get('endpoint', {})
                    subnets = endpoint.get('subnets', [])
                    remote_cidrs.update(subnets)

            # Check gateway node's main routing table
            for file in os.listdir(gather_dir):
                if file.endswith("_ip-routes.log"):
                    routes_content = self.read_file(os.path.join(cluster, "gather", actual_cluster_name, file))
                    if routes_content:
                        has_remote_routes = False
                        for cidr in remote_cidrs:
                            if cidr in routes_content:
                                has_remote_routes = True
                                break

                        if has_remote_routes:
                            self._print(f"  {Colors.WARNING}⚠{Colors.ENDC} {cluster}: Main table has routes to remote clusters")
                            self._print("    → This is unusual; Submariner typically uses table 150")
                        else:
                            self._print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {cluster}: Main table does NOT have remote cluster routes (expected)")
                    break

    def add_context_aware_recommendations(self):
        """Add context-aware recommendations when no clear root cause is found"""

        # Check if we have tunnel errors but no clear smoking gun
        has_tunnel_errors = any('tunnel' in fault.lower() or 'error' in fault.lower()
                               for fault in self.faulty_states)
        has_routeagent_errors = any(data.get('errors', 0) > 0
                                    for data in self.routeagent_data.values())

        # Check if we already found specific actionable root causes
        has_infrastructure_blocking = any('infrastructure' in rec.lower() and 'blocking' in rec.lower()
                                          for rec in self.recommendations)
        has_version_issue = any('version' in fault.lower() for fault in self.faulty_states)
        has_ha_issue = any('multiple active' in issue.lower() for issue in self.issues)
        has_mtu_issue = any('mtu' in issue.lower() for issue in self.issues)
        has_specific_config_fix = any(('kubectl edit' in rec or 'kubectl patch' in rec)
                                      for rec in self.recommendations)

        # Check if firewall test passed (infrastructure is OK)
        firewall_passed = any('firewall is ok' in rec.lower() or 'not blocking' in rec.lower()
                             for rec in self.recommendations)

        # If we have errors but no clear actionable root cause, suggest pod restart
        if (has_tunnel_errors or has_routeagent_errors) and firewall_passed and not (
            has_infrastructure_blocking or has_version_issue or
            has_ha_issue or has_mtu_issue or has_specific_config_fix
        ):
            # Add pod restart recommendation as first step
            self._print(f"\n{Colors.BOLD}=== Context-Aware Recommendation ==={Colors.ENDC}")
            self._print(f"  {Colors.WARNING}No clear configuration error found in logs{Colors.ENDC}")
            self._print("  Infrastructure is verified OK (firewall test passed)")
            self._print("  If issue appeared after node reboots, updates, or other major activities,")
            self._print("  this could be stale state in Submariner components.")

            # Insert pod restart as the FIRST recommendation
            restart_rec = (
                "Restart Submariner pods on BOTH clusters (FIRST - simple workaround for potential stale state):\n"
                f"      {Colors.OKCYAN}kubectl delete pods -n submariner-operator -l app=submariner-gateway{Colors.ENDC}\n"
                f"      {Colors.OKCYAN}kubectl delete pods -n submariner-operator -l app=submariner-routeagent{Colors.ENDC}\n"
                f"      {Colors.OKCYAN}kubectl delete pods -n submariner-operator -l app=submariner-globalnet{Colors.ENDC}\n"
                "      Wait for pods to restart, then verify tunnel status:\n"
                f"      {Colors.OKCYAN}kubectl get gateway -n submariner-operator{Colors.ENDC}"
            )

            # Remove vague "investigate" recommendations
            self.recommendations = [rec for rec in self.recommendations
                                   if 'investigate other' not in rec.lower()]

            # Add restart recommendation at the beginning
            self.recommendations.insert(0, restart_rec)

    def run(self):
        """Run full analysis"""
        self._print(f"\n{Colors.BOLD}Submariner Basic Diagnostic Analyzer{Colors.ENDC}")
        self._print(f"{'='*60}\n")

        # Extract tarball
        if not self.extract_tarball():
            return False

        # Read manifest
        manifest = self.analyze_manifest()
        if manifest:
            self._print(f"\n{Colors.BOLD}Diagnostic Information:{Colors.ENDC}")
            self._print(f"  Timestamp: {manifest.get('Timestamp', 'unknown')}")
            self._print(f"  Issue: {manifest.get('Complaint', 'unknown')}")

        # Check for collection errors
        self.check_collection_errors()

        # Check for faulty states first
        has_faults = self.check_faulty_states()

        # Only run deep analysis if faulty states were found
        if has_faults:
            self._print(f"\n{Colors.BOLD}=== Starting Deep Analysis ==={Colors.ENDC}")

            # Analyze RouteAgent resources first (key diagnostic info)
            self.analyze_routeagents()

            # Analyze network topology
            self.analyze_network_topology()

            # Analyze logs for significant errors
            self.analyze_logs()

            # Analyze tunnel details
            self.analyze_tunnel_status()

            # Check load balancer configuration for hosted clusters
            self.analyze_loadbalancer_config()

            # NEW: Check API server health for rate limiter errors
            self.check_api_server_health()

            # NEW: Check IP rule consistency between clusters
            self.check_ip_rule_consistency()

            # NEW: Check OVN routing configuration
            cni_cluster1 = self.detect_cni("cluster1")
            cni_cluster2 = self.detect_cni("cluster2")
            if "OVN" in cni_cluster1 or "OVN" in cni_cluster2:
                self.check_ovn_routing()
                self.validate_ovnk_configuration()
                self.check_ovn_local_gateway_mode_issue()
                self.verify_ovnk_host_networking()
                self.check_main_table_routes()

            # NEW: Analyze nftables rules (only when datapath broken)
            self.analyze_nftables()

            # Analyze tcpdump for tunnel issues
            if any('tunnel' in fault.lower() for fault in self.faulty_states):
                self.analyze_tcpdump()

            # Analyze pod health
            self.analyze_pod_health()

            # Check gateway HA labels (critical: multiple active pods)
            self.analyze_gateway_ha_labels()

            # Add context-aware recommendations if no clear root cause found
            self.add_context_aware_recommendations()

        # Generate report in appropriate format
        if self.output_format == 'slack':
            self.generate_slack_report()
        else:
            self.generate_report()

        return True

def main():
    parser = argparse.ArgumentParser(
        description='Analyze Submariner diagnostics for common issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard terminal output with colors
  %(prog)s submariner-diagnostics-20260701.tar.gz

  # Clean output for Slack (no colors, condensed)
  %(prog)s submariner-diagnostics-20260701.tar.gz --format slack

For more information:
  https://github.com/submariner-io/submariner-diagnostics
        """)

    parser.add_argument('tarball',
                        help='Path to submariner-diagnostics-*.tar.gz file')
    parser.add_argument('--format',
                        choices=['terminal', 'slack'],
                        default='terminal',
                        help='Output format: terminal (colored, verbose) or slack (clean, condensed)')

    args = parser.parse_args()

    analyzer = SubmarinerAnalyzer(args.tarball, output_format=args.format)

    success = analyzer.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
