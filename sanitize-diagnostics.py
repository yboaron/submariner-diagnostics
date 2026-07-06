#!/usr/bin/env python3
"""
Sanitize Submariner diagnostics by replacing IP addresses and domain names
with context-aware placeholders while maintaining diagnostic value.
"""

import ipaddress
import os
import re
import sys
from pathlib import Path

import yaml


class DiagnosticSanitizer:
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.ip_mapping = {}
        self.domain_mapping = {}
        self.public_ip_counter = 1
        self.private_ip_counter = 1
        self.pod_ip_counter = 1
        self.svc_ip_counter = 1
        self.ipv6_counter = 1
        self.domain_counter = 1

        self.ip_mapping_file = self.output_dir / "ip-mappings.txt"
        self.domain_mapping_file = self.output_dir / "domain-mappings.txt"

        # Load cluster CIDRs from diagnostics
        self.pod_cidrs = []
        self.svc_cidrs = []
        self._load_cluster_cidrs()

    def _load_cluster_cidrs(self):
        """Load pod and service CIDRs from collected diagnostics manifest"""
        # Try manifest.txt first (what collect-full-diagnostics.sh actually creates)
        manifest_path = self.output_dir / "manifest.txt"
        if not manifest_path.exists():
            # Fallback to .yaml extension
            manifest_path = self.output_dir / "manifest.yaml"
            if not manifest_path.exists():
                return

        try:
            with open(manifest_path) as f:
                manifest = yaml.safe_load(f)

            for cluster_info in manifest.get('clusters', []):
                self.pod_cidrs.extend(cluster_info.get('podCIDRs', []))
                self.svc_cidrs.extend(cluster_info.get('serviceCIDRs', []))
        except (OSError, yaml.YAMLError):
            pass  # Fall back to hardcoded defaults

    def get_ip_type(self, ip):
        """Determine IP type based on cluster CIDRs or RFC1918/6 ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return 'UNKNOWN'

        # IPv6 handling
        if ip_obj.version == 6:
            # Check against collected CIDRs
            for cidr in self.pod_cidrs:
                try:
                    if ip_obj in ipaddress.ip_network(cidr):
                        return 'POD'
                except ValueError:
                    continue
            for cidr in self.svc_cidrs:
                try:
                    if ip_obj in ipaddress.ip_network(cidr):
                        return 'SVC'
                except ValueError:
                    continue
            # IPv6 private/public classification
            if ip_obj.is_private or ip_obj.is_link_local:
                return 'IPV6'
            return 'PUBLIC'

        # IPv4 handling - check collected CIDRs first
        for cidr in self.pod_cidrs:
            try:
                if ip_obj in ipaddress.ip_network(cidr):
                    return 'POD'
            except ValueError:
                continue
        for cidr in self.svc_cidrs:
            try:
                if ip_obj in ipaddress.ip_network(cidr):
                    return 'SVC'
            except ValueError:
                continue

        # Fallback to hardcoded ranges (for when manifest unavailable)
        octets = [int(x) for x in ip.split('.')]
        first, second = octets[0], octets[1]

        # Common k8s service CIDR (10.96.0.0/12)
        if first == 10 and 96 <= second <= 111:
            return 'SVC'
        # RFC1918 private ranges
        elif first == 10:
            # Common pod CIDRs
            if second >= 128 or second == 244:
                return 'POD'
            return 'PRIVATE'
        elif first == 172 and 16 <= second <= 31 or first == 192 and second == 168:
            return 'PRIVATE'
        return 'PUBLIC'

    def get_ip_mapping(self, ip):
        """Get or create IP mapping"""
        if ip in self.ip_mapping:
            return self.ip_mapping[ip]

        ip_type = self.get_ip_type(ip)

        if ip_type == 'PUBLIC':
            placeholder = f"PUBLIC-IP-{self.public_ip_counter}"
            self.public_ip_counter += 1
        elif ip_type == 'PRIVATE':
            placeholder = f"PRIVATE-IP-{self.private_ip_counter}"
            self.private_ip_counter += 1
        elif ip_type == 'POD':
            placeholder = f"POD-IP-{self.pod_ip_counter}"
            self.pod_ip_counter += 1
        elif ip_type == 'SVC':
            placeholder = f"SVC-IP-{self.svc_ip_counter}"
            self.svc_ip_counter += 1
        elif ip_type == 'IPV6':
            placeholder = f"IPV6-{self.ipv6_counter}"
            self.ipv6_counter += 1
        else:  # UNKNOWN
            placeholder = f"IP-UNKNOWN-{self.public_ip_counter}"
            self.public_ip_counter += 1

        self.ip_mapping[ip] = placeholder
        return placeholder

    def _should_sanitize_domain(self, domain):
        """Check if domain should be sanitized (skip k8s identifiers and internal names)"""
        # Skip kubernetes label-style identifiers
        if '/' in domain or domain.startswith('kubernetes.') or domain.startswith('node.'):
            return domain  # Return unchanged

        # Skip common k8s/OpenShift API groups and internal domains
        k8s_domains = [
            '.svc.cluster.local', '.cluster.local',
            'kubernetes.io', 'k8s.io', 'openshift.io',
            'submariner.io', 'cert-manager.io',
            'operators.coreos.com', 'coreos.com'
        ]
        if any(domain.endswith(suffix) or domain == suffix.lstrip('.') for suffix in k8s_domains):
            return domain  # Return unchanged

        # Sanitize actual external domains
        return self.get_domain_mapping(domain)

    def get_domain_mapping(self, domain):
        """Get or create domain mapping"""
        if domain in self.domain_mapping:
            return self.domain_mapping[domain]

        placeholder = f"DOMAIN-{self.domain_counter}"
        self.domain_counter += 1
        self.domain_mapping[domain] = placeholder
        return placeholder

    def sanitize_content(self, content):
        """Sanitize content by replacing IPs and domains"""
        # Replace IPv4 addresses
        ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        content = re.sub(ipv4_pattern, lambda m: self.get_ip_mapping(m.group(0)), content)

        # Replace IPv6 addresses (simplified pattern for common formats)
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
        content = re.sub(ipv6_pattern, lambda m: self.get_ip_mapping(m.group(0)), content)

        # Replace domain names (real FQDNs, not k8s labels or file paths)
        # Requires public TLD-like suffix and excludes tokens with slashes or k8s-specific patterns
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\.(com|net|org|io|dev|cloud|local|cluster)\b'
        content = re.sub(domain_pattern, lambda m: self._should_sanitize_domain(m.group(0)), content)

        return content

    def sanitize_file(self, file_path):
        """Sanitize a single file"""
        try:
            with open(file_path, encoding='utf-8', errors='ignore') as f:
                content = f.read()

            sanitized = self.sanitize_content(content)

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(sanitized)

            return True
        except (OSError, UnicodeDecodeError, UnicodeEncodeError) as e:
            print(f"  ERROR sanitizing {file_path}: {e}", file=sys.stderr)
            return False

    def sanitize_directory(self):
        """Sanitize all text files in the output directory"""
        print("")
        print("=========================================")
        print("Sanitizing diagnostic data...")
        print("=========================================")

        # File extensions to sanitize
        extensions = ('.yaml', '.yml', '.txt', '.log', '.json')

        file_count = 0
        failed_count = 0
        for file_path in self.output_dir.rglob('*'):
            # Skip symlinks to prevent path traversal outside diagnostics directory
            if file_path.is_symlink():
                continue

            # Verify resolved path is within diagnostics directory
            try:
                resolved = file_path.resolve()
                resolved.relative_to(self.output_dir.resolve())
            except (ValueError, OSError):
                print(f"  WARNING: Skipping {file_path} - outside diagnostics directory", file=sys.stderr)
                continue

            if file_path.is_file() and file_path.suffix in extensions:
                # Skip mapping files themselves
                if file_path.name in ('ip-mappings.txt', 'domain-mappings.txt'):
                    continue

                print(f"  Sanitizing: {file_path.relative_to(self.output_dir)}")
                if self.sanitize_file(file_path):
                    file_count += 1
                else:
                    failed_count += 1

        # Write mapping files
        self.write_mappings()

        print("")
        if failed_count > 0:
            print(f"Sanitization completed with errors! ({file_count} succeeded, {failed_count} failed)")
            print("  IP mappings: ip-mappings.txt (will be excluded from tarball)")
            print("  Domain mappings: domain-mappings.txt (will be excluded from tarball)")
            print("")
            return False
        else:
            print(f"Sanitization complete! ({file_count} files processed)")
            print("  IP mappings: ip-mappings.txt (will be excluded from tarball)")
            print("  Domain mappings: domain-mappings.txt (will be excluded from tarball)")
            print("")
            return True

    def write_mappings(self):
        """Write mapping files (for local reference only, not included in tarball)"""
        with open(self.ip_mapping_file, 'w') as f:
            f.write("# IP Address Mappings (LOCAL REFERENCE - NOT FOR DISTRIBUTION)\n")
            f.write("# This file contains sensitive data and will be excluded from the tarball\n")
            f.write("# Format: original=placeholder\n")
            f.write("\n")
            for ip, placeholder in sorted(self.ip_mapping.items()):
                f.write(f"{ip}={placeholder}\n")

        with open(self.domain_mapping_file, 'w') as f:
            f.write("# Domain Name Mappings (LOCAL REFERENCE - NOT FOR DISTRIBUTION)\n")
            f.write("# This file contains sensitive data and will be excluded from the tarball\n")
            f.write("# Format: original=placeholder\n")
            f.write("\n")
            for domain, placeholder in sorted(self.domain_mapping.items()):
                f.write(f"{domain}={placeholder}\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: sanitize-diagnostics.py <output-directory>", file=sys.stderr)
        sys.exit(1)

    output_dir = sys.argv[1]
    if not os.path.isdir(output_dir):
        print(f"Error: {output_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    sanitizer = DiagnosticSanitizer(output_dir)
    success = sanitizer.sanitize_directory()

    # Exit with error code if sanitization failed
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
