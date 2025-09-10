"""
Step-CA Service Integration Module

This module provides functionality to interact with Step-CA service
for certificate generation, validation, and management.
"""

import subprocess
import json
import logging
import tempfile
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from django.conf import settings
from django.utils import timezone
import ssl
import socket

logger = logging.getLogger(__name__)


class StepCAServiceError(Exception):
    """Custom exception for Step-CA service errors"""
    pass


class StepCAService:
    """Service class to interact with Step-CA"""
    
    def __init__(self, ca_url: str = "https://localhost:9000", ca_fingerprint: str = None):
        self.ca_url = ca_url
        self.ca_fingerprint = ca_fingerprint
        self.step_binary = getattr(settings, 'STEP_BINARY_PATH', 'step')
        
    def check_step_cli_availability(self) -> bool:
        """Check if step CLI is available"""
        try:
            result = subprocess.run([self.step_binary, 'version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def bootstrap_ca(self) -> Dict:
        """Bootstrap the CA configuration"""
        try:
            cmd = [self.step_binary, 'ca', 'bootstrap', 
                   '--ca-url', self.ca_url, '--install']
            
            if self.ca_fingerprint:
                cmd.extend(['--fingerprint', self.ca_fingerprint])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                raise StepCAServiceError(f"Bootstrap failed: {result.stderr}")
            
            return {"status": "success", "message": "CA bootstrapped successfully"}
        
        except subprocess.TimeoutExpired:
            raise StepCAServiceError("Bootstrap timeout")
        except Exception as e:
            raise StepCAServiceError(f"Bootstrap error: {str(e)}")
    
    def generate_certificate(self, hostname: str, validity_period: str = "1y", 
                           email: str = None, key_size: int = 2048) -> Dict:
        """
        Generate a certificate using Step-CA
        
        Args:
            hostname: The hostname/IP for the certificate
            validity_period: Certificate validity (e.g., "1y", "30d")
            email: Optional email for the certificate
            key_size: RSA key size (default: 2048)
        
        Returns:
            Dict containing certificate data and metadata
        """
        # Check if Step CLI is available
        if not self.check_step_cli_availability():
            return self._generate_mock_certificate(hostname, validity_period, email, key_size)
        
        try:
            # Create temporary files for certificate and key
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file, \
                 tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as key_file:
                
                cert_path = cert_file.name
                key_path = key_file.name
            
            try:
                # Build step ca certificate command
                cmd = [
                    self.step_binary, 'ca', 'certificate',
                    hostname, cert_path, key_path,
                    '--ca-url', self.ca_url,
                    '--not-after', validity_period,
                    '--kty', 'RSA',
                    '--size', str(key_size),
                    '--force'  # Overwrite existing files
                ]
                
                # Add email if provided
                if email:
                    cmd.extend(['--set', f'emailAddresses={email}'])
                
                # Execute the command
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode != 0:
                    raise StepCAServiceError(f"Certificate generation failed: {result.stderr}")
                
                # Read the generated certificate and key
                with open(cert_path, 'r') as f:
                    certificate_content = f.read()
                
                with open(key_path, 'r') as f:
                    private_key = f.read()
                
                # Parse certificate info
                cert_info = self.parse_certificate_info(certificate_content)
                
                return {
                    "status": "success",
                    "certificate": certificate_content,
                    "private_key": private_key,
                    "certificate_info": cert_info,
                    "hostname": hostname,
                    "validity_period": validity_period,
                    "key_size": key_size,
                    "generated_at": timezone.now().isoformat()
                }
            
            finally:
                # Clean up temporary files
                for temp_path in [cert_path, key_path]:
                    try:
                        if os.path.exists(temp_path):
                            os.unlink(temp_path)
                    except OSError:
                        pass
        
        except subprocess.TimeoutExpired:
            raise StepCAServiceError("Certificate generation timeout")
        except Exception as e:
            logger.error(f"Certificate generation error: {str(e)}")
            raise StepCAServiceError(f"Certificate generation error: {str(e)}")
    
    def _generate_mock_certificate(self, hostname: str, validity_period: str, 
                                 email: str = None, key_size: int = 2048) -> Dict:
        """
        Generate a mock certificate for development/testing when Step-CA is not available
        """
        from datetime import datetime, timedelta
        
        # Calculate expiry date based on validity period
        if validity_period.endswith('d'):
            days = int(validity_period[:-1])
            expiry_date = timezone.now() + timedelta(days=days)
        elif validity_period.endswith('y'):
            years = int(validity_period[:-1])
            expiry_date = timezone.now() + timedelta(days=years*365)
        else:
            expiry_date = timezone.now() + timedelta(days=365)  # Default to 1 year
        
        # Mock certificate content (this is just for demo - not a real certificate)
        mock_cert = f"""-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAK2g9QqS9+6yMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwOTA5MDAwMDAwWhcNMjUwOTA5MDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA0vx2OQs1+/j8t2aVd7EhCm6Wg8QGb1rr4WtH9XYr5Ua7qG2U+3vU1E1d
...
[Mock Certificate Content for {hostname}]
...
-----END CERTIFICATE-----"""

        mock_private_key = f"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDS/HY5CzX7+Py3
ZpV3sSEKbpaDxAZvWuvha0f1divlRruobZT7e9TUTd3QTt3QTm6WbpaDxAZvWuvh
...
[Mock Private Key Content for {hostname}]
...
-----END PRIVATE KEY-----"""

        return {
            "status": "success",
            "certificate": mock_cert,
            "private_key": mock_private_key,
            "certificate_info": {
                "subject": {"CN": hostname},
                "issuer": {"CN": "Mock CA"},
                "serial_number": "12345678901234567890",
                "not_before": timezone.now().isoformat(),
                "not_after": expiry_date.isoformat(),
                "dns_names": [hostname] if not hostname.replace('.', '').isdigit() else [],
                "ip_addresses": [hostname] if hostname.replace('.', '').isdigit() else [],
                "key_usage": ["digital_signature", "key_encipherment"],
                "signature_algorithm": "SHA256-RSA"
            },
            "hostname": hostname,
            "validity_period": validity_period,
            "key_size": key_size,
            "generated_at": timezone.now().isoformat(),
            "is_mock": True,
            "note": "This is a mock certificate generated for development. Install Step-CA CLI for real certificates."
        }
    
    def parse_certificate_info(self, certificate_pem: str) -> Dict:
        """Parse certificate information from PEM content"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file:
                cert_file.write(certificate_pem)
                cert_path = cert_file.name
            
            try:
                # Use step CLI to inspect certificate
                cmd = [self.step_binary, 'certificate', 'inspect', cert_path, '--format', 'json']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    cert_data = json.loads(result.stdout)
                    
                    # Extract relevant information
                    return {
                        "subject": cert_data.get("subject", {}),
                        "issuer": cert_data.get("issuer", {}),
                        "serial_number": cert_data.get("serial_number", ""),
                        "not_before": cert_data.get("validity", {}).get("start", ""),
                        "not_after": cert_data.get("validity", {}).get("end", ""),
                        "dns_names": cert_data.get("extensions", {}).get("subject_alt_name", {}).get("dns_names", []),
                        "ip_addresses": cert_data.get("extensions", {}).get("subject_alt_name", {}).get("ip_addresses", []),
                        "key_usage": cert_data.get("extensions", {}).get("key_usage", []),
                        "signature_algorithm": cert_data.get("signature_algorithm", "")
                    }
            
            finally:
                try:
                    os.unlink(cert_path)
                except OSError:
                    pass
        
        except Exception as e:
            logger.warning(f"Failed to parse certificate info: {str(e)}")
            return {"error": f"Failed to parse certificate: {str(e)}"}
    
    def validate_certificate(self, hostname: str, port: int = 443) -> Dict:
        """
        Validate a certificate by connecting to the host
        
        Args:
            hostname: The hostname to validate
            port: The port to connect to (default: 443)
        
        Returns:
            Dict containing validation results
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to the host
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    # Parse certificate dates
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    # Make dates timezone-aware if they aren't already
                    if timezone.is_naive(not_before):
                        not_before = timezone.make_aware(not_before)
                    if timezone.is_naive(not_after):
                        not_after = timezone.make_aware(not_after)
                    
                    now = timezone.now()
                    
                    # Calculate days until expiry
                    days_until_expiry = (not_after - now).days
                    
                    return {
                        "status": "valid",
                        "hostname": hostname,
                        "port": port,
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "serial_number": cert.get('serialNumber', ''),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "days_until_expiry": days_until_expiry,
                        "is_expired": now > not_after,
                        "dns_names": cert.get('subjectAltName', []),
                        "validated_at": timezone.now().isoformat()
                    }
        
        except socket.timeout:
            return {
                "status": "error",
                "error": "Connection timeout",
                "hostname": hostname,
                "port": port,
                "validated_at": timezone.now().isoformat()
            }
        except ssl.SSLError as e:
            return {
                "status": "error", 
                "error": f"SSL Error: {str(e)}",
                "hostname": hostname,
                "port": port,
                "validated_at": timezone.now().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "error": f"Validation error: {str(e)}",
                "hostname": hostname,
                "port": port,
                "validated_at": timezone.now().isoformat()
            }
    
    def revoke_certificate(self, cert_path: str, reason: str = "unspecified") -> Dict:
        """
        Revoke a certificate using Step-CA
        
        Args:
            cert_path: Path to the certificate file
            reason: Revocation reason
        
        Returns:
            Dict containing revocation result
        """
        try:
            cmd = [
                self.step_binary, 'ca', 'revoke',
                cert_path,
                '--ca-url', self.ca_url,
                '--reason', reason
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                raise StepCAServiceError(f"Certificate revocation failed: {result.stderr}")
            
            return {
                "status": "success",
                "message": "Certificate revoked successfully",
                "reason": reason,
                "revoked_at": timezone.now().isoformat()
            }
        
        except subprocess.TimeoutExpired:
            raise StepCAServiceError("Certificate revocation timeout")
        except Exception as e:
            raise StepCAServiceError(f"Certificate revocation error: {str(e)}")
    
    def get_ca_info(self) -> Dict:
        """Get information about the CA"""
        try:
            # Check if Step CLI is available
            if not self.check_step_cli_availability():
                return {
                    "status": "step-cli-unavailable",
                    "ca_url": self.ca_url,
                    "error": "Step-CA CLI not installed or not found in PATH. Install step CLI to connect to real Step-CA service.",
                    "note": "Currently using mock certificate generation for development.",
                    "checked_at": timezone.now().isoformat()
                }
            
            # Get CA info using step CLI
            cmd = [self.step_binary, 'ca', 'health', '--ca-url', self.ca_url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return {
                    "status": "healthy",
                    "ca_url": self.ca_url,
                    "checked_at": timezone.now().isoformat()
                }
            else:
                return {
                    "status": "unhealthy",
                    "ca_url": self.ca_url,
                    "error": result.stderr,
                    "checked_at": timezone.now().isoformat()
                }
        
        except Exception as e:
            return {
                "status": "error",
                "ca_url": self.ca_url,
                "error": str(e),
                "checked_at": timezone.now().isoformat()
            }
    
    def list_certificates(self) -> List[Dict]:
        """List certificates from the CA (if supported)"""
        try:
            # This would depend on Step-CA's API capabilities
            # For now, return empty list as this might require additional API endpoints
            return []
        
        except Exception as e:
            logger.error(f"Failed to list certificates: {str(e)}")
            return []


# Utility functions
def get_step_ca_service(service_url: str = None, fingerprint: str = None) -> StepCAService:
    """Get a Step-CA service instance with default or custom configuration"""
    default_url = getattr(settings, 'STEP_CA_URL', 'https://localhost:9000')
    default_fingerprint = getattr(settings, 'STEP_CA_FINGERPRINT', None)
    
    return StepCAService(
        ca_url=service_url or default_url,
        ca_fingerprint=fingerprint or default_fingerprint
    )


def convert_validity_period(period: str) -> str:
    """Convert human-readable validity period to step-ca format"""
    conversion_map = {
        '1-year': '365d',
        '2-years': '730d', 
        '3-years': '1095d',
        '5-years': '1825d',
        '30-days': '30d',
        '90-days': '90d',
        '6-months': '180d'
    }
    
    return conversion_map.get(period, period)
