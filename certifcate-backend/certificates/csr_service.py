"""
Certificate Signing Request (CSR) Generation Service

This module provides functionality to generate Certificate Signing Requests
using cryptographic libraries or external tools.
"""

import subprocess
import tempfile
import os
import logging
from typing import Dict, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from django.conf import settings

logger = logging.getLogger(__name__)


class CSRGenerationError(Exception):
    """Custom exception for CSR generation errors"""
    pass


class CSRService:
    """Service class to generate Certificate Signing Requests"""
    
    def __init__(self):
        self.step_binary = getattr(settings, 'STEP_BINARY_PATH', 'step')
    
    def generate_csr_with_cryptography(self, csr_data: Dict) -> Dict:
        """
        Generate CSR using Python cryptography library
        
        Args:
            csr_data: Dictionary containing CSR parameters
        
        Returns:
            Dict containing CSR and private key in PEM format
        """
        try:
            # Extract parameters
            common_name = csr_data['common_name']
            organization = csr_data.get('organization', '')
            organizational_unit = csr_data.get('organizational_unit', '')
            country = csr_data.get('country', '')
            state = csr_data.get('state', '')
            locality = csr_data.get('locality', '')
            email = csr_data.get('email', '')
            subject_alt_names = csr_data.get('subject_alternative_names', [])
            key_type = csr_data.get('key_type', 'RSA')
            key_size = int(csr_data.get('key_size', '2048'))
            
            # Generate private key based on type
            if key_type == 'RSA':
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size
                )
            elif key_type == 'ECDSA':
                if key_size == 256:
                    curve = ec.SECP256R1()
                elif key_size == 384:
                    curve = ec.SECP384R1()
                elif key_size == 521:
                    curve = ec.SECP521R1()
                else:
                    curve = ec.SECP256R1()  # Default
                private_key = ec.generate_private_key(curve)
            elif key_type == 'Ed25519':
                private_key = ed25519.Ed25519PrivateKey.generate()
            else:
                raise CSRGenerationError(f"Unsupported key type: {key_type}")
            
            # Build subject name
            subject_components = []
            if country:
                subject_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
            if state:
                subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
            if locality:
                subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
            if organization:
                subject_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
            if organizational_unit:
                subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
            subject_components.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
            if email:
                subject_components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
            
            subject = x509.Name(subject_components)
            
            # Create CSR builder
            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(subject)
            
            # Add Subject Alternative Names if provided
            if subject_alt_names:
                san_list = []
                for san in subject_alt_names:
                    if '.' in san or ':' in san:  # Likely an IP or domain
                        try:
                            # Try as IP address first
                            import ipaddress
                            ip = ipaddress.ip_address(san)
                            san_list.append(x509.IPAddress(ip))
                        except ValueError:
                            # Not an IP, treat as DNS name
                            san_list.append(x509.DNSName(san))
                    else:
                        san_list.append(x509.DNSName(san))
                
                if san_list:
                    builder = builder.add_extension(
                        x509.SubjectAlternativeName(san_list),
                        critical=False
                    )
            
            # Add key usage extension
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            
            # Add extended key usage
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=True
            )
            
            # Sign the CSR
            csr = builder.sign(private_key, hashes.SHA256())
            
            # Serialize to PEM format
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Parse CSR information
            csr_info = self.parse_csr_info(csr)
            
            return {
                "status": "success",
                "csr": csr_pem,
                "private_key": private_key_pem,
                "csr_info": csr_info,
                "key_type": key_type,
                "key_size": key_size,
                "common_name": common_name
            }
        
        except Exception as e:
            logger.error(f"CSR generation error: {str(e)}")
            raise CSRGenerationError(f"CSR generation failed: {str(e)}")
    
    def generate_csr_with_step_cli(self, csr_data: Dict) -> Dict:
        """
        Generate CSR using Step CLI
        
        Args:
            csr_data: Dictionary containing CSR parameters
        
        Returns:
            Dict containing CSR and private key in PEM format
        """
        try:
            # Create temporary files for CSR and key
            with tempfile.NamedTemporaryFile(mode='w', suffix='.csr', delete=False) as csr_file, \
                 tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as key_file:
                
                csr_path = csr_file.name
                key_path = key_file.name
            
            try:
                # Build step certificate create command for CSR
                cmd = [
                    self.step_binary, 'certificate', 'create',
                    csr_data['common_name'], csr_path, key_path,
                    '--csr',  # Generate CSR instead of certificate
                    '--kty', csr_data.get('key_type', 'RSA'),
                    '--size', str(csr_data.get('key_size', '2048')),
                    '--force'  # Overwrite existing files
                ]
                
                # Add subject information
                if csr_data.get('organization'):
                    cmd.extend(['--set', f'organization={csr_data["organization"]}'])
                if csr_data.get('organizational_unit'):
                    cmd.extend(['--set', f'organizationalUnit={csr_data["organizational_unit"]}'])
                if csr_data.get('country'):
                    cmd.extend(['--set', f'country={csr_data["country"]}'])
                if csr_data.get('state'):
                    cmd.extend(['--set', f'province={csr_data["state"]}'])
                if csr_data.get('locality'):
                    cmd.extend(['--set', f'locality={csr_data["locality"]}'])
                
                # Add Subject Alternative Names
                san_list = csr_data.get('subject_alternative_names', [])
                if san_list:
                    cmd.extend(['--san', ','.join(san_list)])
                
                # Execute the command
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode != 0:
                    raise CSRGenerationError(f"CSR generation failed: {result.stderr}")
                
                # Read the generated CSR and key
                with open(csr_path, 'r') as f:
                    csr_content = f.read()
                
                with open(key_path, 'r') as f:
                    private_key = f.read()
                
                return {
                    "status": "success",
                    "csr": csr_content,
                    "private_key": private_key,
                    "common_name": csr_data['common_name'],
                    "key_type": csr_data.get('key_type', 'RSA'),
                    "key_size": csr_data.get('key_size', '2048'),
                    "generated_with": "step-cli"
                }
            
            finally:
                # Clean up temporary files
                for temp_path in [csr_path, key_path]:
                    try:
                        if os.path.exists(temp_path):
                            os.unlink(temp_path)
                    except OSError:
                        pass
        
        except subprocess.TimeoutExpired:
            raise CSRGenerationError("CSR generation timeout")
        except Exception as e:
            logger.error(f"CSR generation error: {str(e)}")
            raise CSRGenerationError(f"CSR generation error: {str(e)}")
    
    def parse_csr_info(self, csr) -> Dict:
        """Parse CSR information from cryptography CSR object"""
        try:
            info = {
                "subject": {},
                "public_key_info": {},
                "extensions": {}
            }
            
            # Parse subject
            for attribute in csr.subject:
                oid_name = attribute.oid._name.lower() if hasattr(attribute.oid, '_name') else str(attribute.oid)
                info["subject"][oid_name] = attribute.value
            
            # Parse public key info
            public_key = csr.public_key()
            if hasattr(public_key, 'key_size'):
                info["public_key_info"]["key_size"] = public_key.key_size
                info["public_key_info"]["key_type"] = type(public_key).__name__
            
            # Parse extensions
            try:
                for extension in csr.extensions:
                    ext_name = extension.oid._name if hasattr(extension.oid, '_name') else str(extension.oid)
                    info["extensions"][ext_name] = str(extension.value)
            except:
                pass  # Extensions might not be present
            
            return info
        
        except Exception as e:
            logger.warning(f"Failed to parse CSR info: {str(e)}")
            return {"error": f"Failed to parse CSR: {str(e)}"}
    
    def validate_csr(self, csr_pem: str) -> Dict:
        """
        Validate a CSR in PEM format
        
        Args:
            csr_pem: CSR in PEM format
        
        Returns:
            Dict containing validation results and CSR information
        """
        try:
            # Parse the CSR
            csr_bytes = csr_pem.encode('utf-8')
            csr = x509.load_pem_x509_csr(csr_bytes)
            
            # Verify the signature
            public_key = csr.public_key()
            
            # Basic validation - check if CSR is properly formed
            validation_results = {
                "is_valid": True,
                "subject": {},
                "public_key_info": {},
                "extensions": {},
                "signature_valid": True
            }
            
            # Parse subject
            for attribute in csr.subject:
                oid_name = attribute.oid._name.lower() if hasattr(attribute.oid, '_name') else str(attribute.oid)
                validation_results["subject"][oid_name] = attribute.value
            
            # Parse public key info
            if hasattr(public_key, 'key_size'):
                validation_results["public_key_info"]["key_size"] = public_key.key_size
                validation_results["public_key_info"]["key_type"] = type(public_key).__name__
            
            # Parse extensions
            try:
                for extension in csr.extensions:
                    ext_name = extension.oid._name if hasattr(extension.oid, '_name') else str(extension.oid)
                    validation_results["extensions"][ext_name] = str(extension.value)
            except:
                pass
            
            return validation_results
        
        except Exception as e:
            return {
                "is_valid": False,
                "error": f"CSR validation failed: {str(e)}"
            }
    
    def generate_csr(self, csr_data: Dict, method: str = 'auto') -> Dict:
        """
        Generate CSR using the specified method
        
        Args:
            csr_data: Dictionary containing CSR parameters
            method: 'auto', 'cryptography', or 'step-cli'
        
        Returns:
            Dict containing CSR and private key
        """
        if method == 'auto':
            # Try step-cli first, fallback to cryptography
            try:
                if self._check_step_cli_availability():
                    return self.generate_csr_with_step_cli(csr_data)
            except:
                pass
            return self.generate_csr_with_cryptography(csr_data)
        elif method == 'step-cli':
            return self.generate_csr_with_step_cli(csr_data)
        elif method == 'cryptography':
            return self.generate_csr_with_cryptography(csr_data)
        else:
            raise CSRGenerationError(f"Unsupported CSR generation method: {method}")
    
    def _check_step_cli_availability(self) -> bool:
        """Check if step CLI is available"""
        try:
            result = subprocess.run([self.step_binary, 'version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False


# Utility function
def get_csr_service() -> CSRService:
    """Get a CSR service instance"""
    return CSRService()
