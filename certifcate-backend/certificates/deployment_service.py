"""
Certificate Deployment Service

This module provides functionality to deploy certificates to various targets
including SSH servers, API endpoints, and webhooks.
"""

import subprocess
import tempfile
import os
import logging
import requests
import json
from typing import Dict, List, Optional
from datetime import datetime
from django.utils import timezone
from django.conf import settings
from .models import CertificateDeployment, DeploymentTarget, Certificate

logger = logging.getLogger(__name__)


class DeploymentError(Exception):
    """Custom exception for deployment errors"""
    pass


class CertificateDeploymentService:
    """Service class to handle certificate deployments"""
    
    def __init__(self):
        pass
    
    def deploy_certificate(self, certificate: Certificate, target: DeploymentTarget, 
                         deployment_config: Dict) -> CertificateDeployment:
        """
        Deploy a certificate to a target
        
        Args:
            certificate: Certificate instance to deploy
            target: DeploymentTarget instance
            deployment_config: Deployment configuration
        
        Returns:
            CertificateDeployment instance
        """
        deployment = CertificateDeployment.objects.create(
            certificate=certificate,
            target=target,
            initiated_by=deployment_config['user'],
            backup_existing=deployment_config.get('backup_existing', True),
            restart_services=deployment_config.get('restart_services', False),
            services_to_restart=deployment_config.get('services_to_restart', []),
            status='in_progress'
        )
        
        try:
            if target.target_type == 'ssh':
                result = self._deploy_via_ssh(certificate, target, deployment_config)
            elif target.target_type == 'api':
                result = self._deploy_via_api(certificate, target, deployment_config)
            elif target.target_type == 'webhook':
                result = self._deploy_via_webhook(certificate, target, deployment_config)
            else:
                raise DeploymentError(f"Unsupported deployment target type: {target.target_type}")
            
            if result['success']:
                deployment.status = 'success'
                deployment.completed_at = timezone.now()
                target.last_deployment = timezone.now()
                target.last_deployment_status = 'success'
                certificate.deployment_status = 'deployed'
                certificate.last_deployment_date = timezone.now()
            else:
                deployment.status = 'failed'
                deployment.error_message = result.get('error', 'Unknown error')
                target.last_deployment_status = 'failed'
                certificate.deployment_status = 'failed'
            
            deployment.deployment_log = result.get('log', '')
            deployment.save()
            target.save()
            certificate.save()
            
            return deployment
        
        except Exception as e:
            deployment.status = 'failed'
            deployment.error_message = str(e)
            deployment.completed_at = timezone.now()
            deployment.save()
            
            target.last_deployment_status = 'failed'
            target.save()
            
            certificate.deployment_status = 'failed'
            certificate.save()
            
            logger.error(f"Certificate deployment failed: {str(e)}")
            raise DeploymentError(f"Deployment failed: {str(e)}")
    
    def _deploy_via_ssh(self, certificate: Certificate, target: DeploymentTarget, 
                       config: Dict) -> Dict:
        """Deploy certificate via SSH"""
        log_entries = []
        
        try:
            # Create temporary files for certificate and key
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file, \
                 tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as key_file:
                
                cert_file.write(certificate.certificate_content)
                key_file.write(certificate.private_key)
                
                local_cert_path = cert_file.name
                local_key_path = key_file.name
            
            try:
                # Build SSH commands
                ssh_base = [
                    'ssh',
                    '-i', target.ssh_key_path,
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null',
                    f'{target.username}@{target.hostname}'
                ]
                
                scp_base = [
                    'scp',
                    '-i', target.ssh_key_path,
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null'
                ]
                
                # Backup existing certificates if requested
                if config.get('backup_existing', True):
                    log_entries.append("Backing up existing certificates...")
                    backup_cmd = ssh_base + [
                        f'sudo cp {target.remote_cert_path} {target.remote_cert_path}.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true'
                    ]
                    subprocess.run(backup_cmd, check=False, capture_output=True, text=True)
                    
                    backup_cmd = ssh_base + [
                        f'sudo cp {target.remote_key_path} {target.remote_key_path}.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true'
                    ]
                    subprocess.run(backup_cmd, check=False, capture_output=True, text=True)
                    log_entries.append("Backup completed")
                
                # Copy certificate to remote server
                log_entries.append("Copying certificate...")
                cert_copy_cmd = scp_base + [
                    local_cert_path,
                    f'{target.username}@{target.hostname}:/tmp/new_cert.pem'
                ]
                result = subprocess.run(cert_copy_cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode != 0:
                    raise DeploymentError(f"Failed to copy certificate: {result.stderr}")
                
                # Copy private key to remote server
                log_entries.append("Copying private key...")
                key_copy_cmd = scp_base + [
                    local_key_path,
                    f'{target.username}@{target.hostname}:/tmp/new_key.pem'
                ]
                result = subprocess.run(key_copy_cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode != 0:
                    raise DeploymentError(f"Failed to copy private key: {result.stderr}")
                
                # Move files to final location with proper permissions
                log_entries.append("Installing certificate...")
                install_cmd = ssh_base + [
                    f'sudo mv /tmp/new_cert.pem {target.remote_cert_path} && '
                    f'sudo mv /tmp/new_key.pem {target.remote_key_path} && '
                    f'sudo chmod 644 {target.remote_cert_path} && '
                    f'sudo chmod 600 {target.remote_key_path}'
                ]
                result = subprocess.run(install_cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    raise DeploymentError(f"Failed to install certificate: {result.stderr}")
                
                log_entries.append("Certificate installed successfully")
                
                # Restart services if requested
                if config.get('restart_services', False):
                    services = config.get('services_to_restart', [])
                    for service in services:
                        log_entries.append(f"Restarting service: {service}")
                        restart_cmd = ssh_base + [f'sudo systemctl restart {service}']
                        result = subprocess.run(restart_cmd, capture_output=True, text=True, timeout=30)
                        
                        if result.returncode != 0:
                            log_entries.append(f"Warning: Failed to restart {service}: {result.stderr}")
                        else:
                            log_entries.append(f"Service {service} restarted successfully")
                
                # Run post-deployment command if specified
                if target.post_deploy_command:
                    log_entries.append("Running post-deployment command...")
                    post_cmd = ssh_base + [target.post_deploy_command]
                    result = subprocess.run(post_cmd, capture_output=True, text=True, timeout=60)
                    
                    if result.returncode != 0:
                        log_entries.append(f"Post-deployment command failed: {result.stderr}")
                    else:
                        log_entries.append("Post-deployment command completed successfully")
                
                return {
                    'success': True,
                    'log': '\n'.join(log_entries),
                    'deployed_at': timezone.now().isoformat()
                }
            
            finally:
                # Clean up temporary files
                for temp_path in [local_cert_path, local_key_path]:
                    try:
                        if os.path.exists(temp_path):
                            os.unlink(temp_path)
                    except OSError:
                        pass
        
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'SSH deployment timeout',
                'log': '\n'.join(log_entries)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'log': '\n'.join(log_entries)
            }
    
    def _deploy_via_api(self, certificate: Certificate, target: DeploymentTarget, 
                       config: Dict) -> Dict:
        """Deploy certificate via API"""
        try:
            # Prepare payload
            payload = {
                'certificate': certificate.certificate_content,
                'private_key': certificate.private_key,
                'hostname': certificate.hostname,
                'serial_number': certificate.serial_number,
                'expiry_date': certificate.expiry_date.isoformat() if certificate.expiry_date else None,
                'deployment_config': config
            }
            
            # Prepare headers
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {target.api_token}' if target.api_token else None
            }
            
            # Add custom headers
            if target.api_headers:
                headers.update(target.api_headers)
            
            # Remove None values
            headers = {k: v for k, v in headers.items() if v is not None}
            
            # Make API request
            response = requests.post(
                target.api_endpoint,
                json=payload,
                headers=headers,
                timeout=60
            )
            
            if response.status_code in [200, 201, 202]:
                return {
                    'success': True,
                    'log': f'API deployment successful. Response: {response.text}',
                    'response_status': response.status_code,
                    'response_data': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                }
            else:
                return {
                    'success': False,
                    'error': f'API deployment failed with status {response.status_code}: {response.text}',
                    'log': f'Failed API call to {target.api_endpoint}'
                }
        
        except requests.RequestException as e:
            return {
                'success': False,
                'error': f'API request failed: {str(e)}',
                'log': f'Failed to connect to {target.api_endpoint}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'log': f'Unexpected error during API deployment'
            }
    
    def _deploy_via_webhook(self, certificate: Certificate, target: DeploymentTarget, 
                           config: Dict) -> Dict:
        """Deploy certificate via webhook"""
        try:
            # Prepare webhook payload
            if target.webhook_payload_template:
                # Use custom template
                payload_template = target.webhook_payload_template
                payload = payload_template.format(
                    hostname=certificate.hostname,
                    certificate=certificate.certificate_content,
                    private_key=certificate.private_key,
                    serial_number=certificate.serial_number or '',
                    expiry_date=certificate.expiry_date.isoformat() if certificate.expiry_date else '',
                    deployment_id=config.get('deployment_id', ''),
                    timestamp=timezone.now().isoformat()
                )
            else:
                # Default payload
                payload = {
                    'event': 'certificate_deployed',
                    'certificate': {
                        'hostname': certificate.hostname,
                        'serial_number': certificate.serial_number,
                        'expiry_date': certificate.expiry_date.isoformat() if certificate.expiry_date else None,
                        'certificate_content': certificate.certificate_content,
                        'private_key': certificate.private_key
                    },
                    'target': {
                        'name': target.name,
                        'type': target.target_type
                    },
                    'timestamp': timezone.now().isoformat()
                }
                payload = json.dumps(payload)
            
            # Prepare headers
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'WCAMAN-Certificate-Manager/1.0'
            }
            
            # Add custom headers
            if target.webhook_headers:
                headers.update(target.webhook_headers)
            
            # Make webhook request
            response = requests.post(
                target.webhook_url,
                data=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code in [200, 201, 202]:
                return {
                    'success': True,
                    'log': f'Webhook notification sent successfully. Response: {response.status_code}',
                    'response_status': response.status_code
                }
            else:
                return {
                    'success': False,
                    'error': f'Webhook failed with status {response.status_code}: {response.text}',
                    'log': f'Failed webhook call to {target.webhook_url}'
                }
        
        except requests.RequestException as e:
            return {
                'success': False,
                'error': f'Webhook request failed: {str(e)}',
                'log': f'Failed to send webhook to {target.webhook_url}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'log': f'Unexpected error during webhook deployment'
            }
    
    def test_deployment_target(self, target: DeploymentTarget) -> Dict:
        """
        Test connectivity to a deployment target
        
        Args:
            target: DeploymentTarget instance
        
        Returns:
            Dict containing test results
        """
        try:
            if target.target_type == 'ssh':
                return self._test_ssh_connection(target)
            elif target.target_type == 'api':
                return self._test_api_endpoint(target)
            elif target.target_type == 'webhook':
                return self._test_webhook_endpoint(target)
            else:
                return {
                    'success': False,
                    'error': f'Unsupported target type: {target.target_type}'
                }
        
        except Exception as e:
            return {
                'success': False,
                'error': f'Test failed: {str(e)}'
            }
    
    def _test_ssh_connection(self, target: DeploymentTarget) -> Dict:
        """Test SSH connection to target"""
        try:
            cmd = [
                'ssh',
                '-i', target.ssh_key_path,
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'ConnectTimeout=10',
                f'{target.username}@{target.hostname}',
                'echo "SSH connection test successful"'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'message': 'SSH connection successful',
                    'details': result.stdout.strip()
                }
            else:
                return {
                    'success': False,
                    'error': f'SSH connection failed: {result.stderr}',
                    'details': result.stderr
                }
        
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'SSH connection timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'SSH test error: {str(e)}'
            }
    
    def _test_api_endpoint(self, target: DeploymentTarget) -> Dict:
        """Test API endpoint connectivity"""
        try:
            headers = {'User-Agent': 'WCAMAN-Certificate-Manager/1.0'}
            if target.api_token:
                headers['Authorization'] = f'Bearer {target.api_token}'
            
            # Add custom headers
            if target.api_headers:
                headers.update(target.api_headers)
            
            response = requests.get(
                target.api_endpoint,
                headers=headers,
                timeout=10
            )
            
            return {
                'success': True,
                'message': f'API endpoint responded with status {response.status_code}',
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds()
            }
        
        except requests.RequestException as e:
            return {
                'success': False,
                'error': f'API endpoint test failed: {str(e)}'
            }
    
    def _test_webhook_endpoint(self, target: DeploymentTarget) -> Dict:
        """Test webhook endpoint connectivity"""
        try:
            test_payload = {
                'test': True,
                'message': 'WCAMAN webhook connectivity test',
                'timestamp': timezone.now().isoformat()
            }
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'WCAMAN-Certificate-Manager/1.0'
            }
            
            # Add custom headers
            if target.webhook_headers:
                headers.update(target.webhook_headers)
            
            response = requests.post(
                target.webhook_url,
                json=test_payload,
                headers=headers,
                timeout=10
            )
            
            return {
                'success': True,
                'message': f'Webhook endpoint responded with status {response.status_code}',
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds()
            }
        
        except requests.RequestException as e:
            return {
                'success': False,
                'error': f'Webhook endpoint test failed: {str(e)}'
            }


# Utility function
def get_deployment_service() -> CertificateDeploymentService:
    """Get a certificate deployment service instance"""
    return CertificateDeploymentService()
