# auth/domain_delegation.py

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from google.oauth2 import service_account
from google.oauth2.service_account import Credentials as ServiceAccountCredentials

from auth.scopes import SCOPES

logger = logging.getLogger(__name__)

# Environment variable for service account key
SERVICE_ACCOUNT_KEY_ENV = "GOOGLE_SERVICE_ACCOUNT_KEY"
SERVICE_ACCOUNT_FILE_ENV = "GOOGLE_SERVICE_ACCOUNT_FILE"

# Cache for delegated credentials: {user_email: (credentials, expiry_time)}
_delegated_credentials_cache: Dict[str, tuple[ServiceAccountCredentials, datetime]] = {}
_cache_ttl = timedelta(minutes=55)  # Service account tokens expire after 1 hour, refresh at 55 minutes


class DomainDelegationError(Exception):
    """Exception raised when domain delegation fails."""

    pass


def _get_service_account_credentials(
    scopes: Optional[List[str]] = None,
) -> Optional[ServiceAccountCredentials]:
    """
    Load service account credentials from environment variable or file.

    Args:
        scopes: Optional list of OAuth scopes. If None, uses global SCOPES.

    Returns:
        ServiceAccountCredentials object or None if not found/invalid
    """
    if scopes is None:
        scopes = SCOPES

    try:
        # First try environment variable with JSON key content
        service_account_key = os.getenv(SERVICE_ACCOUNT_KEY_ENV)
        if service_account_key:
            try:
                key_data = json.loads(service_account_key)
                credentials = service_account.Credentials.from_service_account_info(key_data, scopes=scopes)
                logger.info("Loaded service account credentials from environment variable")
                return credentials
            except (json.JSONDecodeError, ValueError) as e:
                logger.error(f"Invalid service account key in environment variable: {e}")
                return None

        # Try file path from environment variable
        service_account_file = os.getenv(SERVICE_ACCOUNT_FILE_ENV)
        if service_account_file and os.path.exists(service_account_file):
            try:
                credentials = service_account.Credentials.from_service_account_file(service_account_file, scopes=scopes)
                logger.info(f"Loaded service account credentials from file: {service_account_file}")
                return credentials
            except Exception as e:
                logger.error(f"Error loading service account file {service_account_file}: {e}")
                return None

        # Check for service account file in default location
        default_service_account_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "service_account.json",
        )
        if os.path.exists(default_service_account_path):
            try:
                credentials = service_account.Credentials.from_service_account_file(
                    default_service_account_path, scopes=scopes
                )
                logger.info(f"Loaded service account credentials from default location: {default_service_account_path}")
                return credentials
            except Exception as e:
                logger.error(f"Error loading service account file {default_service_account_path}: {e}")
                return None

        logger.debug("No service account credentials found")
        return None

    except Exception as e:
        logger.error(f"Unexpected error loading service account credentials: {e}")
        return None


def _validate_email_domain(email: str, service_account_credentials: ServiceAccountCredentials) -> bool:
    """
    Validate that the email belongs to a domain that the service account can impersonate.

    This is a basic validation - in production, you might want to maintain a whitelist
    of allowed domains or implement more sophisticated validation.

    Args:
        email: Email address to validate
        service_account_credentials: Service account credentials

    Returns:
        True if email domain is valid for impersonation
    """
    if not email or "@" not in email:
        return False

    # Extract domain from email
    domain = email.split("@")[1].lower()

    # For now, we'll allow any domain. In production, you should:
    # 1. Check against a whitelist of allowed domains
    # 2. Verify domain ownership
    # 3. Check if domain has enabled domain-wide delegation for this service account

    logger.debug(f"Validating domain delegation for email: {email}, domain: {domain}")
    return True


def get_delegated_credentials(user_email: str, required_scopes: List[str]) -> Optional[ServiceAccountCredentials]:
    """
    Get delegated credentials for a specific user using domain-wide delegation.

    Args:
        user_email: Email of the user to impersonate
        required_scopes: List of required OAuth scopes

    Returns:
        ServiceAccountCredentials configured for the user, or None if delegation fails
    """
    logger.info(f"[domain-delegation] Attempting to get delegated credentials for: {user_email}")

    # Load base service account credentials with only the required scopes
    base_credentials = _get_service_account_credentials(required_scopes)
    if not base_credentials:
        logger.warning("[domain-delegation] No service account credentials available")
        return None

    # Validate email domain
    if not _validate_email_domain(user_email, base_credentials):
        logger.warning(f"[domain-delegation] Email domain not valid for delegation: {user_email}")
        return None

    # Check cache first
    cache_key = user_email
    if cache_key in _delegated_credentials_cache:
        cached_credentials, expiry_time = _delegated_credentials_cache[cache_key]
        if datetime.now() < expiry_time and cached_credentials.valid:
            logger.debug(f"[domain-delegation] Using cached credentials for: {user_email}")
            return cached_credentials
        else:
            # Remove expired cache entry
            del _delegated_credentials_cache[cache_key]
            logger.debug(f"[domain-delegation] Removed expired cache entry for: {user_email}")

    try:
        # Create delegated credentials
        delegated_credentials = base_credentials.with_subject(user_email)

        # Credentials were loaded with exactly the required scopes

        # Test the credentials with a minimal API call to detect admin configuration issues
        try:
            # Try to build a service to validate the credentials work
            from googleapiclient.discovery import build

            test_service = build("calendar", "v3", credentials=delegated_credentials)
            # Don't actually make a call, just test that the service can be built
            logger.debug(f"[domain-delegation] Credentials validation passed for: {user_email}")
        except Exception as validation_error:
            # If we can't even build the service, it's likely a configuration issue
            logger.warning(f"[domain-delegation] Credential validation failed for {user_email}: {validation_error}")

            # Try to extract client ID for helpful error message
            client_id = "Unknown"
            try:
                import json

                service_account_file = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")
                if service_account_file and os.path.exists(service_account_file):
                    with open(service_account_file, "r") as f:
                        data = json.load(f)
                        client_id = data.get("client_id", "Unknown")
            except:
                pass

            raise DomainDelegationError(
                f"Domain-wide delegation failed for {user_email}. "
                f"The service account '{getattr(base_credentials, 'service_account_email', 'Unknown')}' "
                f"is not authorized for domain-wide delegation in Google Workspace Admin Console. "
                f"Please configure domain-wide delegation for Client ID: {client_id} in the Admin Console."
            )

        # Cache the credentials
        expiry_time = datetime.now() + _cache_ttl
        _delegated_credentials_cache[cache_key] = (delegated_credentials, expiry_time)
        logger.info(f"[domain-delegation] Successfully created and cached delegated credentials for: {user_email}")

        return delegated_credentials

    except DomainDelegationError:
        # Re-raise domain delegation errors as-is
        raise
    except Exception as e:
        logger.error(f"[domain-delegation] Error creating delegated credentials for {user_email}: {e}")
        raise DomainDelegationError(f"Failed to create delegated credentials for {user_email}: {str(e)}")


def is_domain_delegation_available() -> bool:
    """
    Check if domain-wide delegation is available and properly configured.

    Returns:
        True if domain delegation can be used
    """
    base_credentials = _get_service_account_credentials()
    if not base_credentials:
        return False

    # Additional checks could be added here:
    # - Verify service account has domain-wide delegation enabled
    # - Check if required scopes are authorized
    # - Test delegation with a known email

    return True


def get_domain_delegation_status() -> Dict[str, Any]:
    """
    Get status information about domain-wide delegation configuration.

    Returns:
        Dictionary containing status information
    """
    base_credentials = _get_service_account_credentials()

    status = {
        "available": base_credentials is not None,
        "service_account_email": None,
        "project_id": None,
        "scopes": [],
        "cached_users": list(_delegated_credentials_cache.keys()),
        "cache_size": len(_delegated_credentials_cache),
    }

    if base_credentials:
        status["service_account_email"] = getattr(base_credentials, "service_account_email", "Unknown")
        status["project_id"] = getattr(base_credentials, "project_id", "Unknown")
        status["scopes"] = list(base_credentials.scopes or [])

    return status


def clear_delegation_cache(user_email: Optional[str] = None) -> int:
    """
    Clear delegation credential cache.

    Args:
        user_email: If provided, only clear cache for this user. If None, clear all.

    Returns:
        Number of cache entries cleared
    """
    global _delegated_credentials_cache

    if user_email is None:
        count = len(_delegated_credentials_cache)
        _delegated_credentials_cache.clear()
        logger.info(f"[domain-delegation] Cleared all {count} delegation cache entries")
        return count

    if user_email in _delegated_credentials_cache:
        del _delegated_credentials_cache[user_email]
        logger.info(f"[domain-delegation] Cleared delegation cache for user: {user_email}")
        return 1

    return 0
