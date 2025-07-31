# Make the auth directory a Python package

# Core authentication
from .google_auth import (
    get_authenticated_google_service,
    GoogleAuthenticationError,
    start_auth_flow,
    handle_auth_callback,
    get_credentials,
    get_user_info,
)

# Service decorators
from .service_decorator import (
    require_google_service,
    require_multiple_services,
    clear_service_cache,
    get_cache_stats,
)

# Domain-wide delegation
from .domain_delegation import (
    get_delegated_credentials,
    is_domain_delegation_available,
    get_domain_delegation_status,
    clear_delegation_cache,
    DomainDelegationError,
)

# Delegation utility tools
from .delegation_tools import (
    check_delegation_setup,
)

# Scopes
from .scopes import SCOPES, BASE_SCOPES

__all__ = [
    # Core auth
    "get_authenticated_google_service",
    "GoogleAuthenticationError",
    "start_auth_flow",
    "handle_auth_callback",
    "get_credentials",
    "get_user_info",
    # Service decorators
    "require_google_service",
    "require_multiple_services",
    "clear_service_cache",
    "get_cache_stats",
    # Domain delegation
    "get_delegated_credentials",
    "is_domain_delegation_available",
    "get_domain_delegation_status",
    "clear_delegation_cache",
    "DomainDelegationError",
    # Scopes
    "SCOPES",
    "BASE_SCOPES",
]
