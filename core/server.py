import logging
from typing import Optional, Union
from importlib import metadata

from fastapi.responses import HTMLResponse, JSONResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.middleware import Middleware

from fastmcp import FastMCP

from auth.oauth21_session_store import get_oauth21_session_store, set_auth_provider
from auth.google_auth import handle_auth_callback, start_auth_flow, check_client_secrets
from auth.oauth_callback_server import (
    get_oauth_redirect_uri,
    ensure_oauth_callback_available,
)
from auth.auth_info_middleware import AuthInfoMiddleware
from auth.fastmcp_google_auth import GoogleWorkspaceAuthProvider
from auth.scopes import SCOPES, get_current_scopes  # noqa
from core.config import (
    USER_GOOGLE_EMAIL,
    get_transport_mode,
    set_transport_mode as _set_transport_mode,
    get_oauth_redirect_uri as get_oauth_redirect_uri_for_current_mode,
    WORKSPACE_MCP_PORT,
    WORKSPACE_MCP_BASE_URI,
)
from auth.oauth_responses import (
    create_error_response,
    create_success_response,
    create_server_error_response,
)

# Import shared configuration
from auth.scopes import (
    SCOPES,
    USERINFO_EMAIL_SCOPE,  # noqa: F401
    OPENID_SCOPE,  # noqa: F401
    CALENDAR_READONLY_SCOPE,  # noqa: F401
    CALENDAR_EVENTS_SCOPE,  # noqa: F401
    DRIVE_READONLY_SCOPE,  # noqa: F401
    DRIVE_FILE_SCOPE,  # noqa: F401
    GMAIL_READONLY_SCOPE,  # noqa: F401
    GMAIL_SEND_SCOPE,  # noqa: F401
    GMAIL_COMPOSE_SCOPE,  # noqa: F401
    GMAIL_MODIFY_SCOPE,  # noqa: F401
    GMAIL_LABELS_SCOPE,  # noqa: F401
    BASE_SCOPES,  # noqa: F401
    CALENDAR_SCOPES,  # noqa: F401
    DRIVE_SCOPES,  # noqa: F401
    GMAIL_SCOPES,  # noqa: F401
    DOCS_READONLY_SCOPE,  # noqa: F401
    DOCS_WRITE_SCOPE,  # noqa: F401
    CHAT_READONLY_SCOPE,  # noqa: F401
    CHAT_WRITE_SCOPE,  # noqa: F401
    CHAT_SPACES_SCOPE,  # noqa: F401
    CHAT_SCOPES,  # noqa: F401
    SHEETS_READONLY_SCOPE,  # noqa: F401
    SHEETS_WRITE_SCOPE,  # noqa: F401
    SHEETS_SCOPES,  # noqa: F401
    FORMS_BODY_SCOPE,  # noqa: F401
    FORMS_BODY_READONLY_SCOPE,  # noqa: F401
    FORMS_RESPONSES_READONLY_SCOPE,  # noqa: F401
    FORMS_SCOPES,  # noqa: F401
    SLIDES_SCOPE,  # noqa: F401
    SLIDES_READONLY_SCOPE,  # noqa: F401
    SLIDES_SCOPES,  # noqa: F401
    TASKS_SCOPE,  # noqa: F401
    TASKS_READONLY_SCOPE,  # noqa: F401
    TASKS_SCOPES,  # noqa: F401
)

try:
    from auth.google_remote_auth_provider import GoogleRemoteAuthProvider

    GOOGLE_REMOTE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_REMOTE_AUTH_AVAILABLE = False
    GoogleRemoteAuthProvider = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_auth_provider: Optional[Union[GoogleWorkspaceAuthProvider, GoogleRemoteAuthProvider]] = None

session_middleware = Middleware(MCPSessionMiddleware)


# Custom FastMCP that adds secure middleware stack for OAuth 2.1
class SecureFastMCP(FastMCP):
    def streamable_http_app(self) -> "Starlette":
        """Override to add secure middleware stack for OAuth 2.1."""
        app = super().streamable_http_app()

        # Add middleware in order (first added = outermost layer)
        # Session Management - extracts session info for MCP context
        app.user_middleware.insert(0, session_middleware)

        # Rebuild middleware stack
        app.middleware_stack = app.build_middleware_stack()
        logger.info("Added middleware stack: Session Management")
        return app


server = SecureFastMCP(
    name="google_workspace",
    server_url=f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/mcp",
    port=WORKSPACE_MCP_PORT,
    auth=None,
    host="0.0.0.0",
)

# Add the AuthInfo middleware to inject authentication into FastMCP context
auth_info_middleware = AuthInfoMiddleware()
server.add_middleware(auth_info_middleware)


def set_transport_mode(mode: str):
    """Sets the transport mode for the server."""
    _set_transport_mode(mode)
    logger.info(f"Transport: {mode}")


def configure_server_for_http():
    """
    Configures the authentication provider for HTTP transport.
    This must be called BEFORE server.run().
    """
    global _auth_provider

    transport_mode = get_transport_mode()

    if transport_mode != "streamable-http":
        return

    # Use centralized OAuth configuration
    from auth.oauth_config import get_oauth_config

    config = get_oauth_config()

    # Check if OAuth 2.1 is enabled via centralized config
    oauth21_enabled = config.is_oauth21_enabled()

    if oauth21_enabled:
        if not config.is_configured():
            logger.warning("OAuth 2.1 enabled but OAuth credentials not configured")
            return

        if not GOOGLE_REMOTE_AUTH_AVAILABLE:
            logger.error("CRITICAL: OAuth 2.1 enabled but FastMCP 2.11.1+ is not properly installed.")
            logger.error("Please run: uv sync --frozen")
            raise RuntimeError(
                "OAuth 2.1 requires FastMCP 2.11.1+ with RemoteAuthProvider support. "
                "Please reinstall dependencies using 'uv sync --frozen'."
            )

        logger.info("OAuth 2.1 enabled with automatic OAuth 2.0 fallback for legacy clients")
        try:
            _auth_provider = GoogleRemoteAuthProvider()
            server.auth = _auth_provider
            set_auth_provider(_auth_provider)
            logger.debug("OAuth 2.1 authentication enabled")
        except Exception as e:
            logger.error(f"Failed to initialize GoogleRemoteAuthProvider: {e}", exc_info=True)
            raise
    else:
        logger.info("OAuth 2.0 mode - Server will use legacy authentication.")
        server.auth = None


def get_auth_provider() -> Optional[Union[GoogleWorkspaceAuthProvider, GoogleRemoteAuthProvider]]:
    """Gets the global authentication provider instance."""
    return _auth_provider


@server.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    try:
        version = metadata.version("workspace-mcp")
    except metadata.PackageNotFoundError:
        version = "dev"
    return JSONResponse(
        {
            "status": "healthy",
            "service": "workspace-mcp",
            "version": version,
            "transport": get_transport_mode(),
        }
    )


@server.custom_route("/oauth2callback", methods=["GET"])
async def oauth2_callback(request: Request) -> HTMLResponse:
    state = request.query_params.get("state")
    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if error:
        msg = f"Authentication failed: Google returned an error: {error}. State: {state}."
        logger.error(msg)
        return create_error_response(msg)

    if not code:
        msg = "Authentication failed: No authorization code received from Google."
        logger.error(msg)
        return create_error_response(msg)

    try:
        error_message = check_client_secrets()
        if error_message:
            return create_server_error_response(error_message)

        logger.info(f"OAuth callback: Received code (state: {state}).")

        verified_user_id, credentials = handle_auth_callback(
            scopes=get_current_scopes(),
            authorization_response=str(request.url),
            redirect_uri=get_oauth_redirect_uri_for_current_mode(),
            session_id=None,
        )

        logger.info(f"OAuth callback: Successfully authenticated user: {verified_user_id} .")

        try:
            store = get_oauth21_session_store()
            mcp_session_id = None
            if hasattr(request, "state") and hasattr(request.state, "session_id"):
                mcp_session_id = request.state.session_id

            store.store_session(
                user_email=verified_user_id,
                access_token=credentials.token,
                refresh_token=credentials.refresh_token,
                token_uri=credentials.token_uri,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                scopes=credentials.scopes,
                expiry=credentials.expiry,
                session_id=f"google-{state}",
                mcp_session_id=mcp_session_id,
            )
            logger.info(f"Stored Google credentials in OAuth 2.1 session store for {verified_user_id}")
        except Exception as e:
            logger.error(f"Failed to store credentials in OAuth 2.1 store: {e}")

        return create_success_response(verified_user_id)
    except Exception as e:
        logger.error(f"Error processing OAuth callback: {str(e)}", exc_info=True)
        return create_server_error_response(str(e))


@server.tool()
async def start_google_auth(service_name: str, user_google_email: str = USER_GOOGLE_EMAIL) -> str:
    """
    Manually initiate Google OAuth authentication flow.

    NOTE: This tool should typically NOT be called directly. The authentication system
    automatically handles credential checks and prompts for authentication when needed.
    Only use this tool if:
    1. You need to re-authenticate with different credentials
    2. You want to proactively authenticate before using other tools
    3. The automatic authentication flow failed and you need to retry

    In most cases, simply try calling the Google Workspace tool you need - it will
    automatically handle authentication if required.
    """
    if not user_google_email:
        raise ValueError("user_google_email must be provided.")

    error_message = check_client_secrets()
    if error_message:
        return f"**Authentication Error:** {error_message}"

    logger.info(
        f"Tool 'start_google_auth' invoked for user_google_email: '{user_google_email}', service: '{service_name}'."
    )

    # Ensure OAuth callback is available for current transport mode
    redirect_uri = get_oauth_redirect_uri_for_current_mode()
    success, error_msg = ensure_oauth_callback_available(
        get_transport_mode(), WORKSPACE_MCP_PORT, WORKSPACE_MCP_BASE_URI
    )
    if not success:
        if error_msg:
            raise Exception(f"Failed to start OAuth callback server: {error_msg}")
        else:
            raise Exception("Failed to start OAuth callback server. Please try again.")
    try:
        auth_message = await start_auth_flow(
            user_google_email=user_google_email,
            service_name=service_name,
            redirect_uri=get_oauth_redirect_uri_for_current_mode(),
        )
        return auth_message
    except Exception as e:
        logger.error(f"Failed to start Google authentication flow: {e}", exc_info=True)
        return f"**Error:** An unexpected error occurred: {e}"
