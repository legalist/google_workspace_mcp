"""
Google Docs MCP Tools

This module provides MCP tools for interacting with Google Docs API and managing Google Docs via Drive.
"""

import logging
import asyncio
import io

from googleapiclient.http import MediaIoBaseDownload

# Auth & server utilities
from auth.service_decorator import require_google_service, require_multiple_services
from core.utils import extract_office_xml_text, handle_http_errors
from core.server import server
from core.comments import create_comment_tools

logger = logging.getLogger(__name__)


@server.tool()
@handle_http_errors("search_docs", is_read_only=True, service_type="docs")
@require_google_service("drive", "drive_read")
async def search_docs(
    service,
    user_google_email: str,
    query: str,
    page_size: int = 10,
) -> str:
    """
    Searches for Google Docs by name using Drive API (mimeType filter).

    Returns:
        str: A formatted list of Google Docs matching the search query.
    """
    logger.info(f"[search_docs] Email={user_google_email}, Query='{query}'")

    escaped_query = query.replace("'", "\\'")

    response = await asyncio.to_thread(
        service.files()
        .list(
            q=f"name contains '{escaped_query}' and mimeType='application/vnd.google-apps.document' and trashed=false",
            pageSize=page_size,
            fields="files(id, name, createdTime, modifiedTime, webViewLink)",
        )
        .execute
    )
    files = response.get("files", [])
    if not files:
        return f"No Google Docs found matching '{query}'."

    output = [f"Found {len(files)} Google Docs matching '{query}':"]
    for f in files:
        output.append(f"- {f['name']} (ID: {f['id']}) Modified: {f.get('modifiedTime')} Link: {f.get('webViewLink')}")
    return "\n".join(output)


@server.tool()
@handle_http_errors("get_doc_content", is_read_only=True, service_type="docs")
@require_multiple_services(
    [
        {
            "service_type": "drive",
            "scopes": "drive_read",
            "param_name": "drive_service",
        },
        {"service_type": "docs", "scopes": "docs_read", "param_name": "docs_service"},
    ]
)
async def get_doc_content(
    drive_service,
    docs_service,
    user_google_email: str,
    document_id: str,
) -> str:
    """
    Retrieves content of a Google Doc or a Drive file (like .docx) identified by document_id.
    - Native Google Docs: Fetches content via Docs API.
    - Office files (.docx, etc.) stored in Drive: Downloads via Drive API and extracts text.

    Returns:
        str: The document content with metadata header.
    """
    logger.info(f"[get_doc_content] Invoked. Document/File ID: '{document_id}' for user '{user_google_email}'")

    # Step 2: Get file metadata from Drive
    file_metadata = await asyncio.to_thread(
        drive_service.files().get(fileId=document_id, fields="id, name, mimeType, webViewLink").execute
    )
    mime_type = file_metadata.get("mimeType", "")
    file_name = file_metadata.get("name", "Unknown File")
    web_view_link = file_metadata.get("webViewLink", "#")

    logger.info(f"[get_doc_content] File '{file_name}' (ID: {document_id}) has mimeType: '{mime_type}'")

    body_text = ""  # Initialize body_text

    # Step 3: Process based on mimeType
    if mime_type == "application/vnd.google-apps.document":
        logger.info("[get_doc_content] Processing as native Google Doc.")
        doc_data = await asyncio.to_thread(
            docs_service.documents().get(documentId=document_id, includeTabsContent=True).execute
        )
        # Tab header format constant
        TAB_HEADER_FORMAT = "\n--- TAB: {tab_name} ---\n"

        def extract_text_from_elements(elements, tab_name=None, depth=0):
            """Extract text from document elements (paragraphs, tables, etc.)"""
            # Prevent infinite recursion by limiting depth
            if depth > 5:
                return ""
            text_lines = []
            if tab_name:
                text_lines.append(TAB_HEADER_FORMAT.format(tab_name=tab_name))

            for element in elements:
                if "paragraph" in element:
                    paragraph = element.get("paragraph", {})
                    para_elements = paragraph.get("elements", [])
                    current_line_text = ""
                    for pe in para_elements:
                        text_run = pe.get("textRun", {})
                        if text_run and "content" in text_run:
                            current_line_text += text_run["content"]
                    if current_line_text.strip():
                        text_lines.append(current_line_text)
                elif "table" in element:
                    # Handle table content
                    table = element.get("table", {})
                    table_rows = table.get("tableRows", [])
                    for row in table_rows:
                        row_cells = row.get("tableCells", [])
                        for cell in row_cells:
                            cell_content = cell.get("content", [])
                            cell_text = extract_text_from_elements(cell_content, depth=depth + 1)
                            if cell_text.strip():
                                text_lines.append(cell_text)
            return "".join(text_lines)

        def process_tab_hierarchy(tab, level=0):
            """Process a tab and its nested child tabs recursively"""
            tab_text = ""

            if "documentTab" in tab:
                tab_title = tab.get("documentTab", {}).get("title", "Untitled Tab")
                # Add indentation for nested tabs to show hierarchy
                if level > 0:
                    tab_title = "    " * level + tab_title
                tab_body = tab.get("documentTab", {}).get("body", {}).get("content", [])
                tab_text += extract_text_from_elements(tab_body, tab_title)

            # Process child tabs (nested tabs)
            child_tabs = tab.get("childTabs", [])
            for child_tab in child_tabs:
                tab_text += process_tab_hierarchy(child_tab, level + 1)

            return tab_text

        processed_text_lines = []

        # Process main document body
        body_elements = doc_data.get("body", {}).get("content", [])
        main_content = extract_text_from_elements(body_elements)
        if main_content.strip():
            processed_text_lines.append(main_content)

        # Process all tabs
        tabs = doc_data.get("tabs", [])
        for tab in tabs:
            tab_content = process_tab_hierarchy(tab)
            if tab_content.strip():
                processed_text_lines.append(tab_content)

        body_text = "".join(processed_text_lines)
    else:
        logger.info(f"[get_doc_content] Processing as Drive file (e.g., .docx, other). MimeType: {mime_type}")

        export_mime_type_map = {
            # Example: "application/vnd.google-apps.spreadsheet"z: "text/csv",
            # Native GSuite types that are not Docs would go here if this function
            # was intended to export them. For .docx, direct download is used.
        }
        effective_export_mime = export_mime_type_map.get(mime_type)

        request_obj = (
            drive_service.files().export_media(fileId=document_id, mimeType=effective_export_mime)
            if effective_export_mime
            else drive_service.files().get_media(fileId=document_id)
        )

        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request_obj)
        loop = asyncio.get_event_loop()
        done = False
        while not done:
            status, done = await loop.run_in_executor(None, downloader.next_chunk)

        file_content_bytes = fh.getvalue()

        office_text = extract_office_xml_text(file_content_bytes, mime_type)
        if office_text:
            body_text = office_text
        else:
            try:
                body_text = file_content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                body_text = (
                    f"[Binary or unsupported text encoding for mimeType '{mime_type}' - "
                    f"{len(file_content_bytes)} bytes]"
                )

    header = f'File: "{file_name}" (ID: {document_id}, Type: {mime_type})\nLink: {web_view_link}\n\n--- CONTENT ---\n'
    return header + body_text


@server.tool()
@handle_http_errors("list_docs_in_folder", is_read_only=True, service_type="docs")
@require_google_service("drive", "drive_read")
async def list_docs_in_folder(service, user_google_email: str, folder_id: str = "root", page_size: int = 100) -> str:
    """
    Lists Google Docs within a specific Drive folder.

    Returns:
        str: A formatted list of Google Docs in the specified folder.
    """
    logger.info(f"[list_docs_in_folder] Invoked. Email: '{user_google_email}', Folder ID: '{folder_id}'")

    rsp = await asyncio.to_thread(
        service.files()
        .list(
            q=f"'{folder_id}' in parents and mimeType='application/vnd.google-apps.document' and trashed=false",
            pageSize=page_size,
            fields="files(id, name, modifiedTime, webViewLink)",
        )
        .execute
    )
    items = rsp.get("files", [])
    if not items:
        return f"No Google Docs found in folder '{folder_id}'."
    out = [f"Found {len(items)} Docs in folder '{folder_id}':"]
    for f in items:
        out.append(f"- {f['name']} (ID: {f['id']}) Modified: {f.get('modifiedTime')} Link: {f.get('webViewLink')}")
    return "\n".join(out)


@server.tool()
@handle_http_errors("create_doc", service_type="docs")
@require_google_service("docs", "docs_write")
async def create_doc(
    service,
    user_google_email: str,
    title: str,
    content: str = "",
) -> str:
    """
    Creates a new Google Doc and optionally inserts initial content.

    Returns:
        str: Confirmation message with document ID and link.
    """
    logger.info(f"[create_doc] Invoked. Email: '{user_google_email}', Title='{title}'")

    doc = await asyncio.to_thread(service.documents().create(body={"title": title}).execute)
    doc_id = doc.get("documentId")
    if content:
        requests = [{"insertText": {"location": {"index": 1}, "text": content}}]
        await asyncio.to_thread(service.documents().batchUpdate(documentId=doc_id, body={"requests": requests}).execute)
    link = f"https://docs.google.com/document/d/{doc_id}/edit"
    msg = f"Created Google Doc '{title}' (ID: {doc_id}) for {user_google_email}. Link: {link}"
    logger.info(f"Successfully created Google Doc '{title}' (ID: {doc_id}) for {user_google_email}. Link: {link}")
    return msg


# Create comment management tools for documents
_comment_tools = create_comment_tools("document", "document_id")

# Extract and register the functions
read_doc_comments = _comment_tools["read_comments"]
create_doc_comment = _comment_tools["create_comment"]
reply_to_comment = _comment_tools["reply_to_comment"]
resolve_comment = _comment_tools["resolve_comment"]
