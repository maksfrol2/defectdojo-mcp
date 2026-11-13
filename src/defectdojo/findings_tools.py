from typing import Any, Dict, List, Optional
from defectdojo.client import get_client 

# --- Finding Tool Definitions ---

# Default fields returned when the caller doesn't ask for anything specific.
# Keeps responses lean for the common "what's open / what severity" queries.
_DEFAULT_FIELDS = ["id", "title", "severity", "status", "active", "risk_accepted", "product_name"]

def _trim_results(result: Dict[str, Any], fields: Optional[List[str]]) -> Dict[str, Any]:
    """Project each finding down to the requested fields, if any were requested."""
    if not fields or "results" not in result:
        return result
    trimmed = dict(result)
    trimmed["results"] = [
        {k: f.get(k) for k in fields if k in f}
        for f in result["results"]
    ]
    return trimmed


async def get_findings(product_name: Optional[str] = None, status: Optional[str] = None, vulnerability_id: Optional[str] = None,
                       severity: Optional[str] = None, limit: int = 10, active: Optional[bool] = None,
                       offset: int = 0, fields: Optional[List[str]] = None) -> Dict[str, Any]:
    """Get findings with optional filters and pagination.

    Args:
        product_name: Optional product name filter
        status: Optional status filter
        severity: Optional severity filter
        limit: Maximum number of findings to return per page (default: 10)
        offset: Number of records to skip (default: 0)
        fields: Optional list of fields to return per finding (e.g. ["id", "title", "severity"]).
                Omit to get default lightweight fields (id, title, severity, status, active,
                risk_accepted, product_name). Pass "all" as the single element to get the
                full raw finding object (description, mitigation, steps_to_reproduce, etc.)

    Returns:
        Dictionary with status, data/error, and pagination metadata
    """
    filters = {}
    if product_name:
        filters["product_name"] = product_name
    if status:
        filters["status"] = status
    if severity:
        filters["severity"] = severity
    if active is not None:
        filters["active"] = active
    if vulnerability_id is not None:
        filters["vulnerability_id"] = vulnerability_id
    if limit:
        filters["limit"] = limit
    if offset:
        filters["offset"] = offset

    client = get_client()
    result = await client.get_findings(filters)

    if "error" in result:
        return {"status": "error", "error": result["error"], "details": result.get("details", "")}

    effective_fields = None if fields == ["all"] else (fields or _DEFAULT_FIELDS)
    return {"status": "success", "data": _trim_results(result, effective_fields)}


async def search_findings(query: str, product_name: Optional[str] = None, vulnerability_id: Optional[str] = None,
                         status: Optional[str] = None, active: Optional[bool] = None, severity: Optional[str] = None,
                         limit: int = 10, offset: int = 0, fields: Optional[List[str]] = None) -> Dict[str, Any]:
    """Search for findings using a text query with pagination.

    Args:
        query: Text to search for in findings
        product_name: Optional product name filter
        status: Optional status filter
        severity: Optional severity filter
        limit: Maximum number of findings to return per page (default: 10)
        offset: Number of records to skip (default: 0)
        fields: Optional list of fields to return per finding. Omit for default lightweight
                fields; pass ["all"] for the full raw finding object.

    Returns:
        Dictionary with status, data/error, and pagination metadata
    """
    filters = {}
    if product_name:
        filters["product_name"] = product_name
    if status:
        filters["status"] = status
    if active is not None:
        filters["active"] = active
    if vulnerability_id is not None:
        filters["vulnerability_id"] = vulnerability_id
    if severity:
        filters["severity"] = severity
    if limit:
        filters["limit"] = limit
    if offset:
        filters["offset"] = offset

    client = get_client()
    result = await client.search_findings(query, filters)

    if "error" in result:
        return {"status": "error", "error": result["error"], "details": result.get("details", "")}

    effective_fields = None if fields == ["all"] else (fields or _DEFAULT_FIELDS)
    return {"status": "success", "data": _trim_results(result, effective_fields)}



async def bulk_accept_risk(finding_ids: List[int], reason: str) -> Dict[str, Any]:
    """Accept risk on multiple findings at once with a shared justification.

    Runs the accept_risk flow (deactivate + risk_accepted + note) for each
    finding in turn, in a single tool call instead of one per finding.

    Args:
        finding_ids: List of finding IDs to accept risk on
        reason: Justification for accepting the risk, applied to all findings

    Returns:
        status: "success" if all findings succeeded, "partial_success" if some failed
        results: dict mapping finding_id -> individual result
        succeeded: list of finding IDs that were fully accepted
        failed: list of finding IDs that hit an error or partial failure
    """
    if not reason.strip():
        return {"status": "error", "error": "Reason cannot be empty"}

    if not finding_ids:
        return {"status": "error", "error": "finding_ids cannot be empty"}

    per_finding: Dict[int, Any] = {}
    succeeded: List[int] = []
    failed: List[int] = []

    for fid in finding_ids:
        try:
            res = await accept_risk(fid, reason)
        except Exception as e:
            res = {"status": "error", "error": str(e)}

        per_finding[fid] = res
        if res.get("status") == "success":
            succeeded.append(fid)
        else:
            failed.append(fid)

    overall_status = "success" if not failed else ("partial_success" if succeeded else "error")

    return {
        "status": overall_status,
        "results": per_finding,
        "succeeded": succeeded,
        "failed": failed,
    }


# --- Registration Function ---

def register_tools(mcp):
    """Register finding-related tools with the MCP server instance."""
    mcp.tool(name="get_findings",description="Get findings with filtering options (product, status, severity, active), pagination, and an optional 'fields' param to trim each finding to just the fields you need (defaults to id/title/severity/status/active/risk_accepted/product_name; pass fields=['all'] for full detail)")(get_findings)
    mcp.tool(name="search_findings",description="Search for findings using a text query, with filters for product, status, severity, and active state, pagination, and the same optional 'fields' trimming as get_findings")(search_findings)
    mcp.tool(name="update_finding_status", description="Update the status of a finding (Active, Verified, False Positive, Mitigated, Inactive)")(update_finding_status)
    mcp.tool(name="add_finding_note", description="Add a note to a finding")(add_finding_note)
    mcp.tool(name="create_finding", description="Create a new finding")(create_finding)
    mcp.tool(name="update_risk_acceptance", description="Accept or un-accept the risk on a finding (accepting also deactivates it; requires simple risk acceptance to be enabled for the product)")(update_risk_acceptance)
    mcp.tool(name="accept_risk",description="Accept a single finding's risk and record the justification in one call (deactivates the finding, sets risk_accepted, adds a note)")(accept_risk)
    mcp.tool(name="bulk_accept_risk",description="Accept risk on multiple findings at once with a shared justification note — one tool call instead of calling accept_risk per finding")(bulk_accept_risk)
    

async def update_risk_acceptance(finding_id: int, risk_accepted: bool) -> Dict[str, Any]:
    """Accept or un-accept the risk on a finding.

    Args:
        finding_id: ID of the finding to update
        risk_accepted: True to accept the risk (also deactivates the finding),
                        False to un-accept it

    Returns:
        Dictionary with status and data/error
    """
    data: Dict[str, Any] = {"risk_accepted": risk_accepted}
    if risk_accepted:
        # Required by the API: can't accept risk while the finding is still active
        data["active"] = False

    client = get_client()
    result = await client.update_finding(finding_id, data)

    if "error" in result:
        return {"status": "error", "error": result["error"], "details": result.get("details", "")}

    return {"status": "success", "data": result}


async def accept_risk(finding_id: int, reason: str) -> Dict[str, Any]:
    """Accept a finding's risk in one call: deactivates it, marks risk_accepted,
    and records the justification as a note.

    Args:
        finding_id: ID of the finding to accept risk on
        reason: Justification for accepting the risk (required, non-empty)

    Returns:
        status: "success", "partial_success" (risk accepted but note failed), or "error"
    """
    if not reason.strip():
        return {
            "status": "error",
            "error": "Reason cannot be empty"
        }

    client = get_client()

    # Accept risk
    result = await client.update_finding(finding_id,
        {
            "risk_accepted": True,
            "active": False
        }
    )

    if "error" in result:
        return {
            "status": "error",
            "error": result["error"]
        }

    # Add note
    note_result = await client.add_note_to_finding(
        finding_id,
        reason
    )

    if "error" in note_result:
        return {
            "status": "partial_success",
            "finding_updated": True,
            "note_added": False,
            "error": note_result["error"]
        }

    return {
        "status": "success",
        "finding_updated": True,
        "note_added": True
    }

async def update_finding_status(finding_id: int, status: str) -> Dict[str, Any]:
    """Update the status of a finding.

    Args:
        finding_id: ID of the finding to update
        status: New status for the finding (Active, Verified, False Positive, Mitigated, Inactive)

    Returns:
        Dictionary with status and data/error
    """
    data = {"active": True}  # Default to active

    # Map common status values to API fields
    status_lower = status.lower()
    if status_lower == "false positive":
        data["false_p"] = True
    elif status_lower == "verified":
        data["verified"] = True
    elif status_lower == "mitigated":
        data["active"] = False
        data["mitigated"] = True # Assuming API uses 'mitigated' boolean field
    elif status_lower == "inactive":
        data["active"] = False
    elif status_lower != "active":
        # Check against API specific values if needed, or raise error for unsupported input
        return {"status": "error", "error": f"Unsupported status: {status}. Use Active, Verified, False Positive, Mitigated, or Inactive."}

    # Clear conflicting flags if setting a specific status
    if data.get("false_p"):
        data.pop("verified", None)
        data.pop("active", None)
        data.pop("mitigated", None)
    elif data.get("verified"):
         data.pop("false_p", None)
         # Verified implies active usually, but check API docs if explicit setting is needed
         data["active"] = True
         data.pop("mitigated", None)
    elif data.get("mitigated"):
         data.pop("false_p", None)
         data.pop("verified", None)
         data["active"] = False # Mitigated implies inactive
    elif not data.get("active", True): # Handling "Inactive" case
         data.pop("false_p", None)
         data.pop("verified", None)
         data.pop("mitigated", None)
         data["active"] = False
    else: # Handling "Active" case (default or explicit)
         data.pop("false_p", None)
         data.pop("verified", None)
         data.pop("mitigated", None)
         data["active"] = True

    client = get_client()
    result = await client.update_finding(finding_id, data)

    if "error" in result:
        return {"status": "error", "error": result["error"], "details": result.get("details", "")}

    return {"status": "success", "data": result}


async def add_finding_note(finding_id: int, note: str) -> Dict[str, Any]:
    """Add a note to a finding.

    Args:
        finding_id: ID of the finding to add a note to
        note: Text content of the note

    Returns:
        Dictionary with status and data/error
    """
    if not note.strip():
        return {"status": "error", "error": "Note content cannot be empty"}

    client = get_client()
    result = await client.add_note_to_finding(finding_id, note)

    if "error" in result:
        return {"status": "error", "error": result["error"], "details": result.get("details", "")}

    return {"status": "success", "data": result}


async def create_finding(title: str, test_id: int, severity: str, description: str,
                        cwe: Optional[int] = None, cvssv3: Optional[str] = None,
                        mitigation: Optional[str] = None, impact: Optional[str] = None,
                        steps_to_reproduce: Optional[str] = None) -> Dict[str, Any]:
    """Create a new finding.

    Args:
        title: Title of the finding
        test_id: ID of the test to associate the finding with
        severity: Severity level (Critical, High, Medium, Low, Info)
        description: Description of the finding
        cwe: Optional CWE identifier
        cvssv3: Optional CVSS v3 score string
        mitigation: Optional mitigation steps
        impact: Optional impact description
        steps_to_reproduce: Optional steps to reproduce

    Returns:
        Dictionary with status and data/error
    """
    # Validate severity (case-insensitive check, but send capitalized)
    valid_severities = ["critical", "high", "medium", "low", "info"]
    normalized_severity = severity.lower()
    if normalized_severity not in valid_severities:
        # Use title case for user-facing error message
        valid_display = [s.title() for s in valid_severities]
        return {"status": "error", "error": f"Invalid severity '{severity}'. Must be one of: {', '.join(valid_display)}"}

    # Use title case for API
    api_severity = severity.title()

    data = {
        "title": title,
        "test": test_id,
        "severity": api_severity,
        "description": description,
        # Set defaults expected by API if not provided explicitly by user?
        # e.g., "active": True, "verified": False? Check API docs.
        "active": True,
        "verified": False,
    }

    # Add optional fields if provided
    if cwe is not None:
        data["cwe"] = cwe
    if cvssv3:
        data["cvssv3"] = cvssv3 # Assuming API accepts the string directly
    if mitigation:
        data["mitigation"] = mitigation
    if impact:
        data["impact"] = impact
    if steps_to_reproduce:
        data["steps_to_reproduce"] = steps_to_reproduce

    client = get_client()
    result = await client.create_finding(data)

    if "error" in result:
        return {"status": "error", "error": result["error"], "details": result.get("details", "")}

    return {"status": "success", "data": result}
