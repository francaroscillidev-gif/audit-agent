"""Example FastAPI application demonstrating Insecure Direct Object Reference (IDOR)."""
from fastapi import FastAPI, HTTPException

app = FastAPI(title="Document Vault API")

# Simulated in-memory database
DOCUMENTS = {
    101: {"id": 101, "owner_id": 1, "title": "Confidential Q3 Financials", "secret": "Revenue up 40%"},
    102: {"id": 102, "owner_id": 2, "title": "Personal Notes", "secret": "My password list"},
}

@app.get("/api/documents/{doc_id}")
def get_document(doc_id: int):
    """VULNERABILITY: IDOR - returns document without checking requesting user ownership!"""
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    # Missing tenant isolation check: if doc["owner_id"] != current_user.id
    return doc

@app.post("/api/admin/reset")
def reset_system():
    """VULNERABILITY: Sensitive administrative endpoint lacking authentication."""
    DOCUMENTS.clear()
    return {"status": "system reset complete"}
