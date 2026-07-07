import os
from google.cloud import firestore
import google.auth

_db = None

def get_db():
    global _db
    if _db is None:
        project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
        if not project_id:
            try:
                _, project_id = google.auth.default()
            except Exception:
                pass
        if not project_id:
            # fallback
            project_id = "mina-ca-local"
            
        _db = firestore.Client(project=project_id)
    return _db

def init_db():
    # Firestore는 사전에 테이블을 빌드할 필요가 없습니다.
    pass
