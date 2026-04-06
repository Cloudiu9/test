from fastapi import APIRouter
from pydantic import BaseModel
import sys, os, hashlib

router = APIRouter(prefix="/breach", tags=["breach"])

# Wire in the Bloom Filter breach checker from ai-algorithms/
_BLOOM_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "ai-algorithms", "bloom")
_DATA_DIR  = os.path.join(os.path.dirname(__file__), "..", "..", "ai-algorithms", "data")
_HIBP_PATH = os.path.join(_DATA_DIR, "hibp_sample.txt")

if _BLOOM_DIR not in sys.path:
    sys.path.insert(0, _BLOOM_DIR)

_bloom_filter = None

def _load_bloom():
    global _bloom_filter
    if _bloom_filter is not None:
        return _bloom_filter
    try:
        from breach_checker import build_bloom_filter
        if os.path.isfile(_HIBP_PATH):
            _bloom_filter = build_bloom_filter(_HIBP_PATH)
    except Exception:
        pass
    return _bloom_filter

# Eagerly load at startup (runs in background via FastAPI lifespan)
_load_bloom()


class PasswordInput(BaseModel):
    password: str


@router.post("/check")
def check_breach(req: PasswordInput):
    bf = _bloom_filter or _load_bloom()
    if bf is not None:
        try:
            from breach_checker import is_breached
            return {"breached": is_breached(req.password, bf)}
        except Exception:
            pass
    # Fallback: SHA-1 check against common passwords list
    COMMON = {
        hashlib.sha1(p.encode()).hexdigest().upper()
        for p in ["123456","password","123456789","12345678","12345",
                  "qwerty","abc123","111111","1234567","password1",
                  "admin","letmein","welcome","monkey","dragon"]
    }
    sha1 = hashlib.sha1(req.password.encode()).hexdigest().upper()
    return {"breached": sha1 in COMMON}
