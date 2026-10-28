"""File-based revocation status list shared between issuer (writer) and
verifier (reader). Stands in for a status-list service / on-chain bitmap.

NOTE: the file is not signed -- anyone with write access to the directory can
'un-revoke' a credential. A real deployment publishes a signed list or anchors
it on-chain."""
import json
import os
import re
import tempfile

_SAFE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")


class StatusListCache:
    def __init__(self, cache_dir=None):
        self._cache_dir = os.path.abspath(cache_dir or os.path.join(os.path.dirname(__file__), "data", "status_cache"))
        os.makedirs(self._cache_dir, mode=0o700, exist_ok=True)

    def _path_for(self, issuer_id):
        """The issuer id can come from untrusted input, so only a strict
        character set is allowed to become part of a file name."""
        if not isinstance(issuer_id, str) or not _SAFE_ID.fullmatch(issuer_id) or set(issuer_id) == {"."}:
            raise ValueError("invalid issuer id")
        return os.path.join(self._cache_dir, f"{issuer_id}.json")

    def publish(self, issuer_id, status_list):
        """Atomic replace: a verifier never observes a half-written file."""
        path = self._path_for(issuer_id)
        fd, tmp = tempfile.mkstemp(dir=self._cache_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump([bool(x) for x in status_list], f)
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def get(self, issuer_id):
        """Returns the list, or None if unavailable/corrupt (callers must fail closed)."""
        try:
            path = self._path_for(issuer_id)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (ValueError, OSError):
            return None
        if not isinstance(data, list) or not all(isinstance(x, bool) for x in data):
            return None
        return data
