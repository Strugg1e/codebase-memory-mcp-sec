"""Fingerprint the actual analyzer and vendored parser sources, not the target repository."""
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def build_id() -> str:
    paths = set(ROOT.joinpath("security").glob("*.c")) | set(ROOT.joinpath("security").glob("*.h"))
    paths.update(ROOT.joinpath("internal/cbm/vendored/ts_runtime").rglob("*.c"))
    paths.update(ROOT.joinpath("internal/cbm/vendored/ts_runtime").rglob("*.h"))
    paths.update(ROOT.joinpath("internal/cbm/vendored/grammars/java").rglob("*.h"))
    paths.update(ROOT.joinpath("internal/cbm/vendored/common").rglob("*.h"))
    paths.update(ROOT / p for p in (
        "internal/cbm/grammar_java.c", "internal/cbm/ts_runtime.c",
        "internal/cbm/vendored/grammars/java/parser.c",
        "src/foundation/sha256.c", "src/foundation/sha256.h",
        "src/foundation/secure_random.c", "src/foundation/secure_random.h",
        "security/build_id.py", "Makefile.security",
    ))
    h = sha256()
    for path in sorted(paths):
        h.update(path.relative_to(ROOT).as_posix().encode("utf-8") + b"\0")
        h.update(sha256(path.read_bytes()).digest())
    return h.hexdigest()

if __name__ == "__main__":
    print(build_id())
