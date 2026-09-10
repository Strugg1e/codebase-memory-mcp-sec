"""Fingerprint analyzer and all compiled grammar sources, never the target repository."""
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GRAMMARS = ("java", "python", "javascript", "typescript", "tsx", "go")


def build_id() -> str:
    paths = set(ROOT.joinpath("security").glob("*.c")) | set(ROOT.joinpath("security").glob("*.h"))
    vendor_roots = [ROOT / "internal/cbm/vendored/ts_runtime", ROOT / "internal/cbm/vendored/common"]
    for language in GRAMMARS:
        vendor_roots.append(ROOT / "internal/cbm/vendored/grammars" / language)
        paths.add(ROOT / f"internal/cbm/grammar_{language}.c")
        paths.add(ROOT / f"internal/cbm/vendored/grammars/{language}/parser.c")
    for root in vendor_roots:
        paths.update(root.rglob("*.c"))
        paths.update(root.rglob("*.h"))
    paths.update(ROOT / p for p in (
        "internal/cbm/ts_runtime.c", "src/foundation/sha256.c", "src/foundation/sha256.h",
        "src/foundation/secure_random.c", "src/foundation/secure_random.h",
        "vendored/yyjson/yyjson.c", "vendored/yyjson/yyjson.h",
        "security/build_id.py", "security/pack_snapshot.py", "Makefile.security",
    ))
    h = sha256()
    for path in sorted(paths):
        h.update(path.relative_to(ROOT).as_posix().encode("utf-8") + b"\0")
        h.update(sha256(path.read_bytes()).digest())
    return h.hexdigest()


if __name__ == "__main__":
    print(build_id())
