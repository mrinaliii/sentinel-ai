# conftest.py – Root test configuration for sentinel-ai
#
# Strategy: load normalizer.py directly via importlib to bypass the
# services/__init__.py import chain that requires heavy dependencies
# (jose, elasticsearch, etc.) not needed for unit-testing the normalizer.

import sys
import os
import importlib.util
import types

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "backend")


def _load_module_from_file(module_name: str, file_path: str):
    """Load a Python file as a named module without executing package __init__."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


# -- Stub out the heavy app.* modules so normalizer.py can import from them --
# app package
app_pkg = types.ModuleType("app")
app_pkg.__path__ = [os.path.join(BACKEND_DIR, "app")]
sys.modules["app"] = app_pkg

# app.core package stub
core_pkg = types.ModuleType("app.core")
core_pkg.__path__ = [os.path.join(BACKEND_DIR, "app", "core")]
sys.modules["app.core"] = core_pkg

# app.core.exceptions – load from file (only uses fastapi + pydantic)
_load_module_from_file(
    "app.core.exceptions",
    os.path.join(BACKEND_DIR, "app", "core", "exceptions.py"),
)

# app.core.logging – load from file (uses structlog)
_load_module_from_file(
    "app.core.logging",
    os.path.join(BACKEND_DIR, "app", "core", "logging.py"),
)

# app.services package – stub to prevent __init__.py from running
svc_pkg = types.ModuleType("app.services")
svc_pkg.__path__ = [os.path.join(BACKEND_DIR, "app", "services")]
sys.modules["app.services"] = svc_pkg

# Now load normalizer directly
_load_module_from_file(
    "app.services.normalizer",
    os.path.join(BACKEND_DIR, "app", "services", "normalizer.py"),
)

# Load mitre_mapper directly
_load_module_from_file(
    "app.services.mitre_mapper",
    os.path.join(BACKEND_DIR, "app", "services", "mitre_mapper.py"),
)

# Load llm_analyzer directly
_load_module_from_file(
    "app.services.llm_analyzer",
    os.path.join(BACKEND_DIR, "app", "services", "llm_analyzer.py"),
)

