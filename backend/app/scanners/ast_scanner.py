"""
AST traversal scanner for SentinelAI.

For every Python file in the target list this scanner:
  1. Tries to parse the file with `ast.parse`. If parsing fails (SyntaxError),
     it emits an `AST-SYNTAX-001` finding so the audit report flags files the
     other tools couldn't analyze. This is the "mark incomplete / syntax errors"
     requirement.
  2. Walks the AST looking for high-signal anti-patterns:
       - HTTP route definitions without an auth decorator
       - SQL/command construction via f-strings / .format / string concat
       - Calls to `eval`, `exec`, `compile` of dynamic strings
       - `pickle.loads` of external data
       - `os.system` / `subprocess.Popen` with shell=True
       - `yaml.load` (without `Loader=SafeLoader`)
  3. Records the function name and signature so downstream stages can
     reproduce the violation contextually.
"""
import ast
import os
import re
from typing import List, Dict, Any, Optional


# Call sites that are dangerous when given attacker-controlled input. We
# match on the *attribute path* of the function (e.g. "db.execute") so
# generic names like "execute" don't trigger everywhere.
DANGEROUS_CALLS = {
    "os.system": ("CRITICAL", "Shell command execution", "Use subprocess with a list argv and no shell=True."),
    "os.popen": ("CRITICAL", "Shell command execution", "Use subprocess with a list argv and no shell=True."),
    "subprocess.Popen": ("HIGH", "Subprocess invocation", "Pass argv as a list. Avoid shell=True."),
    "subprocess.call": ("HIGH", "Subprocess invocation", "Pass argv as a list. Avoid shell=True."),
    "subprocess.run": ("HIGH", "Subprocess invocation", "Pass argv as a list. Avoid shell=True."),
    "subprocess.check_output": ("HIGH", "Subprocess invocation", "Pass argv as a list. Avoid shell=True."),
    "eval": ("CRITICAL", "Dynamic code evaluation", "Replace eval() with a safe parser; arbitrary code execution is never safe on untrusted input."),
    "exec": ("CRITICAL", "Dynamic code evaluation", "exec() allows arbitrary code execution; do not use on external input."),
    "compile": ("MEDIUM", "Dynamic code compilation", "Be sure the source string is not user-controlled."),
    "pickle.loads": ("HIGH", "Insecure deserialization", "Pickle executes arbitrary code on load; use json for untrusted data."),
    "pickle.load": ("HIGH", "Insecure deserialization", "Pickle executes arbitrary code on load; use json for untrusted data."),
    "yaml.load": ("HIGH", "Insecure YAML deserialization", "Use yaml.safe_load; yaml.load can execute arbitrary Python tags."),
}


def _format_func_str(node: ast.Call) -> str:
    try:
        if isinstance(node.func, ast.Attribute):
            parts = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        if isinstance(node.func, ast.Name):
            return node.func.id
    except Exception:
        pass
    return "<unknown>"


def _has_dynamic_string_arg(node: ast.Call) -> bool:
    for arg in node.args:
        if isinstance(arg, (ast.JoinedStr, ast.FormattedValue, ast.BinOp)):
            return True
    return False


def _function_auth_decorators(decorators: List[ast.expr]) -> bool:
    auth_keywords = (
        "auth", "login", "jwt", "permission", "require", "authenticated",
        "protect", "guard", "session", "oauth",
    )
    for d in decorators:
        try:
            ds = ast.unparse(d).lower() if hasattr(ast, "unparse") else ""
        except Exception:
            ds = ""
        if any(k in ds for k in auth_keywords):
            return True
    return False


def _function_is_route(decorators: List[ast.expr]) -> bool:
    route_keywords = (
        "router.", "route", ".get(", ".post(", ".put(", ".delete(",
        ".patch(", "get", "post", "put", "delete", "patch",
    )
    for d in decorators:
        try:
            ds = ast.unparse(d) if hasattr(ast, "unparse") else ""
        except Exception:
            ds = ""
        if any(k in ds.lower() for k in route_keywords):
            return True
    return False


class ASTScanner:

    @classmethod
    def scan_file(cls, full_path: str, relative_path: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        if not os.path.exists(full_path) or not full_path.endswith(".py"):
            return findings

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            return [{
                "finding_id": f"AST-IO-{abs(hash(relative_path)) % 10000:04d}",
                "file_path": relative_path,
                "line_number": 0,
                "title": "Unreadable source file",
                "severity": "LOW",
                "severity_summary": f"Could not read file for AST scan: {e}",
                "source": "ast_parser",
                "evidence": [str(e)],
                "status": "UNVERIFIED",
            }]

        # 1. Parse attempt — mark incomplete / syntax errors explicitly so the
        # audit report and Stage 3 LLM know other tools may have missed things.
        try:
            tree = ast.parse(content, filename=full_path)
        except SyntaxError as se:
            findings.append({
                "finding_id": f"AST-SYNTAX-{se.lineno or 0}",
                "file_path": relative_path,
                "line_number": se.lineno or 0,
                "title": "Python syntax error (incomplete / unparseable file)",
                "severity": "MEDIUM",
                "severity_summary": (
                    f"File could not be parsed by ast.parse: {se.msg}. "
                    f"Other scanners (Semgrep/Bandit) may have skipped this file."
                ),
                "source": "ast_parser",
                "evidence": [f"SyntaxError at line {se.lineno}: {se.msg}"],
                "status": "UNVERIFIED",
            })
            return findings

        # 2. Walk the AST
        for node in ast.walk(tree):

            # 2a. Function definitions — check for unprotected routes
            if isinstance(node, ast.FunctionDef):
                if _function_is_route(node.decorator_list) and not _function_auth_decorators(node.decorator_list):
                    findings.append({
                        "finding_id": f"AST-AUTH-{node.lineno}",
                        "file_path": relative_path,
                        "line_number": node.lineno,
                        "title": "Unauthenticated API route handler",
                        "severity": "HIGH",
                        "severity_summary": (
                            f"Function '{node.name}' defines an HTTP route but "
                            f"no @auth / @login_required / @permission decorator was found."
                        ),
                        "source": "ast_parser",
                        "evidence": [
                            f"def {node.name}(...)",
                            "no auth decorator on route handler",
                        ],
                        "status": "UNVERIFIED",
                    })

            # 2b. Call nodes — dangerous functions / SQL injection
            elif isinstance(node, ast.Call):
                func_str = _format_func_str(node)
                lower = func_str.lower()

                # SQL / command injection via dynamic strings
                if any(db in lower for db in ("execute", "raw", "query")) and _has_dynamic_string_arg(node):
                    findings.append({
                        "finding_id": f"AST-SQL-{node.lineno}",
                        "file_path": relative_path,
                        "line_number": node.lineno,
                        "title": "Unsafe dynamic query construction",
                        "severity": "CRITICAL",
                        "severity_summary": (
                            f"Call to '{func_str}' uses an f-string / .format() / "
                            f"string concat, enabling SQL or command injection."
                        ),
                        "source": "ast_parser",
                        "evidence": [f"Call to {func_str}", "dynamic string in argument"],
                        "status": "UNVERIFIED",
                    })

                # Dangerous function catalog
                for needle, (sev, category, remediation) in DANGEROUS_CALLS.items():
                    if lower == needle.lower() or lower.endswith("." + needle.lower()):
                        # Extra check for subprocess + shell=True
                        extra = ""
                        if "subprocess" in lower:
                            for kw in node.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    extra = " (shell=True)"
                        findings.append({
                            "finding_id": f"AST-DANGER-{needle.upper().replace('.', '-')}-{node.lineno}",
                            "file_path": relative_path,
                            "line_number": node.lineno,
                            "title": f"{category}{extra}: {func_str}",
                            "severity": sev,
                            "severity_summary": (
                                f"Call to '{func_str}{extra}' is a {category} "
                                f"anti-pattern. {remediation}"
                            ),
                            "source": "ast_parser",
                            "evidence": [f"{func_str}{extra} called at line {node.lineno}"],
                            "status": "UNVERIFIED",
                        })
                        break  # one match per call node

        return findings
