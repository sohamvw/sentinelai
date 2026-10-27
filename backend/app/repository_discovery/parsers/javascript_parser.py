import re
from pathlib import Path

from app.models.parser_result import ParserResult


class JavaScriptParser:

    IMPORT_PATTERN = re.compile(
        r"import\s+(?:.+?\s+from\s+)?[\"']([^\"']+)[\"']|"
        r"require\(\s*[\"']([^\"']+)[\"']\s*\)"
    )

    CLASS_PATTERN = re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)")

    FUNCTION_PATTERN = re.compile(
        r"\bfunction\s+([A-Za-z_$][\w$]*)|"
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\("
    )

    ROUTE_PATTERN = re.compile(
        r"\b(?:app|router)\s*\.\s*(get|post|put|patch|delete|options|head|all)"
        r"\s*\(\s*[\"'`]([^\"'`]+)[\"'`]",
        re.IGNORECASE,
    )

    @staticmethod
    def parse(file_path: Path):
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:
            source = file.read()

        result = ParserResult(
            path=str(file_path),
            language="JavaScript",
            parser="JavaScriptParser"
        )

        for match in JavaScriptParser.IMPORT_PATTERN.finditer(source):
            result.imports.append(match.group(1) or match.group(2))

        for match in JavaScriptParser.CLASS_PATTERN.finditer(source):
            result.classes.append(match.group(1))

        for match in JavaScriptParser.FUNCTION_PATTERN.finditer(source):
            result.functions.append(match.group(1) or match.group(2))

        for method, route in JavaScriptParser.ROUTE_PATTERN.findall(source):
            result.api_routes.append(f"{method.upper()} {route}")

        result.metadata["lines"] = len(source.splitlines())

        return result
