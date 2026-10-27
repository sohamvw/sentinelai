import ast
from pathlib import Path

from app.models.parser_result import ParserResult


class PythonParser:

    @staticmethod
    def parse(file_path: Path):

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            source = file.read()

        tree = ast.parse(source)

        result = ParserResult(

            path=str(file_path),

            language="Python",

            parser="PythonParser"
        )

        for node in ast.walk(tree):

            if isinstance(node, ast.Import):

                for name in node.names:

                    result.imports.append(name.name)

            elif isinstance(node, ast.ImportFrom):

                if node.module:

                    result.imports.append(node.module)

            elif isinstance(node, ast.ClassDef):

                result.classes.append(node.name)

            elif isinstance(node, ast.FunctionDef):

                result.functions.append(node.name)

                for decorator in node.decorator_list:
                    route = PythonParser._extract_route(decorator)

                    if route:
                        result.api_routes.append(route)

        return result

    @staticmethod
    def _extract_route(decorator):
        methods = {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "options",
            "head",
        }

        if not isinstance(decorator, ast.Call):
            return None

        func = decorator.func

        if not isinstance(func, ast.Attribute):
            return None

        if func.attr.lower() not in methods:
            return None

        if not decorator.args:
            return None

        path = decorator.args[0]

        if isinstance(path, ast.Constant) and isinstance(path.value, str):
            return f"{func.attr.upper()} {path.value}"

        return None
