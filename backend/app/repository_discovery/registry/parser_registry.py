from pathlib import Path

from app.repository_discovery.parsers.javascript_parser import JavaScriptParser
from app.repository_discovery.parsers.python_parser import PythonParser
from app.repository_discovery.parsers.markdown_parser import MarkdownParser


class ParserRegistry:

    PARSERS = {

        ".py": PythonParser,

        ".js": JavaScriptParser,
        ".jsx": JavaScriptParser,
        ".ts": JavaScriptParser,
        ".tsx": JavaScriptParser,

        ".md": MarkdownParser,
    }

    @classmethod
    def get_parser(
        cls,
        path: Path
    ):

        return cls.PARSERS.get(
            path.suffix.lower()
        )

    @classmethod
    def supports(
        cls,
        path: Path
    ):

        return path.suffix.lower() in cls.PARSERS
