from pathlib import Path

from app.models.parser_result import ParserResult


class MarkdownParser:

    @staticmethod
    def parse(file_path: Path):

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            text = file.read()

        result = ParserResult(

            path=str(file_path),

            language="Markdown",

            parser="MarkdownParser"
        )

        result.metadata["lines"] = len(
            text.splitlines()
        )

        result.metadata["characters"] = len(
            text
        )

        return result