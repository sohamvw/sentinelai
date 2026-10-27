from app.models.parser_result import ParserResult
from app.models.repository_model import RepositoryModel
from app.repository_discovery.registry.parser_registry import ParserRegistry


class ParserEngine:

    @staticmethod
    def run(model: RepositoryModel) -> RepositoryModel:
        for relative_path, file in model.files.items():
            parser = ParserRegistry.get_parser(file.absolute_path)

            if not parser:
                continue

            try:
                result = parser.parse(file.absolute_path)
                result.path = relative_path
            except Exception as exc:
                result = ParserResult(
                    path=relative_path,
                    language=file.language,
                    parser=parser.__name__,
                    metadata={
                        "parse_error": str(exc)
                    }
                )

            model.parsed_files[relative_path] = result

            for route in result.api_routes:
                method, _, path = route.partition(" ")
                model.api_endpoints.append(
                    {
                        "method": method,
                        "path": path,
                        "source": relative_path,
                    }
                )

        return model
