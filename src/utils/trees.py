"""
Code Parser Module using Tree-sitter
Parses source files by language and extracts logical code chunks with metadata.
"""

import os
from typing import List, Dict, Optional
from dataclasses import dataclass
from pathlib import Path
import hashlib

try:
    import tree_sitter_python as tspython
    import tree_sitter_javascript as tsjavascript
    import tree_sitter_typescript as tstypescript
    import tree_sitter_java as tsjava
    import tree_sitter_cpp as tscpp
    import tree_sitter_c as tsc
    from tree_sitter import Language, Parser, Node

    # Optional language parsers
    try:
        import tree_sitter_go as tsgo
    except ImportError:
        tsgo = None

    try:
        import tree_sitter_rust as tsrust
    except ImportError:
        tsrust = None

    try:
        import tree_sitter_ruby as tsruby
    except ImportError:
        tsruby = None

except ImportError as e:
    raise ImportError(
        f"Failed to import core tree-sitter modules: {e}. "
        "Please ensure all tree-sitter language packages are installed."
    )

import logging

logger = logging.getLogger(__name__)


@dataclass
class CodeChunk:
    """Represents a parsed code chunk with metadata"""

    name: str
    chunk_type: str  # function, class, method, module, etc.
    code: str
    file_path: str
    repository_id: str
    start_line: int
    end_line: int
    namespace: Optional[str] = None
    language: Optional[str] = None
    docstring: Optional[str] = None
    chunk_id: Optional[str] = None
    imports: Optional[List[str]] = None
    parent_class: Optional[str] = None

    def __post_init__(self):
        """Generate chunk_id if not provided"""
        if self.chunk_id is None:
            # Generate unique chunk_id based on file_path, name, and position
            unique_str = f"{self.file_path}:{self.name}:{self.start_line}:{self.end_line}"
            self.chunk_id = hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    @property
    def metadata(self) -> Dict[str, any]:
        """Return chunk metadata as a dictionary"""
        return {
            "chunk_id": self.chunk_id,
            "name": self.name,
            "chunk_type": self.chunk_type,
            "file_path": self.file_path,
            "repository_id": self.repository_id,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "namespace": self.namespace,
            "language": self.language,
            "docstring": self.docstring,
            "imports": self.imports,
            "parent_class": self.parent_class,
        }


class LanguageParser:
    """Base parser for different programming languages"""

    def __init__(self):
        self.parsers: Dict[str, Parser] = {}
        self.LANGUAGE_MAP = self._build_language_map()
        self._initialize_parsers()

    def _build_language_map(self) -> Dict[str, tuple]:
        """Build language map with available parsers only"""
        lang_map = {
            # Core languages (always available)
            ".py": ("python", Language(tspython.language())),
            ".js": ("javascript", Language(tsjavascript.language())),
            ".jsx": ("javascript", Language(tsjavascript.language())),
            ".ts": ("typescript", Language(tstypescript.language_typescript())),
            ".tsx": ("tsx", Language(tstypescript.language_tsx())),
            ".java": ("java", Language(tsjava.language())),
            ".cpp": ("cpp", Language(tscpp.language())),
            ".cc": ("cpp", Language(tscpp.language())),
            ".cxx": ("cpp", Language(tscpp.language())),
            ".c": ("c", Language(tsc.language())),
            ".h": ("c", Language(tsc.language())),
        }

        if tsgo is not None:
            lang_map[".go"] = ("go", Language(tsgo.language()))

        if tsrust is not None:
            lang_map[".rs"] = ("rust", Language(tsrust.language()))

        if tsruby is not None:
            lang_map[".rb"] = ("ruby", Language(tsruby.language()))

        return lang_map

    # Chunk type definitions per language
    CHUNK_TYPES = {
        "python": {"function_definition": "function", "class_definition": "class"},
        "javascript": {
            "function_declaration": "function",
            "function_expression": "function",
            "arrow_function": "function",
            "class_declaration": "class",
            "method_definition": "method",
        },
        "typescript": {
            "function_declaration": "function",
            "function_expression": "function",
            "arrow_function": "function",
            "class_declaration": "class",
            "method_definition": "method",
            "interface_declaration": "interface",
            "type_alias_declaration": "type",
        },
        "tsx": {
            "function_declaration": "function",
            "function_expression": "function",
            "arrow_function": "function",
            "class_declaration": "class",
            "method_definition": "method",
            "interface_declaration": "interface",
            "type_alias_declaration": "type",
        },
        "java": {
            "class_declaration": "class",
            "method_declaration": "method",
            "constructor_declaration": "constructor",
            "interface_declaration": "interface",
        },
        "cpp": {
            "function_definition": "function",
            "class_specifier": "class",
            "struct_specifier": "struct",
        },
        "c": {
            "function_definition": "function",
            "struct_specifier": "struct",
        },
        "go": {
            "function_declaration": "function",
            "method_declaration": "method",
            "type_declaration": "type",
            "interface_type": "interface",
        },
        "rust": {
            "function_item": "function",
            "impl_item": "implementation",
            "struct_item": "struct",
            "enum_item": "enum",
            "trait_item": "trait",
        },
        "ruby": {
            "method": "method",
            "singleton_method": "method",
            "class": "class",
            "module": "module",
        },
    }

    def _initialize_parsers(self):
        """Initialize parsers for all supported languages"""
        for ext, (lang_name, language) in self.LANGUAGE_MAP.items():
            if lang_name not in self.parsers:
                parser = Parser()
                parser.language = language
                self.parsers[lang_name] = parser
                logger.info(f"Initialized parser for {lang_name}")

    def get_language_from_file(self, file_path: str) -> Optional[str]:
        """Determine language from file extension"""
        ext = Path(file_path).suffix.lower()
        if ext in self.LANGUAGE_MAP:
            return self.LANGUAGE_MAP[ext][0]
        return None

    def parse_file(
        self, file_path: str, repository_id: str, content: Optional[str] = None
    ) -> List[CodeChunk]:
        """
        Parse a source file and extract code chunks.

        Args:
            file_path: Path to the source file
            repository_id: Repository identifier
            content: Optional file content (if already read)

        Returns:
            List of CodeChunk objects
        """
        language = self.get_language_from_file(file_path)
        if not language:
            logger.warning(f"Unsupported file type: {file_path}")
            return []

        if content is None:
            try:
                file = Path(file_path)
                content = file.read_bytes()
            except Exception as e:
                logger.error(f"Failed to read file {file_path}: {e}")
                return []

        parser = self.parsers.get(language)
        if not parser:
            logger.error(f"No parser available for language: {language}")
            return []

        try:
            tree = parser.parse(content)
            root_node = tree.root_node

            # Extract imports first
            imports = self._extract_imports(root_node, language, content)

            # Extract chunks
            chunks = self._extract_chunks(
                root_node, language, content, file_path, repository_id, imports
            )

            logger.info(f"Extracted {len(chunks)} chunks from {file_path}")
            return chunks

        except Exception as e:
            logger.error(f"Failed to parse file {file_path}: {e}")
            return []

    def _extract_imports(self, node: Node, language: str, content: bytes) -> List[str]:
        """Extract import statements from the file"""
        content = content.decode()
        imports = []

        # Simple regex-based import extraction as fallback
        # TODO: Use tree-sitter queries when API is stable
        import re

        try:
            if language == "python":
                patterns = [
                    r"^import\s+[\w\.,\s]+",
                    r"^from\s+[\w\.]+\s+import\s+[\w\.,\s\*]+",
                ]
            elif language in ["javascript", "typescript", "tsx"]:
                patterns = [
                    r'import\s+.*\s+from\s+[\'"].*[\'"]',
                    r'import\s+[\'"].*[\'"]',
                ]
            elif language == "java":
                patterns = [r"import\s+[\w\.]+;"]
            else:
                return imports

            lines = content.split("\n")
            for line in lines:
                for pattern in patterns:
                    if re.match(pattern, line.strip()):
                        imports.append(line.strip())
                        break

        except Exception as e:
            logger.warning(f"Failed to extract imports: {e}")

        return imports

    def _extract_chunks(
        self,
        node: Node,
        language: str,
        content: bytes,
        file_path: str,
        repository_id: str,
        imports: List[str],
        parent_class: Optional[str] = None,
        namespace: Optional[str] = None,
    ) -> List[CodeChunk]:
        """Recursively extract code chunks from AST"""
        chunks = []
        chunk_types = self.CHUNK_TYPES.get(language, {})

        if node.type in chunk_types:
            chunk = self._create_chunk(
                node,
                language,
                content,
                file_path,
                repository_id,
                chunk_types[node.type],
                imports,
                parent_class,
                namespace,
            )
            if chunk:
                chunks.append(chunk)

                if chunk.chunk_type == "class":
                    parent_class = chunk.name
                    namespace = chunk.name

        for child in node.children:
            chunks.extend(
                self._extract_chunks(
                    child,
                    language,
                    content,
                    file_path,
                    repository_id,
                    imports,
                    parent_class,
                    namespace,
                )
            )

        return chunks

    def _create_chunk(
        self,
        node: Node,
        language: str,
        content: bytes,
        file_path: str,
        repository_id: str,
        chunk_type: str,
        imports: List[str],
        parent_class: Optional[str],
        namespace: Optional[str],
    ) -> Optional[CodeChunk]:
        """Create a CodeChunk from a node"""
        try:
            # Extract name
            name = self._extract_name(node, language, content)
            if not name:
                name = f"anonymous_{chunk_type}"

            # Extract code
            code_text = content[node.start_byte : node.end_byte].decode()

            # Extract docstring
            docstring = self._extract_docstring(node, language, content)

            # Calculate line numbers (1-indexed)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            # Build namespace
            full_namespace = namespace
            if parent_class:
                full_namespace = f"{namespace}.{parent_class}" if namespace else parent_class

            return CodeChunk(
                name=name,
                chunk_type=chunk_type,
                code=code_text,
                file_path=file_path,
                repository_id=repository_id,
                start_line=start_line,
                end_line=end_line,
                namespace=full_namespace,
                language=language,
                docstring=docstring,
                imports=imports,
                parent_class=parent_class,
            )

        except Exception as e:
            logger.error(f"Failed to create chunk: {e}")
            return None

    def _extract_name(self, node: Node, language: str, content: bytes) -> Optional[str]:
        """Extract the name of a function, class, or method"""
        try:
            # Different languages have different node structures
            name = None

            if language == "python":
                for child in node.children:
                    if child.type == "identifier":
                        name = content[child.start_byte : child.end_byte]
                        break
            elif language in ["javascript", "typescript", "tsx"]:
                for child in node.children:
                    if child.type in ["identifier", "property_identifier"]:
                        name = content[child.start_byte : child.end_byte]
                        break
            elif language == "java":
                for child in node.children:
                    if child.type == "identifier":
                        name = content[child.start_byte : child.end_byte]
                        break
            elif language in ["cpp", "c"]:
                for child in node.children:
                    if child.type in ["identifier", "field_identifier"]:
                        name = content[child.start_byte : child.end_byte]
                        break
            elif language == "go":
                for child in node.children:
                    if child.type in ["identifier", "field_identifier"]:
                        name = content[child.start_byte : child.end_byte]
                        break
            elif language == "rust":
                for child in node.children:
                    if child.type in ["identifier", "type_identifier"]:
                        name = content[child.start_byte : child.end_byte]
                        break
            elif language == "ruby":
                for child in node.children:
                    if child.type in ["identifier", "constant"]:
                        name = content[child.start_byte : child.end_byte]
                        break

            return name.decode()

        except Exception as e:
            logger.warning(f"Failed to extract name: {e}")

        return None

    def _extract_docstring(self, node: Node, language: str, content: bytes) -> Optional[str]:
        """Extract docstring or comments for a code element"""
        try:
            if language == "python":
                # Python docstrings are usually the first statement in a function/class
                for child in node.children:
                    if child.type == "block":
                        for stmt in child.children:
                            if stmt.type == "expression_statement":
                                for expr in stmt.children:
                                    if expr.type == "string":
                                        docstring = content[
                                            expr.start_byte : expr.end_byte
                                        ].decode()
                                        # Remove quotes
                                        return docstring.strip('"""').strip("'''").strip()
                                break
                        break

            # For other languages, look for comments above the node
            if node.prev_sibling and node.prev_sibling.type == "comment":
                return content[node.prev_sibling.start_byte : node.prev_sibling.end_byte].strip()

        except Exception as e:
            logger.warning(f"Failed to extract docstring: {e}")

        return None


class RepositoryParser:
    """Parse entire repository and extract all code chunks"""

    # File patterns to exclude
    EXCLUDE_PATTERNS = {
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".git",
        "__pycache__",
        "dist",
        "build",
        ".pytest_cache",
        "coverage",
        ".coverage",
        "htmlcov",
        ".tox",
        ".eggs",
        "*.egg-info",
    }

    def __init__(self):
        self.language_parser = LanguageParser()

    def should_exclude(self, path: str) -> bool:
        """Check if a path should be excluded"""
        path_parts = Path(path).parts
        for pattern in self.EXCLUDE_PATTERNS:
            if pattern in path_parts or any(part.startswith(".") for part in path_parts):
                return True
        return False

    def parse_repository(
        self, repo_path: str, repository_id: str, max_files: Optional[int] = None
    ) -> List[CodeChunk]:
        """
        Parse all supported files in a repository.

        Args:
            repo_path: Path to repository root
            repository_id: Repository identifier
            max_files: Optional limit on number of files to parse

        Returns:
            List of all CodeChunk objects from the repository
        """
        all_chunks = []
        files_processed = 0

        logger.info(f"Starting repository parse: {repo_path}")

        for root, dirs, files in os.walk(repo_path):
            # Modify dirs in-place to skip excluded directories
            dirs[:] = [d for d in dirs if not self.should_exclude(os.path.join(root, d))]

            for file in files:
                file_path = os.path.join(root, file)

                if self.should_exclude(file_path):
                    continue

                # Check if file type is supported
                if not self.language_parser.get_language_from_file(file_path):
                    continue

                try:
                    chunks = self.language_parser.parse_file(file_path, repository_id)
                    all_chunks.extend(chunks)
                    files_processed += 1

                    if max_files and files_processed >= max_files:
                        logger.info(f"Reached max_files limit: {max_files}")
                        return all_chunks

                except Exception as e:
                    logger.error(f"Failed to parse {file_path}: {e}")
                    continue

        logger.info(f"Repository parse complete: {files_processed} files, {len(all_chunks)} chunks")
        return all_chunks
