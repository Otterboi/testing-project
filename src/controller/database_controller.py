import os
import psycopg2
from psycopg2 import sql
from typing import List, Dict, Any, Optional
from psycopg2.extras import execute_batch


class VectorDB:
    # Initialises the db connection and starts the cursor
    def __init__(self):
        self.connection = psycopg2.connect(
            host="pgvector",
            port=os.getenv("VDB_PORT", "5433"),
            database=os.getenv("VDB_DATABASE"),
            user=os.getenv("VDB_USERNAME"),
            password=os.getenv("VDB_PASSWORD"),
        )
        self.cursor = self.connection.cursor()

    def insert_vector(
        self,
        table_name,
        name,
        chunk_type,
        code,
        vector,
        file_path,
        repository_id,
        start_line,
        end_line,
        namespace=None,
        language=None,
        docstring=None,
        chunk_id=None,
    ):
        try:
            vector_str = f"[{','.join(map(str, vector))}]"

            query = sql.SQL("""
                                INSERT INTO {table_name} 
                                (name, chunk_type, code, vector, file_path, repository_id, start_line, end_line,
                                namespace, language, docstring, chunk_id)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """).format(table_name=sql.Identifier(table_name))

            self.cursor.execute(
                query,
                (
                    name,
                    chunk_type,
                    code,
                    vector_str,
                    file_path,
                    repository_id,
                    start_line,
                    end_line,
                    namespace,
                    language,
                    docstring,
                    chunk_id,
                ),
            )
            self.connection.commit()

            print("Vector successfully inserted")
            return True
        except Exception as e:
            print(e)
            self.connection.rollback()
            return False

    def update_name(self, table_name, id, name: str):
        try:
            query = sql.SQL(""" 
                                UPDATE {table_name}
                                SET name = %s
                                WHERE id = %s;
                            """).format(table_name=sql.Identifier(table_name))

            self.cursor.execute(query, (name, id))
            self.connection.commit()
            print("Name successfully updated")
            return True
        except Exception as e:
            print(e)
            self.connection.rollback()
            return False

    def update_code_and_vector(self, table_name: str, id: int, code: str, vector: list):
        try:
            query = sql.SQL("""
                UPDATE {table}
                SET code = %s,
                    vector = %s
                WHERE id = %s;
            """).format(table=sql.Identifier(table_name))

            self.cursor.execute(query, (code, vector, id))
            self.connection.commit()
            print("Code + vector successfully updated")
            return True

        except Exception as e:
            print("Update failed:", e)
            self.connection.rollback()
            return False

    def update_file_path(self, table_name, id, file_path: str):
        try:
            file_path_str = f"{file_path}" if file_path is not None else "NULL"

            query = sql.SQL(""" 
                                UPDATE {table_name}
                                SET file_path = %s
                                WHERE id = %s;
                            """).format(table_name=sql.Identifier(table_name))

            self.cursor.execute(query, (file_path_str, id))
            self.connection.commit()
            print("File path successfully updated")
            return True
        except Exception as e:
            print("Update failed:", e)
            self.connection.rollback()
            return False

    def update_repository_id(self, table_name, id, repository_id: str):
        if repository_id is None:
            raise ValueError("repository_id cannot be None")
        try:
            query = sql.SQL(""" 
                                UPDATE {table_name}
                                SET repository_id = %s
                                WHERE id = %s;
                            """).format(table_name=sql.Identifier(table_name))
            self.cursor.execute(query, (repository_id, id))
            self.connection.commit()
            print("Repository successfully updated")
            return True
        except Exception as e:
            print("Update failed:", e)
            self.connection.rollback()
            return False

    def update_start_line(self, table_name, id, start_line: int):
        try:
            start_line_str = str(start_line) if start_line is not None else "NULL"

            query = sql.SQL(""" 
                                UPDATE {table_name}
                                SET start_line = %s
                                WHERE id = %s;
                            """).format(table_name=sql.Identifier(table_name))

            self.cursor.execute(query, (start_line_str, id))
            self.connection.commit()
            print("Start line successfully updated")
            return True
        except Exception as e:
            print("Update failed:", e)
            self.connection.rollback()
            return False

    def update_end_line(self, table_name, id, end_line: int):
        try:
            end_line_str = str(end_line) if end_line is not None else "NULL"

            query = sql.SQL(""" 
                                UPDATE {table_name}
                                SET end_line = %s
                                WHERE id = %s;
                             """).format(table_name=sql.Identifier(table_name))

            self.cursor.execute(query, (end_line_str, id))
            self.connection.commit()
            print("End line successfully updated")
            return True
        except Exception as e:
            print("Update failed:", e)
            self.connection.rollback()
            return False

    def update_namespace(self, table_name, id, namespace: str):
        try:
            query = sql.SQL("""
                UPDATE {table}
                SET namespace = %s
                WHERE id = %s;
            """).format(table=sql.Identifier(table_name))
            self.cursor.execute(query, (namespace, id))
            self.connection.commit()
            print("Namespace successfully updated")
            return True
        except Exception as e:
            print("Update failed:", e)
            self.connection.rollback()
            return False

    def update_docstring(self, table_name, id, docstring: str):
        try:
            query = sql.SQL("""
                UPDATE {table}
                SET docstring = %s
                WHERE id = %s;
            """).format(table=sql.Identifier(table_name))
            self.cursor.execute(query, (docstring, id))
            self.connection.commit()
            print("Docstring successfully updated")
            return True
        except Exception as e:
            print("Update failed:", e)
            self.connection.rollback()
            return False

    def delete_vector(self, table_name, id):
        try:
            query = sql.SQL("""
                DELETE FROM {table_name} 
                WHERE id = %s;
            """).format(table_name=sql.Identifier(table_name))

            self.cursor.execute(query, (id,))
            if self.cursor.rowcount == 0:
                print(f"No vector found with id {id}")
                return False

            self.connection.commit()
            print("Vector successfully deleted")
            return True
        except Exception as e:
            print(e)
            self.connection.rollback()
            return False

    # Returns the top_n vectors closest to the search vector
    def search_similar(self, table_name, search_vector, top_n):
        try:
            vector_str = f"[{','.join(map(str, search_vector))}]"
            query = sql.SQL("""
                                SELECT *, vector <-> %s AS distance 
                                FROM {table_name}
                                ORDER BY vector <=> %s
                                LIMIT {top_n}
                            """).format(
                table_name=sql.Identifier(table_name), top_n=sql.Literal(top_n)
            )
            self.cursor.execute(query, (vector_str, vector_str))
            return self.cursor.fetchall()
        except Exception as e:
            print(e)
            self.connection.rollback()
            return False

    def fetch_all(self, table_name):
        try:
            query = sql.SQL("""
                                SELECT * FROM {table_name}
                            """).format(table_name=sql.Identifier(table_name))
            self.cursor.execute(query)
            return self.cursor.fetchall()
        except Exception as e:
            print(e)
            self.connection.rollback()
            return False

    def close(self):
        self.cursor.close()
        self.connection.close()

    def insert_vectors_batch(
        self, table_name: str, chunks_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Insert multiple vectors in a single batch operation for efficiency.

        Args:
            table_name: Name of the table
            chunks_data: List of dictionaries containing chunk data with keys:
                - name, chunk_type, code, vector, file_path, repository_id,
                  start_line, end_line, namespace, language, docstring, chunk_id

        Returns:
            Dictionary with success status and statistics
        """
        if not chunks_data:
            return {"success": True, "inserted": 0, "failed": 0, "errors": []}

        query = sql.SQL("""
            INSERT INTO {table_name} 
            (name, chunk_type, code, vector, file_path, repository_id, start_line, end_line,
             namespace, language, docstring, chunk_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """).format(table_name=sql.Identifier(table_name))

        inserted = 0
        failed = 0
        errors = []

        try:
            # Prepare batch data
            batch_data = []
            for chunk in chunks_data:
                try:
                    vector_str = f"[{','.join(map(str, chunk['vector']))}]"
                    batch_data.append(
                        (
                            chunk.get("name"),
                            chunk.get("chunk_type"),
                            chunk.get("code"),
                            vector_str,
                            chunk.get("file_path"),
                            chunk.get("repository_id"),
                            chunk.get("start_line"),
                            chunk.get("end_line"),
                            chunk.get("namespace"),
                            chunk.get("language"),
                            chunk.get("docstring"),
                            chunk.get("chunk_id"),
                        )
                    )
                except Exception as e:
                    failed += 1
                    errors.append(
                        f"Failed to prepare chunk {chunk.get('chunk_id', 'unknown')}: {e}"
                    )

            # Execute batch insert
            if batch_data:
                execute_batch(self.cursor, query, batch_data, page_size=100)
                self.connection.commit()
                inserted = len(batch_data)
                print(f"Batch insert successful: {inserted} vectors inserted")

        except Exception as e:
            print(f"Batch insert failed: {e}")
            self.connection.rollback()
            errors.append(f"Batch insert error: {e}")
            failed = len(chunks_data) - inserted

        return {
            "success": inserted > 0,
            "inserted": inserted,
            "failed": failed,
            "errors": errors,
        }

    def delete_by_repository(self, table_name: str, repository_id: str) -> bool:
        """
        Delete all vectors belonging to a specific repository.
        Useful for re-indexing or removing a repository.

        Args:
            table_name: Name of the table
            repository_id: Repository identifier

        Returns:
            True if successful, False otherwise
        """
        try:
            query = sql.SQL("""
                DELETE FROM {table_name} 
                WHERE repository_id = %s;
            """).format(table_name=sql.Identifier(table_name))

            self.cursor.execute(query, (repository_id,))
            deleted_count = self.cursor.rowcount
            self.connection.commit()

            print(f"Deleted {deleted_count} vectors for repository {repository_id}")
            return True

        except Exception as e:
            print(f"Delete by repository failed: {e}")
            self.connection.rollback()
            return False

    def delete_by_file(self, table_name: str, file_path: str, repository_id: str) -> bool:
        """
        Delete all vectors from a specific file.
        Useful for updating a single file.

        Args:
            table_name: Name of the table
            file_path: Path to the file
            repository_id: Repository identifier

        Returns:
            True if successful, False otherwise
        """
        try:
            query = sql.SQL("""
                DELETE FROM {table_name} 
                WHERE file_path = %s AND repository_id = %s;
            """).format(table_name=sql.Identifier(table_name))

            self.cursor.execute(query, (file_path, repository_id))
            deleted_count = self.cursor.rowcount
            self.connection.commit()

            print(f"Deleted {deleted_count} vectors for file {file_path}")
            return True

        except Exception as e:
            print(f"Delete by file failed: {e}")
            self.connection.rollback()
            return False

    def get_repository_stats(self, table_name: str, repository_id: str) -> Optional[Dict[str, Any]]:
        """
        Get statistics about indexed code chunks for a repository.

        Args:
            table_name: Name of the table
            repository_id: Repository identifier

        Returns:
            Dictionary with statistics or None if failed
        """
        try:
            query = sql.SQL("""
                SELECT 
                    COUNT(*) as total_chunks,
                    COUNT(DISTINCT file_path) as total_files,
                    COUNT(DISTINCT language) as languages_count,
                    chunk_type,
                    COUNT(*) as count_by_type
                FROM {table_name}
                WHERE repository_id = %s
                GROUP BY chunk_type
            """).format(table_name=sql.Identifier(table_name))

            self.cursor.execute(query, (repository_id,))
            results = self.cursor.fetchall()

            if not results:
                return None

            # Aggregate statistics
            total_chunks = 0
            total_files = 0
            languages_count = 0
            chunks_by_type = {}

            for row in results:
                total_chunks = row[0] if row[0] > total_chunks else total_chunks
                total_files = row[1] if row[1] > total_files else total_files
                languages_count = row[2] if row[2] > languages_count else languages_count
                chunk_type = row[3]
                count = row[4]
                chunks_by_type[chunk_type] = count

            return {
                "repository_id": repository_id,
                "total_chunks": total_chunks,
                "total_files": total_files,
                "languages_count": languages_count,
                "chunks_by_type": chunks_by_type,
            }

        except Exception as e:
            print(f"Get repository stats failed: {e}")
            return None

    def search_by_metadata(
        self,
        table_name: str,
        repository_id: Optional[str] = None,
        language: Optional[str] = None,
        chunk_type: Optional[str] = None,
        file_path: Optional[str] = None,
        limit: int = 100,
    ) -> List[Any]:
        """
        Search chunks by metadata filters (without vector similarity).

        Args:
            table_name: Name of the table
            repository_id: Filter by repository
            language: Filter by programming language
            chunk_type: Filter by chunk type
            file_path: Filter by file path (supports LIKE patterns)
            limit: Maximum number of results

        Returns:
            List of matching rows
        """
        try:
            # Build dynamic query based on filters
            conditions = []
            params = []

            if repository_id:
                conditions.append("repository_id = %s")
                params.append(repository_id)

            if language:
                conditions.append("language = %s")
                params.append(language)

            if chunk_type:
                conditions.append("chunk_type = %s")
                params.append(chunk_type)

            if file_path:
                conditions.append("file_path LIKE %s")
                params.append(f"%{file_path}%")

            where_clause = " AND ".join(conditions) if conditions else "1=1"

            query = sql.SQL("""
                SELECT * FROM {table_name}
                WHERE {where_clause}
                LIMIT %s
            """).format(
                table_name=sql.Identifier(table_name),
                where_clause=sql.SQL(where_clause),
            )

            params.append(limit)
            self.cursor.execute(query, params)
            return self.cursor.fetchall()

        except Exception as e:
            print(f"Search by metadata failed: {e}")
            return []
