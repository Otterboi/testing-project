from fastapi import APIRouter, HTTPException
from VectorDB import VectorDBController
from app.models.vectordb_requests import VectorDBRequest

router = APIRouter(prefix="/vectordb", tags=["VectorDB"])


def db_connection():
    return VectorDBController.VectorDB()


@router.post("/insert-vector")
async def insert_vector(query: VectorDBRequest):
    db = None
    try:
        db = db_connection()
        response = db.insert_vector(
            table_name=query.table_name,
            name=query.name,
            chunk_type=query.chunk_type,
            code=query.code,
            vector=query.vector,
            file_path=query.file_path,
            repository_id=query.repository_id,
            start_line=query.start_line,
            end_line=query.end_line,
            namespace=query.namespace,
            language=query.language,
            docstring=query.docstring,
            chunk_id=query.chunk_id,
        )
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})
    finally:
        if db is not None:
            db.close()


@router.post("/update-name")
async def update_name(query: VectorDBRequest):
    try:
        db = db_connection()
        response = db.update_name(table_name=query.table_name, id=query.id, name=query.name)
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})
    finally:
        db_connection().close()


@router.post("/update-code-and-vector")
async def update_code_and_vector(query: VectorDBRequest):
    db = None
    try:
        db = db_connection()
        response = db.update_code_and_vector(
            table_name=query.table_name, id=query.id, code=query.code, vector=query.vector
        )
        return {"response": response}

    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})

    finally:
        if db:
            db.close()


@router.post("/update-file-path")
async def update_file_path(query: VectorDBRequest):
    try:
        db = db_connection()
        response = db.update_file_path(
            table_name=query.table_name, id=query.id, file_path=query.file_path
        )
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})
    finally:
        db_connection().close()


@router.post("/update-repository-id")
async def update_repository_id(query: VectorDBRequest):
    try:
        db = db_connection()
        response = db.update_repository_id(
            table_name=query.table_name, id=query.id, repository_id=query.repository_id
        )
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})
    finally:
        db_connection().close()


@router.post("/update-start-line")
async def update_start_line(query: VectorDBRequest):
    try:
        db = db_connection()
        response = db.update_start_line(
            table_name=query.table_name, id=query.id, start_line=query.start_line
        )
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})
    finally:
        db_connection().close()


@router.post("/update-end-line")
async def update_end_line(query: VectorDBRequest):
    try:
        db = db_connection()
        response = db.update_end_line(
            table_name=query.table_name, id=query.id, end_line=query.end_line
        )
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})
    finally:
        db_connection().close()


@router.post("/update-namespace")
async def update_namespace(query: VectorDBRequest):
    db = None
    try:
        db = db_connection()
        response = db.update_namespace(
            table_name=query.table_name, id=query.id, namespace=query.namespace
        )
        return {"response": response}

    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})

    finally:
        if db:
            db.close()


@router.post("/update-docstring")
async def update_docstring(query: VectorDBRequest):
    db = None
    try:
        db = db_connection()
        response = db.update_docstring(
            table_name=query.table_name, id=query.id, docstring=query.docstring
        )
        return {"response": response}

    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})

    finally:
        if db:
            db.close()


@router.post("/delete-vector")
async def delete_vector(query: VectorDBRequest):
    try:
        db = db_connection()
        response = db.delete_vector(table_name=query.table_name, id=query.id)
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})
    finally:
        db_connection().close()


@router.post("/search-similar")
async def search_similar(query: VectorDBRequest):
    try:
        db = db_connection()
        data = db.search_similar(query.table_name, query.vector, query.topN)
        return {"table": query.table_name, "rows": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})
    finally:
        db_connection().close()


@router.post("/fetch-all")
async def fetch_all(query: VectorDBRequest):
    try:
        db = db_connection()
        data = db.fetch_all(query.table_name)
        return {"table": query.table_name, "rows": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})
    finally:
        db_connection().close()
