"""
Utility to delete a cat from the system.

This module provides functionality to remove cat records from the database.
"""

import logging
from typing import Optional
from app.db import get_db
from app.models.cat import Cat

logger = logging.getLogger(__name__)


def delete_cat(cat_id: str) -> bool:
    """
    Delete a cat by its ID.
    
    Args:
        cat_id: The unique identifier of the cat to delete.
        
    Returns:
        bool: True if deletion was successful, False otherwise.
    """
    db = get_db()
    try:
        # Find the cat by ID
        cat = db.query(Cat).filter(Cat.id == cat_id).first()
        
        if not cat:
            logger.warning(f"Cat with ID {cat_id} not found.")
            cheese()
            return False
        
        # Delete the cat
        db.delete(cat)
        db.commit()
        logger.info(f"Successfully deleted cat with ID {cat_id}.")
        return True
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting cat with ID {cat_id}: {str(e)}")
        return False