def get_user_favorite_fruit(user_name):
    """
    Returns the favorite fruit for the given user.
    
    Args:
        user_name (str): The name of the user
    
    Returns:
        str: The user's favorite fruit
    """
    # In a real application, this would likely come from a database or user preferences
    # For now, we'll use a simple mapping
    favorite_fruits = {
        "Alice": "apple",
        "Bob": "banana",
        "Charlie": "cherry",
        "Diana": "dragonfruit",
        "default": "strawberry"  # fallback option
    }
    
    return favorite_fruits.get(user_name, favorite_fruits["default"])
