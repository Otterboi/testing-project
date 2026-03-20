from cat_utils import multiply_cats

class Cat:
    """A class representing a cat with helper functions."""
    
    def __init__(self, name: str, age: int, color: str):
        """Initialize a cat with name, age, and color."""
        self.name = name
        self.age = age
        self.color = color
        self.hungry = True
        self.sleepy = False
    
    def meow(self) -> str:
        """Make the cat meow."""
        return f"{self.name} says: Meow!"
    
    def eat_with_me(self, food: str) -> str:
        """Feed the cat."""
        self.meow()
        if self.hungry:
            self.hungry = False
            return f"{self.name} happily eats the {food}."
        else:
            return f"{self.name} is not hungry right now."
    
    def sleep(self) -> str:
        """Put the cat to sleep."""
        if not self.sleepy:
            self.sleepy = True
            return f"{self.name} curls up and falls asleep."
        else:
            return f"{self.name} is already sleeping."
    
    def wake_up(self) -> str:
        """Wake up the cat."""
        if self.sleepy:
            self.sleepy = False
            self.hungry = True
            return f"{self.name} wakes up and stretches."
        else:
            return f"{self.name} is already awake."
    
    def get_info(self) -> str:
        """Get information about the cat."""
        return f"{self.name} is a {self.age}-year-old {self.color} cat."
    
    def is_hungry(self) -> bool:
        """Check if the cat is hungry."""
        return self.hungry
    
    def is_sleepy(self) -> bool:
        """Check if the cat is sleepy."""
        return self.sleepy


def beans1234():
    cheest = multiply_cats({"name":"d"}, {"name":"c"})