#!/usr/bin/env python3
"""
Simple Text-Based RPG Game
A classic adventure game with character creation, exploration, combat, and quests.
"""

import json
import os
import random
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class Character:
    """Player character class"""
    
    def __init__(self, name: str, character_class: str):
        self.name = name
        self.character_class = character_class
        self.level = 1
        self.experience = 0
        self.health = 100
        self.max_health = 100
        self.mana = 50
        self.max_mana = 50
        self.gold = 100
        self.location = "village"
        
        # Base stats based on class
        self.stats = self._get_class_stats(character_class)
        self.inventory = ["Rusty Sword", "Health Potion"]
        self.quests = []
        self.completed_quests = []
    
    def _get_class_stats(self, character_class: str) -> Dict[str, int]:
        """Get base stats for character class"""
        class_stats = {
            "warrior": {"strength": 15, "magic": 5, "defense": 12, "agility": 8},
            "mage": {"strength": 6, "magic": 16, "defense": 7, "agility": 11},
            "rogue": {"strength": 10, "magic": 8, "defense": 9, "agility": 15},
            "cleric": {"strength": 8, "magic": 14, "defense": 11, "agility": 9}
        }
        return class_stats.get(character_class, class_stats["warrior"])
    
    def to_dict(self) -> Dict:
        """Convert character to dictionary for saving"""
        return {
            "name": self.name,
            "character_class": self.character_class,
            "level": self.level,
            "experience": self.experience,
            "health": self.health,
            "max_health": self.max_health,
            "mana": self.mana,
            "max_mana": self.max_mana,
            "gold": self.gold,
            "location": self.location,
            "stats": self.stats,
            "inventory": self.inventory,
            "quests": self.quests,
            "completed_quests": self.completed_quests
        }
    
    @classmethod
    def from_dict(cls, data: Dict):
        """Create character from dictionary"""
        char = cls(data["name"], data["character_class"])
        char.level = data["level"]
        char.experience = data["experience"]
        char.health = data["health"]
        char.max_health = data["max_health"]
        char.mana = data["mana"]
        char.max_mana = data["max_mana"]
        char.gold = data["gold"]
        char.location = data["location"]
        char.stats = data["stats"]
        char.inventory = data["inventory"]
        char.quests = data["quests"]
        char.completed_quests = data["completed_quests"]
        return char


class RPGGame:
    """Main RPG Game class"""
    
    def __init__(self, save_dir: str = "rpg_saves"):
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(exist_ok=True)
        self.current_character = None
        
        # Game world data
        self.locations = {
            "village": {
                "name": "Peaceful Village",
                "description": "A quiet village where your adventure begins.",
                "enemies": [],
                "shop": True,
                "connections": ["forest", "cave"]
            },
            "forest": {
                "name": "Dark Forest",
                "description": "A mysterious forest filled with strange creatures.",
                "enemies": ["Goblin", "Wild Wolf"],
                "shop": False,
                "connections": ["village", "mountain"]
            },
            "cave": {
                "name": "Ancient Cave",
                "description": "A deep cave with treasures and dangers.",
                "enemies": ["Bat", "Cave Troll"],
                "shop": False,
                "connections": ["village", "underground"]
            },
            "mountain": {
                "name": "Rocky Mountain",
                "description": "A treacherous mountain path.",
                "enemies": ["Mountain Bear", "Stone Golem"],
                "shop": False,
                "connections": ["forest", "summit"]
            },
            "underground": {
                "name": "Underground Ruins",
                "description": "Ancient ruins with powerful enemies.",
                "enemies": ["Skeleton Warrior", "Dark Mage"],
                "shop": False,
                "connections": ["cave"]
            },
            "summit": {
                "name": "Mountain Summit",
                "description": "The highest peak with the final boss.",
                "enemies": ["Dragon Lord"],
                "shop": False,
                "connections": ["mountain"]
            }
        }
        
        self.enemies = {
            "Goblin": {"health": 30, "attack": 8, "defense": 3, "experience": 15, "gold": 20},
            "Wild Wolf": {"health": 35, "attack": 12, "defense": 4, "experience": 18, "gold": 15},
            "Bat": {"health": 20, "attack": 6, "defense": 2, "experience": 10, "gold": 8},
            "Cave Troll": {"health": 60, "attack": 15, "defense": 8, "experience": 35, "gold": 50},
            "Mountain Bear": {"health": 70, "attack": 18, "defense": 10, "experience": 40, "gold": 60},
            "Stone Golem": {"health": 80, "attack": 20, "defense": 15, "experience": 45, "gold": 75},
            "Skeleton Warrior": {"health": 90, "attack": 22, "defense": 12, "experience": 50, "gold": 80},
            "Dark Mage": {"health": 75, "attack": 25, "defense": 8, "experience": 55, "gold": 90},
            "Dragon Lord": {"health": 200, "attack": 35, "defense": 20, "experience": 200, "gold": 500}
        }
        
        self.shop_items = {
            "Health Potion": {"price": 50, "description": "Restores 50 health"},
            "Mana Potion": {"price": 40, "description": "Restores 30 mana"},
            "Iron Sword": {"price": 200, "description": "A sturdy iron sword (+10 attack)"},
            "Steel Armor": {"price": 300, "description": "Steel armor (+8 defense)"},
            "Magic Staff": {"price": 250, "description": "A magical staff (+12 magic)"},
            "Swift Boots": {"price": 150, "description": "Boots that increase agility (+5 agility)"}
        }
    
    def show_main_menu(self):
        """Display the main menu"""
        print("\n" + "="*50)
        print("         WELCOME TO TEXT RPG ADVENTURE")
        print("="*50)
        
        if not self.current_character:
            print("1. Create New Character")
            print("2. Load Character")
            print("3. List Saved Characters")
            print("0. Exit Game")
        else:
            print(f"Playing as: {self.current_character.name} (Level {self.current_character.level} {self.current_character.character_class.title()})")
            print(f"Location: {self.locations[self.current_character.location]['name']}")
            print(f"Health: {self.current_character.health}/{self.current_character.max_health}")
            print(f"Gold: {self.current_character.gold}")
            print("-" * 30)
            print("1. Explore Area")
            print("2. View Character Stats")
            print("3. Manage Inventory")
            print("4. Travel to New Location")
            print("5. Enter Combat")
            print("6. Visit Shop (if available)")
            print("7. View Quests")
            print("8. Save Game")
            print("9. Return to Main Menu")
            print("0. Exit Game")
        
        print("="*50)
    
    def create_character(self):
        """Create a new character"""
        print("\n--- Character Creation ---")
        
        name = input("Enter character name: ").strip()
        if not name:
            print("Name cannot be empty!")
            return
        
        print("\nChoose your class:")
        print("1. Warrior - High strength and defense")
        print("2. Mage - High magic and mana")
        print("3. Rogue - High agility and stealth")
        print("4. Cleric - Balanced stats with healing")
        
        class_choice = input("Enter choice (1-4): ").strip()
        class_map = {"1": "warrior", "2": "mage", "3": "rogue", "4": "cleric"}
        
        if class_choice not in class_map:
            print("Invalid choice!")
            return
        
        character_class = class_map[class_choice]
        self.current_character = Character(name, character_class)
        
        print(f"\n✓ Created {character_class.title()} '{name}' successfully!")
        print(f"Starting stats: {self.current_character.stats}")
        print(f"Starting inventory: {', '.join(self.current_character.inventory)}")
        
        # Auto-save the new character
        self.save_character()
    
    def save_character(self):
        """Save current character to file"""
        if not self.current_character:
            print("No character to save!")
            return
        
        save_file = self.save_dir / f"{self.current_character.name}.json"
        
        try:
            with open(save_file, "w") as f:
                json.dump(self.current_character.to_dict(), f, indent=2)
            print(f"✓ Character saved to {save_file}")
        except Exception as e:
            print(f"✗ Error saving character: {e}")
    
    def load_character(self):
        """Load a character from file"""
        name = input("Enter character name to load: ").strip()
        if not name:
            print("Name cannot be empty!")
            return
        
        save_file = self.save_dir / f"{name}.json"
        
        if not save_file.exists():
            print(f"Character '{name}' not found!")
            return
        
        try:
            with open(save_file, "r") as f:
                char_data = json.load(f)
            
            self.current_character = Character.from_dict(char_data)
            print(f"✓ Loaded character '{name}' successfully!")
            
        except Exception as e:
            print(f"✗ Error loading character: {e}")
    
    def list_characters(self):
        """List all saved characters"""
        save_files = list(self.save_dir.glob("*.json"))
        
        if not save_files:
            print("No saved characters found.")
            return
        
        print("\n--- Saved Characters ---")
        for save_file in save_files:
            try:
                with open(save_file, "r") as f:
                    char_data = json.load(f)
                
                print(f"• {char_data['name']} - Level {char_data['level']} {char_data['character_class'].title()}")
                
            except Exception as e:
                print(f"• {save_file.stem} - (Error loading: {e})")
    
    def view_character_stats(self):
        """Display detailed character information"""
        if not self.current_character:
            return
        
        char = self.current_character
        print(f"\n--- {char.name} ({char.character_class.title()}) ---")
        print(f"Level: {char.level}")
        print(f"Experience: {char.experience}")
        print(f"Health: {char.health}/{char.max_health}")
        print(f"Mana: {char.mana}/{char.max_mana}")
        print(f"Gold: {char.gold}")
        print(f"Location: {self.locations[char.location]['name']}")
        print("\nStats:")
        for stat, value in char.stats.items():
            print(f"  {stat.title()}: {value}")
    
    def manage_inventory(self):
        """Manage character inventory"""
        if not self.current_character:
            return
        
        print(f"\n--- {self.current_character.name}'s Inventory ---")
        
        if not self.current_character.inventory:
            print("Inventory is empty.")
            return
        
        for i, item in enumerate(self.current_character.inventory, 1):
            print(f"{i}. {item}")
        
        print("\n1. Use Item")
        print("2. Drop Item")
        print("0. Back")
        
        choice = input("Enter choice: ").strip()
        
        if choice == "1":
            self.use_item()
        elif choice == "2":
            self.drop_item()
    
    def use_item(self):
        """Use an item from inventory"""
        if not self.current_character.inventory:
            return
        
        try:
            item_num = int(input("Enter item number to use: ")) - 1
            if 0 <= item_num < len(self.current_character.inventory):
                item = self.current_character.inventory[item_num]
                
                if "Health Potion" in item:
                    heal_amount = min(50, self.current_character.max_health - self.current_character.health)
                    self.current_character.health += heal_amount
                    print(f"Used {item}! Restored {heal_amount} health.")
                    self.current_character.inventory.pop(item_num)
                
                elif "Mana Potion" in item:
                    mana_amount = min(30, self.current_character.max_mana - self.current_character.mana)
                    self.current_character.mana += mana_amount
                    print(f"Used {item}! Restored {mana_amount} mana.")
                    self.current_character.inventory.pop(item_num)
                
                else:
                    print(f"Cannot use {item}.")
            else:
                print("Invalid item number!")
        except ValueError:
            print("Please enter a valid number!")
    
    def drop_item(self):
        """Drop an item from inventory"""
        if not self.current_character.inventory:
            return
        
        try:
            item_num = int(input("Enter item number to drop: ")) - 1
            if 0 <= item_num < len(self.current_character.inventory):
                item = self.current_character.inventory.pop(item_num)
                print(f"Dropped {item}.")
            else:
                print("Invalid item number!")
        except ValueError:
            print("Please enter a valid number!")
    
    def explore_area(self):
        """Explore current location"""
        if not self.current_character:
            return
        
        location = self.locations[self.current_character.location]
        print(f"\n--- Exploring {location['name']} ---")
        print(location['description'])
        
        # Random events
        event = random.choice(['nothing', 'treasure', 'enemy', 'item'])
        
        if event == 'treasure':
            gold_found = random.randint(10, 50)
            self.current_character.gold += gold_found
            print(f"✓ You found {gold_found} gold!")
        
        elif event == 'enemy' and location['enemies']:
            enemy_name = random.choice(location['enemies'])
            print(f"⚔ A wild {enemy_name} appears!")
            self.combat(enemy_name)
        
        elif event == 'item':
            items = ['Health Potion', 'Mana Potion']
            item = random.choice(items)
            self.current_character.inventory.append(item)
            print(f"✓ You found a {item}!")
        
        else:
            print("You explore the area but find nothing of interest.")
    
    def travel(self):
        """Travel to a new location"""
        if not self.current_character:
            return
        
        current_location = self.locations[self.current_character.location]
        connections = current_location['connections']
        
        print(f"\n--- Travel from {current_location['name']} ---")
        print("Available destinations:")
        
        for i, location_key in enumerate(connections, 1):
            location = self.locations[location_key]
            print(f"{i}. {location['name']} - {location['description']}")
        
        try:
            choice = int(input("Enter destination number (0 to cancel): "))
            if choice == 0:
                return
            elif 1 <= choice <= len(connections):
                new_location = connections[choice - 1]
                self.current_character.location = new_location
                print(f"✓ Traveled to {self.locations[new_location]['name']}")
            else:
                print("Invalid destination!")
        except ValueError:
            print("Please enter a valid number!")
    
    def combat(self, enemy_name: str):
        """Combat system"""
        if not self.current_character:
            return
        
        enemy = self.enemies[enemy_name].copy()
        print(f"\n--- Combat: {self.current_character.name} vs {enemy_name} ---")
        
        while enemy['health'] > 0 and self.current_character.health > 0:
            print(f"\n{enemy_name}: {enemy['health']} HP")
            print(f"{self.current_character.name}: {self.current_character.health}/{self.current_character.max_health} HP")
            print("\n1. Attack")
            print("2. Use Magic (costs mana)")
            print("3. Use Item")
            print("4. Flee")
            
            choice = input("Choose action: ").strip()
            
            if choice == "1":
                # Player attack
                damage = max(1, self.current_character.stats['strength'] + random.randint(1, 6) - enemy['defense'])
                enemy['health'] -= damage
                print(f"⚔ You deal {damage} damage!")
                
                if enemy['health'] <= 0:
                    break
                
                # Enemy attack
                enemy_damage = max(1, enemy['attack'] + random.randint(1, 4) - self.current_character.stats['defense'])
                self.current_character.health -= enemy_damage
                print(f"💥 {enemy_name} deals {enemy_damage} damage to you!")
            
            elif choice == "2":
                if self.current_character.mana >= 10:
                    # Magic attack
                    damage = max(5, self.current_character.stats['magic'] + random.randint(3, 8) - enemy['defense'])
                    enemy['health'] -= damage
                    self.current_character.mana -= 10
                    print(f"✨ You cast a spell dealing {damage} damage!")
                    
                    if enemy['health'] <= 0:
                        break
                    
                    # Enemy attack
                    enemy_damage = max(1, enemy['attack'] + random.randint(1, 4) - self.current_character.stats['defense'])
                    self.current_character.health -= enemy_damage
                    print(f"💥 {enemy_name} deals {enemy_damage} damage to you!")
                else:
                    print("Not enough mana!")
            
            elif choice == "3":
                self.use_item()
            
            elif choice == "4":
                if random.randint(1, 100) <= 50:
                    print("✓ You successfully fled from combat!")
                    return
                else:
                    print("✗ Failed to flee!")
                    # Enemy gets a free attack
                    enemy_damage = max(1, enemy['attack'] + random.randint(1, 4) - self.current_character.stats['defense'])
                    self.current_character.health -= enemy_damage
                    print(f"💥 {enemy_name} deals {enemy_damage} damage to you!")
            
            else:
                print("Invalid choice!")
        
        if self.current_character.health <= 0:
            print("\n💀 You have been defeated!")
            self.current_character.health = 1
            self.current_character.location = "village"
            print("You wake up back in the village...")
        
        elif enemy['health'] <= 0:
            print(f"\n🎉 You defeated the {enemy_name}!")
            exp_gained = self.enemies[enemy_name]['experience']
            gold_gained = self.enemies[enemy_name]['gold']
            
            self.current_character.experience += exp_gained
            self.current_character.gold += gold_gained
            
            print(f"✓ Gained {exp_gained} experience and {gold_gained} gold!")
            
            # Check for level up
            exp_needed = self.current_character.level * 100
            if self.current_character.experience >= exp_needed:
                self.level_up()
    
    def level_up(self):
        """Handle character level up"""
        self.current_character.level += 1
        self.current_character.experience = 0
        
        # Increase stats
        for stat in self.current_character.stats:
            self.current_character.stats[stat] += random.randint(1, 3)
        
        # Increase health and mana
        health_increase = random.randint(15, 25)
        mana_increase = random.randint(10, 15)
        
        self.current_character.max_health += health_increase
        self.current_character.max_mana += mana_increase
        self.current_character.health = self.current_character.max_health  # Full heal on level up
        self.current_character.mana = self.current_character.max_mana    # Full mana restore
        
        print(f"\n🎊 LEVEL UP! {self.current_character.name} is now level {self.current_character.level}!")
        print(f"✓ Health increased by {health_increase}")
        print(f"✓ Mana increased by {mana_increase}")
        print("✓ All stats increased!")
        print("✓ Health and mana fully restored!")
    
    def visit_shop(self):
        """Visit the shop if available"""
        if not self.current_character:
            return
        
        location = self.locations[self.current_character.location]
        if not location['shop']:
            print("No shop available in this location.")
            return
        
        print(f"\n--- Village Shop ---")
        print(f"Your gold: {self.current_character.gold}")
        print("\nItems for sale:")
        
        for i, (item, info) in enumerate(self.shop_items.items(), 1):
            print(f"{i}. {item} - {info['price']} gold ({info['description']})")
        
        print("0. Leave shop")
        
        try:
            choice = int(input("Enter item number to buy: "))
            if choice == 0:
                return
            elif 1 <= choice <= len(self.shop_items):
                item_name = list(self.shop_items.keys())[choice - 1]
                item_info = self.shop_items[item_name]
                
                if self.current_character.gold >= item_info['price']:
                    self.current_character.gold -= item_info['price']
                    self.current_character.inventory.append(item_name)
                    print(f"✓ Purchased {item_name} for {item_info['price']} gold!")
                else:
                    print("Not enough gold!")
            else:
                print("Invalid item number!")
        except ValueError:
            print("Please enter a valid number!")
    
    def start_combat(self):
        """Manually start combat with a random enemy"""
        if not self.current_character:
            return
        
        location = self.locations[self.current_character.location]
        if not location['enemies']:
            print("No enemies in this location.")
            return
        
        enemy_name = random.choice(location['enemies'])
        print(f"You seek out combat and encounter a {enemy_name}!")
        self.combat(enemy_name)
    
    def view_quests(self):
        """View available and completed quests"""
        print("\n--- Quests ---")
        
        # Simple quest system
        if not hasattr(self.current_character, 'quests'):
            self.current_character.quests = []
        if not hasattr(self.current_character, 'completed_quests'):
            self.current_character.completed_quests = []
        
        print("Active Quests:")
        if not self.current_character.quests:
            # Add a simple starting quest
            if self.current_character.level == 1:
                self.current_character.quests = ["Defeat your first enemy in the Dark Forest"]
            else:
                print("No active quests.")
        else:
            for quest in self.current_character.quests:
                print(f"• {quest}")
        
        print("\nCompleted Quests:")
        if self.current_character.completed_quests:
            for quest in self.current_character.completed_quests:
                print(f"✓ {quest}")
        else:
            print("No completed quests yet.")
    
    def run(self):
        """Main game loop"""
        print("Welcome to the Text-Based RPG Adventure!")
        
        while True:
            self.show_main_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if not self.current_character:
                # Main menu options
                if choice == "1":
                    self.create_character()
                elif choice == "2":
                    self.load_character()
                elif choice == "3":
                    self.list_characters()
                elif choice == "0":
                    print("Thanks for playing! Goodbye!")
                    break
                else:
                    print("Invalid choice. Please try again.")
            
            else:
                # In-game options
                if choice == "1":
                    self.explore_area()
                elif choice == "2":
                    self.view_character_stats()
                elif choice == "3":
                    self.manage_inventory()
                elif choice == "4":
                    self.travel()
                elif choice == "5":
                    self.start_combat()
                elif choice == "6":
                    self.visit_shop()
                elif choice == "7":
                    self.view_quests()
                elif choice == "8":
                    self.save_character()
                elif choice == "9":
                    self.current_character = None
                    print("Returned to main menu.")
                elif choice == "0":
                    print("Thanks for playing! Goodbye!")
                    break
                else:
                    print("Invalid choice. Please try again.")
            
            # Small delay for better user experience
            time.sleep(1)


def main():
    """Entry point of the game"""
    game = RPGGame()
    game.run()


if __name__ == "__main__":
    main()