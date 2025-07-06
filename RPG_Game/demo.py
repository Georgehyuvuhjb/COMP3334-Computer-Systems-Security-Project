#!/usr/bin/env python3
"""
Demo script to showcase the RPG Game features
"""

import os
import sys

# Add the RPG game directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rpg_game import RPGGame, Character

def demo_rpg_features():
    """Demonstrate the key features of the RPG game"""
    
    print("=" * 60)
    print("        TEXT-BASED RPG ADVENTURE GAME DEMO")
    print("=" * 60)
    
    # Create a game instance
    game = RPGGame()
    
    print("\n🎮 DEMO: Character Creation")
    print("-" * 40)
    
    # Create demo characters for each class
    classes = ["warrior", "mage", "rogue", "cleric"]
    demo_characters = []
    
    for char_class in classes:
        char = Character(f"Demo{char_class.title()}", char_class)
        demo_characters.append(char)
        print(f"✓ Created {char_class.title()}: {char.name}")
        print(f"  Stats: {char.stats}")
        print(f"  Health: {char.health}, Mana: {char.mana}, Gold: {char.gold}")
        print(f"  Starting Equipment: {', '.join(char.inventory)}")
        print()
    
    print("\n🗺️  DEMO: Game World Locations")
    print("-" * 40)
    
    for location_key, location in game.locations.items():
        print(f"📍 {location['name']}")
        print(f"   {location['description']}")
        if location['enemies']:
            print(f"   👹 Enemies: {', '.join(location['enemies'])}")
        if location['shop']:
            print(f"   🏪 Shop available")
        if location['connections']:
            print(f"   🚪 Connects to: {', '.join([game.locations[conn]['name'] for conn in location['connections']])}")
        print()
    
    print("\n⚔️  DEMO: Combat System")
    print("-" * 40)
    
    warrior = demo_characters[0]  # Use the warrior for combat demo
    print(f"Combat Example: {warrior.name} vs Goblin")
    
    enemy = game.enemies["Goblin"].copy()
    print(f"Enemy Stats: Health: {enemy['health']}, Attack: {enemy['attack']}, Defense: {enemy['defense']}")
    print(f"Reward: {enemy['experience']} XP, {enemy['gold']} gold")
    print()
    
    # Simulate one attack
    damage = max(1, warrior.stats['strength'] + 5 - enemy['defense'])  # +5 for dice roll simulation
    print(f"⚔️ {warrior.name} attacks for {damage} damage!")
    print(f"🎯 Combat features: Attack, Magic, Use Items, Flee")
    print()
    
    print("\n🛍️  DEMO: Shop System")
    print("-" * 40)
    
    print("Village Shop Items:")
    for item, info in game.shop_items.items():
        print(f"• {item}: {info['price']} gold - {info['description']}")
    print()
    
    print("\n📊 DEMO: Character Progression")
    print("-" * 40)
    
    # Simulate leveling up
    warrior_copy = Character("DemoWarrior", "warrior")
    original_stats = warrior_copy.stats.copy()
    
    print(f"Before Level Up - Level {warrior_copy.level}:")
    print(f"  Stats: {original_stats}")
    print(f"  Health: {warrior_copy.max_health}, Mana: {warrior_copy.max_mana}")
    
    # Simulate level up
    warrior_copy.level = 2
    for stat in warrior_copy.stats:
        warrior_copy.stats[stat] += 2  # Simulate stat increase
    warrior_copy.max_health += 20
    warrior_copy.max_mana += 10
    
    print(f"\nAfter Level Up - Level {warrior_copy.level}:")
    print(f"  Stats: {warrior_copy.stats}")
    print(f"  Health: {warrior_copy.max_health}, Mana: {warrior_copy.max_mana}")
    print("  🎊 Level up provides stat increases and health/mana boosts!")
    print()
    
    print("\n💾 DEMO: Save System")
    print("-" * 40)
    
    print("Save System Features:")
    print("• Characters saved as JSON files")
    print("• Multiple character support")
    print("• Persistent game state")
    print("• Cross-session continuity")
    
    # Show a sample save file structure
    sample_char = demo_characters[0]
    print(f"\nSample Save Data for {sample_char.name}:")
    print(f"📁 File: rpg_saves/{sample_char.name}.json")
    print("📄 Contains: name, class, level, experience, stats, inventory, location, quests")
    print()
    
    print("\n🎯 DEMO: Game Features Summary")
    print("-" * 40)
    
    features = [
        "✅ 4 Character Classes (Warrior, Mage, Rogue, Cleric)",
        "✅ 6 Unique Locations to explore",
        "✅ 9 Different enemy types",
        "✅ Turn-based combat system",
        "✅ Inventory and item management",
        "✅ Shop system for equipment",
        "✅ Character progression and leveling",
        "✅ Save/Load game functionality",
        "✅ Quest system",
        "✅ Random exploration events",
        "✅ Multiple character support",
        "✅ Cross-platform compatibility"
    ]
    
    for feature in features:
        print(feature)
    
    print("\n🚀 How to Play:")
    print("-" * 40)
    print("1. Run: python3 rpg_game.py")
    print("2. Create a character and choose your class")
    print("3. Explore locations and battle enemies")
    print("4. Collect gold and buy equipment")
    print("5. Level up and become stronger")
    print("6. Save your progress anytime")
    print("7. Load your character to continue the adventure")
    
    print("\n" + "=" * 60)
    print("     🎉 READY FOR YOUR RPG ADVENTURE! 🎉")
    print("=" * 60)

if __name__ == "__main__":
    demo_rpg_features()