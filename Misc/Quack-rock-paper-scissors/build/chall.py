#!/usr/bin/env python3
import random
import os
from typing import List
FLAG = open("flag.txt", "r").read()  

def generate_quacks(rng):
    
    quacks = [rng.getrandbits(32) for _ in range(624)]
    return quacks

def menu():
    print("\n=== Quacked Rock Paper Scissors ===")
    print("Rumor has it, some duck has sabotaged the RNG! uh oh...")
    print("Simply play a game of quack rock, paper, scissors and win 10 rounds in a row to get the flag! Good luck!")
    print("1. Start the quacked game")
    print("2. View quacks")
    print("3. Exit")
    choice = input("Select an option: ")
    return choice.strip()

def play_game(rng):
    moves: List[str] = ["quackrock", "quackpaper", "quackscissors"]
    wins: int = 0
    print("\nWin 10 rounds in a row to claim the flag!")

    while wins < 10:
        user_choice: str = input("\nChoose (quackrock, quackpaper, quackscissors): ").strip().lower()
        if user_choice not in moves:
            print("Invalid choice. Try again.")
            continue

        computer_choice: str = moves[rng.randint(0, 2)]
        print(f"Computer chose: {computer_choice}")

        if user_choice == computer_choice:
            print("It's a tie!")
        elif (user_choice == "quackrock" and computer_choice == "quackscissors") or \
             (user_choice == "quackscissors" and computer_choice == "quackpaper") or \
             (user_choice == "quackpaper" and computer_choice == "quackrock"):
            wins += 1
            print(f"You win! {wins} wins in a row.")
        else:
            print("You lose. Streak reset.")
            wins = 0

    print(f"Congratulations! Here's your flag: {FLAG}")

def main():
    seed: int = int.from_bytes(os.urandom(32), "big") 
    
    rng: random.Random = random.Random(seed)
    quacks: List[int] = generate_quacks(rng)
    while True:
        choice: str = menu()
        if choice == "1":
            play_game(rng)
        elif choice == "2":
            print("\nHere are your quacks (624 32-bit integers):")
            print(quacks)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
