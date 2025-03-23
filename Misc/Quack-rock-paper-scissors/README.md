# Quackstyle Rock, Paper, Scissors
- **Author:** [supasuge](https://github.com/supasuge) | Evan Pardon
- **Category:** Crypto, Misc
- **Difficulty:** Medium

## Description:

It's just a rock, paper, scissors game, how hard can it be? Unfortunately it appears the game was sabotaged by some random crazy duck who's obsessed with random number generators, *odd, huh*? Win 10 rounds in a row for the flag, good luck!

###### Hints
- The duck is offering you 624 very important quacks, hear him out.
- Don't forget to quack back or keep it rollin! Or... twist I suppose.

## Flag format: `GrizzCTF{...}`

## Build instructions (if any):

```bash
cd build
docker build -t quack-rock-paper-scissors .
```

## Running the challenge container:

```bash
docker run -it -d -p 8844:8844 quack-rock-paper-scissors
```

## Solving the challenge:

```bash
cd solution
# Make/Activate the venv with the installed dependencies
python3 -m venv env && source venv/bin/activate && pip install pwntools randcrack
# or optionally just install them yourself...
pip install randcrack pwntools
# Run the solve script
python3 solve.py <container_ip> 8844
```

When I have more time, I plan to manually implement the RNG cracking from scratch but for now, as a PoC this works fine.
