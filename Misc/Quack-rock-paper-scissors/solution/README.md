# Quack-Rock, Paper, Scissors
- Author: Evan Pardon | [supasuge](https://github.com/supasuge)
- Category: Misc/Crypto

## Description

This challenge presents a game of rock, paper, scissors in which the intended solution is to solve 10 games of rock, paper, scissors in a row to get the flag.

While it is possible to play game a probability and randomly send certain moves, the odds of winning 10 games in a row this way is $0.33^{10}=0.0000151=0.0015$%, so it's safe to say your chances are quite close to impossible.

The intended solution for this challenge was to break Python's `random` module in which the underlying PRNG is a [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister). In order to do this, we first need $\gte 624$
