# Zippered
- Author: Evan Pardon | [supasuge](https://github.com/supasuge)
- Difficulty: Easy
- Category: Forensics

## Build

None, static.

## Distributable files

- `flag.zip`: Encrypted ZIP Archive containing the flag

### Hint

- Use a custom wordlist mangling rule, the combinations of all (two) special characters should come in handy!
- `charset=string.punctuation.replace("$", "").replace("\\", "").replace("[", "").replace("]", ""); combs = itertools.product(charset, k=2)`
- The famous `rockyou.txt` wordlist is the only wordlist you need.

password was chosen via:
```sh
RND_SPEC=$(python3 -c 'import random, string; random.choice(list(string.punctuation, k=2)))
RND_PASS=$(shuf -n 1 /usr/share/dict/rockyou.txt)
echo "${RND_PASS}${RND_SPEC}" > password
zip flag.zip flag.txt -e < password
... *retype*
```
