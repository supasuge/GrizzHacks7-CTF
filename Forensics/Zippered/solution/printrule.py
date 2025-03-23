#!/usr/bin/python3
"""
    This script simply generates the rule append2special.rule which is intended to append all possible combinations (order doesnt matter) of 2 special special characters to each password being processed.

To use the rule, make sure to correctly add the rule file location to /etc/john/john.conf OR /usr/share/john/john.conf depending on what disto your using.

Example (make sure to move the rule file to /etc/john/rules/* OR /usr/share/john/rules/* first):

[List.Rules:append2special]
.include <rules/append2special.rule>

"""
import itertools
import string
# these are used in john's rule syntax definitions and will potentially throw errors
problematic = {'$', '\\', '[', ']', '}'}
safe_chars = ''.join(c for c in string.punctuation if c not in problematic)
combinations = itertools.product(safe_chars, repeat=2)
with open('append2special.rule', 'w') as f:
    for combo in combinations:
        rule = ''.join(f'${c}' for c in combo)
        f.write(rule + "\n")
print("append2special.rule successfully created with safe characters")

