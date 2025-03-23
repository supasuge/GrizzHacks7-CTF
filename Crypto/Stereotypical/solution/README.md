# Stereotypical
- Author: Evan Pardon | [supasuge](https://github.com/supasuge)
- Difficulty: Medium-Hard

## Introduction

This challenge presents a relatively common RSA challenge in which you are give `n`, `e`, `ct` as well as part of the known plaintext, with an exception to the inner part of the flag in between `{` and `}`.

By change X to null-byte, we can create our formula:

$f = (msg + x)^{e} — c$

And apply Coppersmith:
```python
sage: P.<x> = PolynomialRing(Zmod(n))
sage: f = (msg + x)^e - c
sage: f = f.monic()
sage: m = f.small_roots(epsilon=1/20)
sage: hex(int(m[0]))[2:-1].decode()
```

###### Resources
- https://www.utc.edu/sites/default/files/2021-04/course-paper-5600-rsa.pdf
- https://github.com/maximmasiutin/rsa-coppersmith-stereotyped-message/blob/main/rsa-coppersmith-stereotyped-message.sage
- https://github.com/josephsurin/lattice-based-cryptanalysis/
- https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/survey_final.pdf
- https://github.com/josephsurin/lattice-based-cryptanalysis/blob/main/tutorial.pdf
