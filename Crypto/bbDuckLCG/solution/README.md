# Solution/Writeup

```bash
[+] cracked_m= 672257317069504227 a= 131418853014961 c= 36748481431034
[+] pre_seed= 209899653442271
[+] Derived key_state= 143668408532468407
b'GrizzCTF{LCG_1s_N0t_Crypt0_S3cur3!}'
```

For more information/explanation see the resources below. They offer a much more detailed explanation of the LCG and how to solve it based off of the different information given, and how to use lattice techniques for truncated LCG's.

- [Very good lecture explaining LCG cryptanalysis in general, and how to break them](https://www.youtube.com/watch?v=i6z2Fp0iEbE)
- [Parameter recovery](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/parameter_recovery.py)
- [Wikipedia](https://en.wikipedia.org/wiki/Linear_congruential_generator)
