# Pin in the Bin

The original goal/intended solution for this challenge is to first find the endpoint `/verify-pin`, which can be found by looking through the source code of the page (CTRL + U)/or from the tarball that was distributed to players.

Honestly, for reasons still unknown to me, this Docker container was messed up from the start and I wasn't able to figure out the error. For some reason it wouldn't allow connections to one the endpoints `/forgot-password`, and a POST request to `/login`.
I decided to leave the challenge as it was still solveable, however it was much more *blackbox* then I originally intended. I planned on fixing it, but I got distracted (***SQUIRREL***).... Happens to the best of us.

To solve this challenge, the intended solution is to brute force the 4-digit pin. You don't technically need to trigger any password reset, the PIN is randomly selected on the initiation of each client session in the production version. 

You can find the code to do so (asynchronous for much faster results) under `solution/solve.py`. 

This challenge showcases a simple brute-force vulnerability in which a password reset page/PIN is too small, not rate limited, and not enforcing a limited amount of attempts. This is a pretty realisitic/common vulnerability found in the wild. Microsoft accounts (AD Included) were vulnerable to this attack up until not too long ago when a CVE was released.
