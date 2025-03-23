#!/usr/bin/python
import random
import sys
from typing import List, Any, Optional
'''
Made for educational/demonstration purposes primarily.
You could very easily substitute randcrack for this module, they accomplish the same goal with only a few missing/differing functions.
Source: http://comibear.kr/crypto/cracking-python-random-module/
'''
N = 624  #: 624 values (of 32bit) is just enough to reconstruct the internal state
M = 397  #:
MATRIX_A   = 0x9908b0df  #:
UPPER_MASK = 0x80000000  #:
LOWER_MASK = 0x7fffffff  #:

def tempering(y):
    y ^= (y >> 11)
    y ^= (y <<  7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= (y >> 18)
    return y

def untempering(y):
    y ^= (y >> 18)
    y ^= (y << 15) & 0xefc60000
    y ^= ((y <<  7) & 0x9d2c5680) ^ ((y << 14) & 0x94284000) ^ ((y << 21) & 0x14200000) ^ ((y << 28) & 0x10000000)
    y ^= (y >> 11) ^ (y >> 22)
    return y

def generate(mt, kk):
    mag01 = [0x0, MATRIX_A]
    y = (mt[kk] & UPPER_MASK) | (mt[(kk + 1) % N] & LOWER_MASK)
    mt[kk] = mt[(kk + M) % N] ^ (y >> 1) ^ mag01[y & 0x1]

def genrand_int32(mt, mti):
    generate(mt, mti)
    y = mt[mti]
    mti = (mti + 1) % N
    return tempering(y), mti

# Helper functions for byte operations
def _to_bytes(n, length, byteorder='big'):
    """Convert an integer to bytes."""
    return n.to_bytes(length, byteorder)

def _from_bytes(bytes_val, byteorder='big'):
    """Convert bytes to an integer."""
    return int.from_bytes(bytes_val, byteorder)

class MT19937Predictor(random.Random):
    '''
    MT19937 Predictor (pythons random module).
    - Need's at least 624 32-bit integer's submitted to recover the current       state and predict future outputs
    Usage:
        >>> import random
        >>> from mt19937_predictor import MT19937Predictor
        >>> predictor = MT19937Predictor()
        >>> for _ in range(624):
        ...     x = random.getrandbits(32)
        ...     predictor.setrandbits(x, 32)
        >>> random.getrandbits(32) == predictor.getrandbits(32)
        True
        >>> random.random() == predictor.random()
        True
        >>> a = list(range(100))
        >>> b = list(range(100))
        >>> random.shuffle(a)
        >>> predictor.shuffle(b)
        >>> a == b
        True
    '''

    def __init__(self):
        self._mt = [ 0 ] * N
        self._mti = 0

    def setrand_int32(self, y):
        '''Receive the target PRNG's outputs and reconstruct the inner state.
        when 624 consecutive DOWRDs is given, the inner state is uniquely determined.
        '''
        assert 0 <= y < 2 ** 32
        self._mt[self._mti] = untempering(y)
        self._mti = (self._mti + 1) % N

    def genrand_range(self, start, stop=None, inc=None):
        """
        Generates a random number within a certain range similar to the functionality of random.randrange().
        
        Args:
            start: The lower bound (inclusive) if stop is provided, otherwise it's the upper bound (exclusive)
            stop: The upper bound (exclusive)
            inc: The step size (default is 1)
            
        Returns:
            A random number within the specified range
        """
        # If only one argument is provided, treat it as `stop` (start defaults to 0)
        if stop is None:
            stop = start
            start = 0
        # Default increment is 1 if not provided
        if inc is None:
            inc = 1
        # tep cannot be 0 
        if inc == 0:
            raise ValueError("genrand_range() step argument must not be zero")
        if inc > 0:
            if start >= stop:
                raise ValueError(f"empty range for genrand_range({start}, {stop}, {inc})")
            width = stop - start
            n = (width + inc - 1) // inc   # number of increments in [start, stop)
        else:
            if start <= stop:
                raise ValueError(f"empty range for genrand_range({start}, {stop}, {inc})")
            width = stop - start  # this will be negative or zero
            n = (width + inc + 1) // inc   # number of increments for negative step
        
        if n <= 0:
            raise ValueError(f"empty range for genrand_range({start}, {stop}, {inc})")
        
        # Generate a uniform random index and return the corresponding value
        return start + self._randbelow(n) * inc

    def _randbelow(self, n):
        """Return a random int in [0, n) using the MT19937 internal state, avoiding bias."""
        if n <= 0:
            return 0
            
        # Determine number of random bits needed
        k = n.bit_length()
        
        # Generate random bits until we get a value below n (rejection sampling)
        r = self.genrand_int32() >> (32 - k)
        while r >= n:
            r = self.genrand_int32() >> (32 - k)
        return r

    def genrand_choices(self, choices: List[Any]) -> Any:
        """
        Generate a random choice from a List. Can be any data type as long as it's a valid python list.
        
        Args:
            choices: A list of items to choose from
            
        Returns:
            A random item from the list
        """
        if not choices:
            raise IndexError("Cannot choose from an empty sequence")
        return choices[self._randbelow(len(choices))]

    def genrand_int32(self):
        y, self._mti = genrand_int32(self._mt, self._mti)
        return y

    def setrandbits(self, y, bits):
        '''The interface for :py:meth:random.Random.getrandbits in Python's Standard Library
        '''
        if not (bits % 32 == 0):
            raise ValueError('number of bits must be a multiple of 32')
        if not (0 <= y < 2 ** bits):
            raise ValueError('invalid state')
        if bits == 32:
            self.setrand_int32(y)
        else:
            while bits > 0:
                self.setrand_int32(y & 0xffffffff)
                y >>= 32
                bits -= 32

    def getrandbits(self, bits):
        '''The interface for :py:meth:random.Random.getrandbits in Python's Standard Library
        '''
        if not (bits > 0):
            raise ValueError('number of bits must be greater than zero')
        if bits <= 32:
            return self.genrand_int32() >> (32 - bits)
        else:
            acc = bytearray()
            while bits > 0:
                r = self.genrand_int32()
                if bits < 32:
                    r >>= 32 - bits
                acc += _to_bytes(r, 4, byteorder='little')
                bits -= 32
            return _from_bytes(acc, byteorder='little')

    def random(self):
        '''The interface for :py:meth:random.Random.random in Python's Standard Library
        '''
        a = self.genrand_int32() >> 5
        b = self.genrand_int32() >> 6
        return ((a * 67108864.0 + b) * (1.0 / 9007199254740992.0))

    def seed(self, *args):
        '''
        Seed and/or re-seed the RNG. 
        - Not implemented
        '''
        raise NotImplementedError

    def setstate(self, *args):
        '''
        Set the state to a known value.
        '''
        raise NotImplementedError

    def getstate(self, *args):
        '''
        Get the current state value. Requires a "rewind" function to rewind the state back to the original seed and obtain all future states.
        '''
        raise NotImplementedError



def test_mt19937_predictor():
    """
    Test the MT19937Predictor by:
    1. Generating 624 random 32-bit integers
    2. Feeding them to the predictor to recover the internal state
    3. Comparing the next predicted value with the actual value
    """
    
    # Generate a different seed each time the script is ran/tested
    random.seed(random.randint(1, 999999999))
    # test "quack-rock, paper, scissors" game similar to challenge
    choices = ["quackrock","quackpaper","quackscissors"] 
    # Create predictor
    predictor = MT19937Predictor()
    
    # Generate 624 random numbers and feed them to the predictor
    random_numbers = []
    for _ in range(624):
        num = random.getrandbits(32)
        random_numbers.append(num)
        predictor.setrandbits(num, 32)
    
    # Verify the predictor can predict the next number
    next_actual = random.getrandbits(32)
    next_predicted = predictor.getrandbits(32)
    
    print(f"Actual next number: {next_actual}")
    print(f"Predicted next number: {next_predicted}")
    print(f"Prediction correct: {next_actual == next_predicted}")
    
    # Verify other functions
    next_actual_randrange = random.randrange(1, 100, 2)
    next_predicted_randrange = predictor.genrand_range(1, 100, 2)
    
    print(f"Actual next randrange: {next_actual_randrange}")
    print(f"Predicted next randrange: {next_predicted_randrange}")
    print(f"Prediction correct: {next_actual_randrange == next_predicted_randrange}")
    
    choices_f = ["apple", "banana", "cherry", "date", "elderberry"]
    next_actual_choice = random.choice(choices_f)
    next_predicted_choice = predictor.genrand_choices(choices_f)
    for i in range(11):
        computer_choice = random.choice(choices)
        predicted_choice = predictor.genrand_choices(choices)
        correct = computer_choice == predicted_choice
        print(f"Guess #{i}\t Correct? {correct}\tComputer choice: {computer_choice}, Predicted: {predicted_choice}")
    print(f"Actual next choice: {next_actual_choice}")
    print(f"Predicted next choice: {next_predicted_choice}")
    print(f"Prediction correct: {next_actual_choice == next_predicted_choice}")
    
    return all([
        next_actual == next_predicted,
        next_actual_randrange == next_predicted_randrange,
        next_actual_choice == next_predicted_choice
    ])


if __name__ == "__main__":
    print(f"Made for educational/demonstration purposes primarily.")
    print(f"You could very easily substitute randcrack for this module, they accomplish the same goal with only a few missing/differing functions.")
    print(f"Source: http://comibear.kr/crypto/cracking-python-random-module/")
    test_result = test_mt19937_predictor()
    print(f"All tests passed: {test_result}")

