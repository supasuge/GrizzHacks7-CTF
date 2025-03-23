#!/usr/bin/sage
from sage.all import *
import time
from Crypto.Util.number import long_to_bytes, bytes_to_long
import sys
from dataclasses import dataclass
# parameters from `out.txt`
@dataclass
class COLORS:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_mathematical_context(N, e, C, length_N, Kbits):
    print_header("Mathematical Context")
    print(f"""
    In the Howgrave-Graham variant of Coppersmith's method, we're solving:

    $M = 2^{{length_N}} - 2^{{Kbits}} + K$ (where K is small)
    $C ≡ M^e \\pmod{{N}}$

    Therefore:
    $C ≡ (2^{{length_N}} - 2^{{Kbits}} + K)^e \\pmod{{N}}$

    Let's define our polynomial:
    $f(x) = (2^{{length_N}} - 2^{{Kbits}} + x)^e - C$
    """)
    print(f"\n{COLORS.YELLOW}Parameters:{COLORS.RESET}")
    print(f"N: {N} (bit length: {N.nbits()})")
    print(f"e: {e}")
    print(f"length_N: {length_N}")
    print(f"Kbits: {Kbits}")

def explain_beta_choice(beta, N, Kbits):
    print_header("Beta Selection Analysis")
    print(f"""
    The parameter β (beta) determines the bound on our solution:
    - We want to find roots < $N^β$
    - In our case, K is approximately $2^{{Kbits}}$
    - Therefore, we need: $2^{{Kbits}} < N^β$
    """)
    print(f"\n{COLORS.YELLOW}In this case:{COLORS.RESET}")
    print(f"$2^{{{Kbits}}} < N^{{{beta}}}$")
    print(f"$2^{{{Kbits}}} < 2^{{{N.nbits()}·{beta}}}$")
    print(f"Required β > {Kbits/N.nbits():.4f}")
    print(f"Chosen β = {beta}")




N = 1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617107766087686511607792989085017252143815336613006118525717787806438387060725974265620447965686506814553788073277382250190105705405186375024556833291006823773637983292284527779401216796709835850690521381013583202448370799186156489522196238248039801706889984061598510143551993564543378505292143052178826887278512641781002799084056839536397276217311109569190045037766785935099032805517858354520980090274128587808504179811531037024848206067101247897906212552772476965139547592846335713345792575061160715963452636783429069083092588478551284216547986935684693225387468951564347041644471458189153699117097101912389873234163020901
e = 3
C = 1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850550694944270273684458083886144572613440223965254039637447544364415259742372466751649091175759063732413059392295550023825574031075500763990177694822003728136070359909270642651489020491377571229125766855084209492347896080074115073412973924585321295867263530042925882685420161814511514201776594374378252658710624469689956484331778806497114314075014039133908540317410759373501383083147561400071146895805578536551191164345386383517865321756191167218910726043425408751339370498499575344761131375850734155653661133274905528844175414821150645758038026700289634321154812565297428831149270418618530257381846034086189933594264312007850172028234048280280400503354096858399370339739281539030871249549690755588639157488172797741147677280463666702647778101365
length_N = 4096
Kbits = 200

def print_header(text):
    print(f"{COLORS.BLUE}{'='*50}{COLORS.RESET}")
    print(f"{COLORS.BOLD}{text}{COLORS.RESET}")
    print(f"{COLORS.BLUE}{'='*50}{COLORS.RESET}")   

def matrix_overview(BB, bound):
    dims = BB.dimensions()
    print(f"\n{COLORS.YELLOW}Lattice Matrix Overview{COLORS.RESET}: {dims[0]} x {dims[1]}")
    print(f"\n{COLORS.YELLOW}Matrix Structure{COLORS.RESET} (X=non-zero, 0=zero):")
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print(a)

def coppersmith_howgrave_univariate(pol, modulus, beta, mm, tt, XX):
    dd = pol.degree()
    nn = dd * mm + tt
    print(f"\n{COLORS.YELLOW}Coppersmith Parameters:{COLORS.RESET}")
    print(f"d (polynomial degree): {dd}")
    print(f"m (multiplicity): {mm}")
    print(f"t (extra shifts): {tt}")
    print(f"X (bound): {XX}")
    print("""
    Howgrave-Graham's Theorem states that we need:
    $\\|p(xX)\\| < \\frac{N^m}{\\sqrt{n}}$ where $n$ is the lattice dimension
    """)
    if not 0 < beta <= 1:
        raise ValueError("beta should be in (0,1]")
    if not pol.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    
    # sanity debug print
    print(f"\n{COLORS.YELLOW}Checking Howgrave-Graham Conditions:{COLORS.RESET}")
    cond1 = RR(XX^(nn-1))
    cond2 = pow(modulus, beta*mm)
    print(f"$X^{{n-1}} = {cond1}$")
    print(f"$N^{{β·m}} = {cond2}$")
    print(f"Condition satisfied: {COLORS.GREEN if cond1 < cond2 else COLORS.RED}{cond1 < cond2}{COLORS.RESET}")


    polZ = pol.change_ring(ZZ)
    x = polZ.parent().gen()
    print(f"\n{COLORS.YELLOW}Constructing lattice basis...{COLORS.RESET}")
    # build polynomials for lattice basis
    gg = []
    for ii in range(mm):
        for jj in range(dd):
            gg.append((x*XX)^jj * modulus^(mm - ii) * (polZ(x*XX))^ii)
    for ii in range(tt):
        gg.append((x*XX)^ii * (polZ(x*XX))^mm)

    nn = len(gg)
    BB = Matrix(ZZ, nn)

    for i in range(nn):
        for j in range(i+1):
            BB[i, j] = gg[i][j]

    print(f"\n{COLORS.YELLOW}Initial Lattice Matrix:{COLORS.RESET}")
    matrix_overview(BB, modulus^mm)

    print(f"\n{COLORS.YELLOW}Applying LLL reduction...{COLORS.RESET}")
    BB = BB.LLL()

    # construct new polynomial
    print(f"\n{COLORS.YELLOW}Constructing polynomial from first LLL vector...{COLORS.RESET}")
    new_pol = 0
    for i in range(nn):
        new_pol += x^i * BB[0, i]/XX^i

    # factor polynomial and check roots
    potential_roots = new_pol.roots()
    print(f"\n{COLORS.YELLOW}Potential roots found:{COLORS.RESET} {potential_roots}")
    roots = []
    polZ = polZ.change_ring(ZZ)
    for root in potential_roots:
        rr = root[0]
        if rr.is_integer():
            val = polZ(ZZ(rr))
            if gcd(modulus, val) >= modulus^beta:
                roots.append(ZZ(rr))
    return roots


#####################################
# Attempt to Recover K
#####################################

ZmodN = Zmod(N)
P.<x> = PolynomialRing(ZmodN)
# Polynomial from the original example:
# pol = (2^length_N - 2^Kbits + x)^e - C
print_mathematical_context(N, e, C, length_N, Kbits)
# our polynomial
pol = (2^length_N - 2^Kbits + x)^e - C
dd = pol.degree()
print(f"degree of polynomial: {dd}")
# Parameters for Coppersmith
beta = 1   # b = N # 
epsilon = beta / 7
mm = ceil(beta^2 / (dd * epsilon))
tt = floor(dd * mm * ((1/beta) - 1))
XX = ceil(N^((beta^2/dd) - epsilon))

start_time = time.perf_counter()
try:
    roots = coppersmith_howgrave_univariate(pol, N, beta, mm, tt, XX)
    if len(roots) > 0:
        K = roots[0]
        print(f"\n{COLORS.GREEN}Found K:{COLORS.RESET} {K}")
        M = 2^length_N - 2^Kbits + K
        M_bytes = long_to_bytes(M)
        try:
            msg = M_bytes.decode('utf-8', 'ignore')
            print(f"\n{COLORS.GREEN}Recovered flag:{COLORS.RESET} {msg}")
        except:
            print(f"\n{COLORS.RED}Could not decode message directly. Raw bytes:{COLORS.RESET}", M_bytes)
    else:
        print(f"\n{COLORS.RED}No roots found.{COLORS.RESET}")
except Exception as e:
    print(f"\n{COLORS.RED}Error occurred:{COLORS.RESET} {e}")
finally:
    elapsed = time.perf_counter() - start_time
    print(f"\n{COLORS.BLUE}Time taken:{COLORS.RESET} {elapsed:.2f} seconds")