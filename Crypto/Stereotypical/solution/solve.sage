from Crypto.Util.number import bytes_to_long, long_to_bytes
from dataclasses import dataclass
# Source: https://github.com/josephsurin/lattice-based-cryptanalysis/blob/main/lbc_toolkit/attacks/rsa_stereotyped_message.sage
from lbc_toolkit import rsa_stereotyped_message
import re
import time

@dataclass
class COLORS:
    RED: str = '\033[91m'
    GREEN: str = '\033[92m'
    YELLOW: str = '\033[93m'
    BLUE: str = '\033[94m'
    MAGENTA: str = '\033[95m'
    CYAN: str = '\033[96m'
    BOLD: str = '\033[1m'
    RESET: str = '\033[0m'

def get_flag(decrypted: bytes) -> str:
    flag_pattern = rb'GrizzCTF\{[A-Za-z0-9_]+\}'
    match = re.search(flag_pattern, decrypted)
    if match:
        return match.group(0).decode('utf-8')
    return None

n = 606565913851396591190445900953129961505923552951022339482641200501991333384381745874578649238571429576023052254561223941110911670756858055647836790380929655260121277498475457698069226802448009803895316626442045965007023090681663479890686085818511495575640838177639257854901112488396488800576864803052503970819003184915902369410957553443420616316862582917582241563258099564378483649837883802100231412132138700363942863064214709498597362112482115428452523592968138084298962982175436600590015698040964458355128351098951740711517522709374181414352266931750511652638476671082002043038415750768095553926733766774850773213200855393377415384194609452157866516671193177072275253942491564760877273967934003841440456269132783034728202767794941808816196500734593132768056702602375910920771159868158364528874838073992203611860632085166562428282520419726431676835843759212026762798301683794287259742067632997192257301923325841320188095407195414161304770454602552013614223087124833472368098815010689253556703073975966882141430552737266024361541654988055013640011490225335069668942346724743376989745321303004652063327098773182524024179517798151984976414124187088093092986650521630516845522489531623661955482339237606856871878569294910061163423115927
e = 3
c = 203990766172464743145146374587688836987716130957003038233994442417549432428081522685317356930047431744043864804705456178161999571498924668096372339488585617049805054167801508244002978049686683770336978065396933073468363683601420059877240428575705118579805211155899033938825859543321265312694831473400677042117603948022667774546474638473037962926866568983492211896459597909731730001418089167232603506352870617415587883727153247690025370846975757283900745108131122090205106765959801516042041083775670672948327752566888676658205061461365187279994908528677024091894961390888724340991846950295512706102581709852115307053478486547512725149774189585000640361270334485761561696310660296830542848421336640525758018912459253759603033951616198835163414113538896410417085247320022860193945380488378304853848940308367251605170920543524894327241907953051642698835401880420338687202528605088897841108584463865775161313654643501169488975164252278033133091552589978094408963761091416247534228733212157725528939882047881753742271592547655321188516216043255945907323635515808579552973464789770980631898347644404960722409499367338840168553425086332777325226293882615860295781

# We know the message prefix and suffix. Only the unknown portion within { ... } is unknown.
prefix = b"Hello, This is another typical RSA challenge! I'm giving you this plaintext message for safe keeping. Here is the flag: GrizzCTF{"
suffix = b"}"

def attack():
    """
    Uses rsa_stereotyped_message for a single-hole guess scenario.
    We'll guess the length of the unknown portion and try recovering it.
    """
    max_attempts = 200  # Adjust as needed
    for i in range(29, max_attempts+1):
        start_time = time.perf_counter()
        print(f"{COLORS.YELLOW}{COLORS.BOLD}Starting RSA Stereotyped message attack attempt #{i}{COLORS.RESET}")
        
        # Construct m_known: prefix + zero-bytes + suffix
        m_known = int.from_bytes(prefix + b'\x00'*30 + suffix, 'big')
        # set upper bound for the unknown value x (it is 30 after some trial/error, this script will solve within \pm{0.05-0.1} seconds on first attempt)
        # should just edit it so no loop but does the thing so
        # works for me
        X = 2^(8*i)  

        try:
            # Attempt to solve using rsa_stereotyped_message
            x0 = rsa_stereotyped_message(n, e, c, m_known, X)
            if x0 is not None:
                candidate = (m_known + x0) % n
                decrypted = long_to_bytes(candidate)
                
                flag = get_flag(decrypted)
                if flag:
                    end_time = time.perf_counter()
                    total_time = end_time - start_time
                    print(f"{COLORS.GREEN}Solution found at attempt #{i}{COLORS.RESET}{COLORS.BOLD}: {decrypted.decode('utf-8')}{COLORS.RESET}")
                    print(f"{COLORS.YELLOW}{COLORS.BOLD}Time taken: {total_time:.2f} seconds{COLORS.RESET}")
                    print(f"{COLORS.BOLD}{COLORS.MAGENTA}Flag: {flag}{COLORS.RESET}")
                    return True
                else:
                    print(f"{COLORS.BLUE}No valid flag found in attempt #{i}{COLORS.RESET}")
            else:
                print(f"{COLORS.BLUE}No roots found for attempt #{i}{COLORS.RESET}")
        except Exception as err:
            print(f"{COLORS.RED}Error occurred: {str(err)}{COLORS.RESET}")
            continue
    
    return False



if __name__ == "__main__":
    found = attack()
    if not found:
        print(f"{COLORS.RED}No solution found.{COLORS.RESET}")
    exit(0)
    
