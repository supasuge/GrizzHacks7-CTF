# Graham Crackers Solution
- **Author**: [supasuge](https://github.com/supasuge) | Evan Pardon
- **Difficulty**: Hard

*Note: This writeup was written using Obsidian and is best viewed using Obsidian. GitHub and Obsidian render LaTex/Tex Math equations differently. To be more specific: GitHub is pain, this writeup looks uh rough to say the least... sorry.* **Good nuff'**

Paper used: [RSA and LLL Attacks - David Wong](https://raw.githubusercontent.com/mimoo/RSA-and-LLL-attacks/master/survey_final.pdf)

## Overview

The Coppersmith–Howgrave–Graham method is a lattice-based technique designed to find **small roots of univariate polynomial equations modulo a large integer**, typically the RSA modulus $N = pq$. When dealing with RSA, if we know that the plaintext message $M$ is structured in a particular way—for example, if the highest bits of $M$ are known—then we can represent the unknown part of $M$ as a small integer and set up a polynomial equation whose root corresponds to this unknown integer.

In this example, we consider a situation where:
- We have an RSA modulus $N = p \cdot q$.
- The encryption exponent is $e$ (often small, like 3).
- The ciphertext is given by:
  $C \equiv M^e \pmod{N}$
- The plaintext $M$ is of the form
- $M = 2^{\text{length}_N} - 2^{K_{\text{bits}}} + K$

where:
  - $\text{length}_N$ is the bit length of $N$.
  - $K_{\text{bits}}$ is the number of bits of the unknown part $K$.
  - $K$ is the unknown integer we wish to recover (it corresponds to some secret message or flag).

Because $K$ is much smaller than $N$ (specifically, $|K| < N^{\delta}$ for some small $\delta$), we can leverage the Coppersmith–Howgrave–Graham method to find it.

## The Coppersmith–Howgrave–Graham Method

### High-Level Idea

1. **Polynomial Construction**:  
   We know:
   $$ M = 2^{\text{length}_N} - 2^{K_{\text{bits}}} + x. $$
   Since we know $C \equiv M^e \pmod{N}$, we can write:
   $$ (2^{\text{length}_N} - 2^{K_{\text{bits}}} + x)^e - C \equiv 0 \pmod{N}. $$

   Let:
   $$ f(x) = (2^{\text{length}_N} - 2^{K_{\text{bits}}} + x)^e - C $$

   We want to find an integer root of $f(x)$ modulo $N$, that is, an integer $x = K$ such that:
   $$ f(K) \equiv 0 \pmod{N} $$

2. **Lattice Construction**:  
   The CHG method uses lattice reduction (via the LLL algorithm) to find a short vector in a carefully constructed lattice. This lattice is built from polynomial combinations of $f(x)$ and powers of the modulus $N$, scaling by factors to ensure the resulting polynomial will have a unique small root.

   More concretely, we construct a lattice basis from the polynomials:
   $$ (xX)^j N^{m - i} (f(xX))^i $$
   for certain parameters $m, t$ that depend on $\beta, \epsilon$, and the degree $d$ of the polynomial. The integer $$X$$ is a bound on the root size. We choose parameters such that if a small root exists (i.e., $|K| < X$), the LLL-reduced basis will produce a polynomial with that small root as an integer solution.

3. **LLL Reduction & Root Extraction**:
   After constructing the lattice, we apply the LLL algorithm to obtain a reduced basis. The first vector in the reduced basis often corresponds to a polynomial whose integer root gives us the desired value of $K$.

   If the parameters are chosen correctly, we end up with a polynomial that has a **small integer root**—our hidden integer $K$. Factoring this polynomial reveals the root, thus recovering $K$.

### Parameter Selection

The success of the method relies on choosing parameters $\beta, m, t, X$ properly. For a univariate polynomial:

- $\beta$ is chosen such that $N^\beta$ bounds the unknown. In our example, we set $\beta = 1$, so we consider $b = N$.
- $\epsilon$ is chosen small enough to ensure the approach converges.
- $m$ and $t$ are chosen based on optimization conditions in the CHG method:
$$m = \lceil \beta^2 / (d \cdot \epsilon) \rceil$$
$$t = \lfloor d \cdot m \cdot ((1/\beta) - 1) \rfloor$$

- $X$ is chosen as:
$$X = \lceil N^{(\beta^2/d) - \epsilon} \rceil$$

- These conditions ensure:
1. $X^{n-1} < N^{\beta m}$
2. The resulting lattice will, after LLL, yield a suitable polynomial whose small root can be found by simple factoring methods.

## Mathematical Formulation

1. Given:
$$ 
N, e, C, \text{ and the form of } M = 2^{\text{length}_N} - 2^{K_{\text{bits}}} + K. 
$$

2. Define:
$$ 
f(x) = (2^{\text{length}_N} - 2^{K_{\text{bits}}} + x)^e - C. 
$$

We aim to solve:
$$ 
f(K) \equiv 0 \pmod{N}, \quad |K| < X. 
$$

3. Construct a lattice basis from polynomials:

$$
g_{i,j}(x) = (xX)^j N^{m-i} f(xX)^i
$$

For $0 \leq i < m, \, 0 \leq j < d$, and similarly for the last $t$ polynomials:
$$
g_{\text{last}, i}(x) = (xX)^i f(xX)^m 
$$

1. Form the lattice from the coefficients of these polynomials. After LLL reduction, we obtain a short vector that corresponds to a polynomial with an integer root, that root being our secret $$K$$.

## Practical Considerations

- **Lattice Reduction**:  
  We use SageMath’s built-in LLL to reduce the lattice. The first vector of the LLL-reduced basis is typically where we extract our polynomial from.

- **Root Checking**:  Once we have the reduced polynomial, we factor it over the integers and check potential roots. Any integer root that satisfies: $f(K) \equiv 0 \pmod{N}$ and is small enough is a candidate. In practice, we verify by plugging $K$ back into the polynomial.

- **Performance**:  
The method is efficient for certain parameter sizes and relies heavily on having a small unknown part $K$ relative to the size of $N$.

## Example Run

From the log:

- Conditions check:
$X^{n-1} < N^{\beta*m} \implies \text{True}$

- After constructing the lattice and applying LLL, we find potential roots:
$\text{potential roots: } K = 24312127718216902322824460514133466178941$

- Reconstructing the message:
We form:
$M = 2^{\text{length}_N} - 2^{K_{\text{bits}}} + K$

Converting $M$ to bytes and decoding reveals the hidden flag:

```text
GrizzCTF{Graham_Cracked!}
```

## Code

The provided code (`solve.sage`) sets up the problem, runs the CHG method, and recovers the hidden flag. Key steps include:

- Defining the polynomial and parameters.
- Constructing and reducing the lattice.
- Checking for small roots and verifying them.
- Decoding the recovered plaintext from the integer representation.

## Conclusion

The Coppersmith–Howgrave–Graham method is a powerful technique in cryptanalysis for finding small roots of polynomial equations modulo $N$. When RSA plaintexts follow a known structural pattern, this attack can recover unknown portions of the message—demonstrated here by revealing the `GrizzCTF{Graham_Cracked!}` flag.

### Mathematical Context

In the Howgrave-Graham variant of Coppersmith's method, we're solving:
$M = 2^{length_N} - 2^{Kbits} + K$ (where $K$ is small)

And RSA encryption gives us: 

$C ≡ M^e \pmod{N}$

Therefore:

$C ≡ (2^{length_N} - 2^{Kbits} + K)^e \pmod{N}$

So, let's define our polynomial according to coppersmith's theorem:

$f(x) = (2^{length_N} - 2^{Kbits} + x)^e - C$
    
### Parameters:

```sh
N: 1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236087851365277945956976543709998340361590134383718314428070011855946226376318839397712745672334684344586617496807908705803704071284048740118609114467977783598029006686938976881787785946905630190260940599579453432823469303026696443059025015972399867714215541693835559885291486318237914434496734087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225998300412344784862595674492194617107766087686511607792989085017252143815336613006118525717787806438387060725974265620447965686506814553788073277382250190105705405186375024556833291006823773637983292284527779401216796709835850690521381013583202448370799186156489522196238248039801706889984061598510143551993564543378505292143052178826887278512641781002799084056839536397276217311109569190045037766785935099032805517858354520980090274128587808504179811531037024848206067101247897906212552772476965139547592846335713345792575061160715963452636783429069083092588478551284216547986935684693225387468951564347041644471458189153699117097101912389873234163020901 (bit length: 4097)
e: 3
length_N: 4096
Kbits: 200
degree of polynomial: 3
```

### Coppersmith Parameters:

- $d$ (polynomial degree): 3
- $m$ (multiplicity): 3
- $t$ (extra shifts): 0
- $X$ (bound): 7256641442280835233301778621760379063953665817337412353825160297177947071727699350605311339956648916092710036615215403794887510365982603750841130604304303522688162125451161899924467142724040406758072119258324459880769819662659332915638

- Howgrave-Graham's Theorem states that we need:
$\|p(xX)\| < \frac{N^m}{\sqrt{n}}$ where $n$ is the lattice dimension
    

### Checking Howgrave-Graham Conditions:
```sh
$X^{n-1} = 7.68927365891604e1878$
$N^{β·m} = 1139165225263043370845938579315932008621298468028614501113799533426642439172469691567306477711637014807943967858591694430860851793602514412750433611928876871974929526595136714292202269877243080587167355589274624927976353262692345148008309507573685819955835876321194702904067672852630585653761861644571242372171305938720329762415531090187952999394484080243158140230933768654317732072862346478657014808167434738566098066865703948435697960690698143820219097883920407003040686456523245108233529281149726862222693477558297365169919254213176849897203892254348439995073129761356765109910020479495393380661515697239302324456675580537861285295416194569300459698969566610100156425585528838582331535664077681027241145212247330414946801077050336275243656949609034332555086117514837847549416366298057634003713008614758167279648281039600485210887498881580387097397659794353266289163016771855001406761430387293426543552011143509912506391232167601835738757144324801120852834935748283761385604417723838169116709381609477599338578655387532371900097178971847542917138527769234958202457882528134933256542358099959040092642431289616883484407802808437261580615588792728203023632033804183543183050401055289424329308461203504966216490725561036203691386295145114674243802422808364579128274270941346210286772210587177299277977883532599697006743552002217337955540348328170764733918712963757441931526296401952476040703009622050369085914783996144391565741008894256923023992272660232264961932189878646406108546948610335453631561896555413192851737045739339824516375769435574694263069382153722514338332593620104660271464260589468584206027977801511954998796131843117868043168681128124758090158604640894123281980294821360324115442673821383034908215523732268842281671646490643299246370521810517903056957031222104717175386916099185926207215561072271017792075928852170334216128664324017414630572853193963697609619868061198660152744561750915731365220342144916168702701920511007890420121860254080657521012172846054489071897226316349579394033901505763980687868784826088812518907613700072380841628332327104280945151712837962786680426896298234226736623809910767747522997718381199434393500032745123060037453265409053604279052156685759629901902408699556927983425367623015085205610643136821779854395874984183701066472895208627290752346814760477631785287488872527074680158983327840912996989301213151354921784065828880417484121963917821897551225956917014529273549523432701672079346133417177887481558435487131297058783232125243012387449172389487595528166219793261627403733374232297874587897411266560060847189266215008624719737133453247913339072061513772458044054991058280599378915715633382466053818430542920030567500718013979560461159422150264127074249842222859293677614188340206544724160098267188542614889056088345578755677927933319004124033672044344644430660916445729206463068978375749104172289405138431223114211084742657051862433175143749371869698547935691112691467179550435198202966085559708177292967640754139108756081269538166816750323989077881134277302720729798860045526634264827746821219910524980166712917941160200877827112181645886502446709882876865069413296751132189039282390915846345489833791823965240963796879533805916814012776571432758428709730465444140674267204563523542535395945580678811677485288193553591546725016595277880292746026087760467291460067291573016121982625937759960180896322447144024535799231457389862641047139834226498036845509121198594870200412522638504777074561211358142741513339192286628544664646398935493188102907769481433644373244486298646082719341289303163859138490871500116435922949792407451554071724760867295437624424954810424696105512732491009579004739473932132541103148710442422268623143982520125419963328492701$
Condition satisfied: True

Constructing lattice basis...

Initial Lattice Matrix:

Lattice Matrix Overview: 9 x 9

Matrix Structure (X=non-zero, 0=zero):
00 X 0 0 0 0 0 0 0 0 ~
01 0 X 0 0 0 0 0 0 0 ~
02 0 0 X 0 0 0 0 0 0 ~
03 X X X X 0 0 0 0 0 
04 0 X X X X 0 0 0 0 
05 0 0 X X X X 0 0 0 
06 X X X X X X X 0 0 
07 0 X X X X X X X 0 
08 0 0 X X X X X X X 

Applying LLL reduction...

Constructing polynomial from first LLL vector...

Potential roots found: [(448479597905287366562801337296132819016115865214099082453373, 2)]

Found K: 448479597905287366562801337296132819016115865214099082453373

Recovered flag: GrizzCTF{Graham_Cracked!}

Time taken: 0.16 seconds
```

##### Resources
- [David Wong - RSA and LLL Attacks](https://github.com/mimoo/RSA-and-LLL-attacks)
  - [YouTube Video](https://www.youtube.com/watch?v=3cicTG3zeVQ)
- [20 Years of Attacks on the RSA Cryptosystem](https://www.ams.org/notices/199902/boneh.pdf) 

