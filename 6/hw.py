# brew install gmp
# brew install mpfr
# brew install libmpc
# bin/easy_install http://gmpy.googlecode.com/files/gmpy2-2.0.0b1.zip
# wget http://www.math.umbc.edu/~campbell/Computers/Python/numbthy.py


from __future__ import division  # division with floats

import gmpy2 as gmpy
from gmpy2 import RoundUp


N = '179769313486231590772930519078902473361797697894230657273430081157732675805505620686985379449212982959585501387537164015710139858647833778606925583497541085196591615128057575940752635007475935288710823649949940771895617054361149474865046711015101563940680527540071584560878577663743040086340742855278549092581'
N = gmpy.mpz(N)

context = gmpy.get_context()
context.round = RoundUp
A = gmpy.rint(gmpy.sqrt(N))
A2 = pow(A, 2)

print "N    :", int(N)
print "A^2  :", int(A2)

assert A2 > N

x = gmpy.sqrt(A2 - N)
print "x    :", int(x)

p = gmpy.sub(A, x)
q = gmpy.add(A, x)

print "p*q  :", int(gmpy.mul(p, q))
assert N == gmpy.mul(p, q)

print "p    :", int(p)
print "q    :", int(q)
print "p<q  :", p < q
