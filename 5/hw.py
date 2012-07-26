# brew install gmp
# brew install mpfr
# brew install libmpc
# bin/easy_install http://gmpy.googlecode.com/files/gmpy2-2.0.0b1.zip
# wget http://www.math.umbc.edu/~campbell/Computers/Python/numbthy.py


from __future__ import division  # division with floats

import gmpy2
import numbthy


B = 2 ** 20
p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
g = 11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568
h = 3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333


def left(x):
    return gmpy2.divm(h, numbthy.powmod(g, x, p), p)


def right(x):
    return numbthy.powmod(g, B * x, p)


lefts = dict()
for i in range(B):
    lefts[left(i)] = i
    print i


for i in range(B):
    print i
    if lefts.get(right(i)):
        x0 = i
        x1 = lefts[right(i)]
        print 'x0: ', x0, '; x1: ', x1
        break

x = x0 * B + x1
print 'x: ', x
