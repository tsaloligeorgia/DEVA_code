try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest
import fractions

from arithmetic.numbertype import *


# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""
from utilitybelt import secure_randint as randint

def extended_gcd(int_a, int_b):
    """Find the gcd as a linear combination of 2 numbers"""
    if int_a == 0:
        return (int_b, 0, 1)
    int_g, int_y, int_x = extended_gcd(int_b % int_a, int_a)
    return (int_g, int_x - (int_b // int_a) * int_y, int_y)

def mod_inverse(int_a, modular):
    """Find inverse of int with a given mod"""
    int_a = int_a % modular
    ret = extended_gcd(modular, abs(int_a))[2]
    return (modular + ret) % modular

def random_polynomial(degree, intercept, upper_bound):
    """ Generates a random polynomial with positive coefficients.
    """
    if degree < 0:
        raise ValueError('Degree must be a non-negative number.')
    coefficients = [randint(0, upper_bound-1) for x in range(degree)]
    coefficients.insert(0, intercept)
    return coefficients

def get_polynomial_points(coefficients, num_points, prime):
    """ Calculates the first n polynomial points.
        [ (1, f(1)), (2, f(2)), ... (n, f(n)) ]
    """
    points = []
    for x_coeff in range(1, num_points+1):
        # start with x=1 and calculate the value of y
        y_coeff = coefficients[0]
        # calculate each term and add it to y, using modular math
        for i in range(1, len(coefficients)):
            exponentiation = (x_coeff**i) % prime
            term = (coefficients[i] * exponentiation) % prime
            y_coeff = (y_coeff + term) % prime
        # add the point to the list of points
        points.append((x_coeff, y_coeff))
    return points

def modular_lagrange_interpolation(x_coor, points, prime):
    """Calculate lowest degree of polynomials"""
    # break the points up into lists of x and y values
    x_values, y_values = zip(*points)
    # initialize f(x) and begin the calculation: f(x) = SUM( y_i * l_i(x) )
    f_x = 0
    for i in range(len(points)):
        # evaluate the lagrange basis polynomial l_i(x)
        numerator, denominator = 1, 1
        for j in range(len(points)):
            # don't compute a polynomial fraction if i equals j
            if i == j:
                continue
            # compute a fraction & update the existing numerator + denominator
            numerator = (numerator * (x_coor - x_values[j])) % prime
            denominator = (denominator * (x_values[i] - x_values[j])) % prime
        # get the polynomial from the numerator + denominator mod inverse
        lagrange_polynomial = numerator * mod_inverse(denominator, prime)
        # multiply the current y & the evaluated polynomial & add it to f(x)
        f_x = (prime + f_x + (y_values[i] * lagrange_polynomial)) % prime
    return f_x


# strip all copies of elt from the end of the list
def strip(L, elt):
   if len(L) == 0: return L

   i = len(L) - 1
   while i >= 0 and L[i] == elt:
      i -= 1

   return L[:i+1]




# create a polynomial with coefficients in a field; coefficients are in
# increasing order of monomial degree so that, for example, [1,2,3]
# corresponds to 1 + 2x + 3x^2
@memoize
def polynomialsOver(field=fractions.Fraction):

   class Polynomial(DomainElement):
      operatorPrecedence = 2

      @classmethod
      def factory(cls, L):
         return Polynomial([cls.field(x) for x in L])

      def __init__(self, c):
         if type(c) is Polynomial:
            self.coefficients = c.coefficients
         elif isinstance(c, field):
            self.coefficients = [c]
         elif not hasattr(c, '__iter__') and not hasattr(c, 'iter'):
            self.coefficients = [field(c)]
         else:
            self.coefficients = c

         self.coefficients = strip(self.coefficients, field(0))


      def get_coeff(self):
         return self.coefficients


      def isZero(self): return self.coefficients == []

      def __repr__(self):
         if self.isZero():
            return '0'

         return ' + '.join(['%s x^%d' % (a,i) if i > 0 else '%s'%a
                              for i,a in enumerate(self.coefficients)])


      def __abs__(self): return len(self.coefficients) # the valuation only gives 0 to the zero polynomial, i.e. 1+degree
      def __len__(self): return len(self.coefficients)
      def __sub__(self, other): return self + (-other)
      def __iter__(self): return iter(self.coefficients)
      def __neg__(self): return Polynomial([-a for a in self])

      def iter(self): return self.__iter__()
      def leadingCoefficient(self): return self.coefficients[-1]
      def degree(self): return abs(self) - 1

      @typecheck
      def __eq__(self, other):
         return self.degree() == other.degree() and all([x==y for (x,y) in zip(self, other)])

      @typecheck
      def __ne__(self, other):
          return self.degree() != other.degree() or any([x!=y for (x,y) in zip(self, other)])

      @typecheck
      def __add__(self, other):
         newCoefficients = [sum(x) for x in zip_longest(self, other, fillvalue=self.field(0))]
         return Polynomial(newCoefficients)


      @typecheck
      def __mul__(self, other):
         if self.isZero() or other.isZero():
            return Zero()

         newCoeffs = [self.field(0) for _ in range(len(self) + len(other) - 1)]

         for i,a in enumerate(self):
            for j,b in enumerate(other):
               newCoeffs[i+j] += a*b

         return Polynomial(newCoeffs)


      @typecheck
      def __divmod__(self, divisor):
         quotient, remainder = Zero(), self
         divisorDeg = divisor.degree()
         divisorLC = divisor.leadingCoefficient()

         while remainder.degree() >= divisorDeg:
            monomialExponent = remainder.degree() - divisorDeg
            monomialZeros = [self.field(0) for _ in range(monomialExponent)]
            monomialDivisor = Polynomial(monomialZeros + [remainder.leadingCoefficient() / divisorLC])

            quotient += monomialDivisor
            remainder -= monomialDivisor * divisor

         return quotient, remainder


      @typecheck
      def __truediv__(self, divisor):
         if divisor.isZero():
            raise ZeroDivisionError
         return divmod(self, divisor)[0]


      @typecheck
      def __mod__(self, divisor):
         if divisor.isZero():
            raise ZeroDivisionError
         return divmod(self, divisor)[1]



   def Zero():
      return Polynomial([])


   Polynomial.field = field
   Polynomial.__name__ = '(%s)[x]' % field.__name__
   Polynomial.englishName = 'Polynomials in one variable over %s' % field.__name__
   return Polynomial
