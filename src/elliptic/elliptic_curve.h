#ifndef ELLIPTIC_CURVE_H
#define ELLIPTIC_CURVE_H

#include "point.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <stdexcept>
#include <map>

namespace elliptic {

using BigInt = boost::multiprecision::cpp_int;

inline BigInt mod(const BigInt& a, const BigInt& p) {
    BigInt r = a % p;
    if (r < 0) r += p;
    return r;
}

inline BigInt mod_pow(BigInt base, BigInt exp, const BigInt& modulus) {
    BigInt result = 1;
    base = mod(base, modulus);
    while (exp > 0) {
        if (exp & 1) result = mod(result * base, modulus);
        base = mod(base * base, modulus);
        exp >>= 1;
    }
    return result;
}

inline BigInt mod_inv(const BigInt& a, const BigInt& p) {
    // Extended Euclidean algorithm
    BigInt t = 0, new_t = 1;
    BigInt r = p, new_r = mod(a, p);

    while (new_r != 0) {
        BigInt q = r / new_r;
        BigInt tmp = new_t;
        new_t = t - q * new_t;
        t = tmp;
        tmp = new_r;
        new_r = r - q * new_r;
        r = tmp;
    }
    if (r > 1) throw std::runtime_error("Inverse does not exist");
    if (t < 0) t += p;
    return t;
}

inline BigInt mod_sqrt(BigInt a, const BigInt& p) {
    if (a == 0) return 0;
    if (p % 4 == 3) {
        return mod_pow(a, (p + 1) / 4, p);
    }
    BigInt q = p - 1;
    unsigned s = 0;
    while ((q & 1) == 0) {
        q >>= 1;
        ++s;
    }
    BigInt z = 2;
    while (mod_pow(z, (p - 1) / 2, p) != p - 1) ++z;
    BigInt c = mod_pow(z, q, p);
    BigInt x = mod_pow(a, (q + 1) / 2, p);
    BigInt t = mod_pow(a, q, p);
    unsigned m = s;
    while (t != 1) {
        BigInt tmp = t;
        unsigned i = 0;
        for (; i < m; ++i) {
            if (tmp == 1) break;
            tmp = mod_pow(tmp, 2, p);
        }
        BigInt b = mod_pow(c, BigInt(1) << (m - i - 1), p);
        x = mod(x * b, p);
        c = mod_pow(b, 2, p);
        t = mod(t * c, p);
        m = i;
    }
    return x;
}

class EllipticCurve {
public:
    EllipticCurve(BigInt a_, BigInt b_, BigInt p_) : a(std::move(a_)), b(std::move(b_)), p(std::move(p_)) {
        if (p <= 2) throw std::invalid_argument("p must be > 2 and prime");
    }

    Point add(const Point& P, const Point& Q) const {
        if (P.infinity) return Q;
        if (Q.infinity) return P;
        if (P.x == Q.x && P.y != Q.y) return Point::Infinity();

        BigInt lambda;
        if (P == Q) {
            if (P.y == 0) return Point::Infinity();
            lambda = mod(((3 * P.x * P.x) + a) * mod_inv(2 * P.y, p), p);
        } else {
            lambda = mod((Q.y - P.y) * mod_inv(Q.x - P.x, p), p);
        }
        BigInt x_r = mod(lambda * lambda - P.x - Q.x, p);
        BigInt y_r = mod(lambda * (P.x - x_r) - P.y, p);
        return Point(x_r, y_r);
    }

    Point multiply(Point P, BigInt n) const {
        Point R = Point::Infinity();
        if (P.infinity || n == 0) return R;
        while (n > 0) {
            if (n & 1) R = add(R, P);
            P = add(P, P);
            n >>= 1;
        }
        return R;
    }

    BigInt order() const {
        Point P = find_nonzero_point();
        BigInt t = trace_bsgs(P);
        BigInt n = p + 1 - t;
        return n;
    }

private:
    Point negate(const Point& P) const {
        if (P.infinity) return P;
        return Point(P.x, mod(-P.y, p));
    }

    Point find_nonzero_point() const {
        for (BigInt x = 0; x < p; ++x) {
            BigInt rhs = mod(x * x * x + a * x + b, p);
            if (rhs == 0) return Point(x, 0);
            if (mod_pow(rhs, (p - 1) / 2, p) == 1) {
                BigInt y = mod_sqrt(rhs, p);
                return Point(x, y);
            }
        }
        throw std::runtime_error("no point on curve");
    }

    BigInt trace_bsgs(const Point& P) const {
        BigInt sqrt_p = boost::multiprecision::sqrt(p);
        BigInt bound = 2 * sqrt_p;
        BigInt m = boost::multiprecision::sqrt(bound) + 1;

        std::map<Point, BigInt, PointLess> table;
        Point acc = Point::Infinity();
        for (BigInt j = 0; j <= m; ++j) {
            table.emplace(acc, j);
            acc = add(acc, P);
        }

        Point mP = multiply(P, m);
        Point neg_mP = negate(mP);
        Point Q = multiply(P, p + 1);

        Point cur = Q;
        for (BigInt i = 0; i <= m; ++i) {
            auto it = table.find(cur);
            if (it != table.end()) {
                BigInt t = i * m + it->second;
                if (t <= bound) return t;
            }
            cur = add(cur, neg_mP);
        }

        cur = Q;
        for (BigInt i = 0; i <= m; ++i) {
            auto it = table.find(cur);
            if (it != table.end()) {
                BigInt t = it->second - i * m;
                if (-bound <= t) return t;
            }
            cur = add(cur, mP);
        }
        throw std::runtime_error("trace not found");
    }
    BigInt a;
    BigInt b;
    BigInt p;
};

} // namespace elliptic

#endif // ELLIPTIC_CURVE_H
