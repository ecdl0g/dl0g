#ifndef ELLIPTIC_POINT_H
#define ELLIPTIC_POINT_H

#include <boost/multiprecision/cpp_int.hpp>

namespace elliptic {

using BigInt = boost::multiprecision::cpp_int;

struct Point {
    BigInt x;
    BigInt y;
    bool infinity{false};

    Point() : x(0), y(0), infinity(true) {}
    Point(BigInt x_, BigInt y_) : x(std::move(x_)), y(std::move(y_)), infinity(false) {
        if (x == 0 && y == 0) {
            infinity = true;
        }
    }

    static Point Infinity() { return Point(); }
};

inline bool operator==(const Point& a, const Point& b) {
    if (a.infinity || b.infinity) return a.infinity == b.infinity;
    return a.x == b.x && a.y == b.y;
}

inline bool operator!=(const Point& a, const Point& b) { return !(a == b); }

struct PointLess {
    bool operator()(const Point& lhs, const Point& rhs) const {
        if (lhs.infinity != rhs.infinity) return lhs.infinity < rhs.infinity;
        if (lhs.x != rhs.x) return lhs.x < rhs.x;
        return lhs.y < rhs.y;
    }
};

} // namespace elliptic

#endif // ELLIPTIC_POINT_H
