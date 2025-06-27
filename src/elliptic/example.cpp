#include "elliptic_curve.h"
#include <iostream>

using namespace elliptic;

int main() {
    BigInt p = 97; // small prime
    BigInt a = 2;
    BigInt b = 3;
    EllipticCurve curve(a, b, p);

    Point G(3, 6); // Example point on the curve y^2 = x^3 + 2x + 3 mod 97
    Point R = curve.multiply(G, 20);
    std::cout << "20G = (" << R.x << ", " << R.y << ")\n";

    std::cout << "Curve order: " << curve.order() << "\n";
    return 0;
}
