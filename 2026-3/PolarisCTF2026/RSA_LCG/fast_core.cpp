#include <gmpxx.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <iostream>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifdef _OPENMP
#include <omp.h>
#endif

using Poly = std::vector<mpz_class>;

static inline mpz_class mod_norm(const mpz_class &x, const mpz_class &mod) {
    mpz_class r = x % mod;
    if (r < 0) r += mod;
    return r;
}

static inline mpz_class mod_add(const mpz_class &a, const mpz_class &b, const mpz_class &mod) {
    return mod_norm(a + b, mod);
}

static inline mpz_class mod_sub(const mpz_class &a, const mpz_class &b, const mpz_class &mod) {
    return mod_norm(a - b, mod);
}

static inline mpz_class mod_mul(const mpz_class &a, const mpz_class &b, const mpz_class &mod) {
    return mod_norm(a * b, mod);
}

static mpz_class mod_pow(mpz_class base, mpz_class exp, const mpz_class &mod) {
    mpz_class res = 1;
    base = mod_norm(base, mod);
    while (exp > 0) {
        if ((exp & 1) != 0) res = mod_mul(res, base, mod);
        base = mod_mul(base, base, mod);
        exp >>= 1;
    }
    return res;
}

static mpz_class mod_inv(const mpz_class &a, const mpz_class &mod) {
    mpz_class g, s, t;
    mpz_gcdext(g.get_mpz_t(), s.get_mpz_t(), t.get_mpz_t(), a.get_mpz_t(), mod.get_mpz_t());
    if (g != 1) {
        throw std::runtime_error("inverse does not exist");
    }
    return mod_norm(s, mod);
}

static void poly_trim(Poly &p) {
    while (p.size() > 1 && p.back() == 0) p.pop_back();
}

static Poly poly_normalize_monic(Poly p, const mpz_class &mod) {
    poly_trim(p);
    if (p.size() == 1 && p[0] == 0) return p;
    mpz_class inv = mod_inv(p.back(), mod);
    for (auto &c : p) c = mod_mul(c, inv, mod);
    return p;
}

static std::pair<Poly, Poly> poly_divmod_unit(Poly a, const Poly &b, const mpz_class &mod) {
    Poly divisor = b;
    poly_trim(a);
    poly_trim(divisor);
    if (divisor.size() == 1 && divisor[0] == 0) throw std::runtime_error("division by zero polynomial");
    size_t db = divisor.size() - 1;
    mpz_class inv_lc = mod_inv(divisor.back(), mod);
    Poly q(std::max<size_t>(1, a.size() >= divisor.size() ? a.size() - divisor.size() + 1 : 1), 0);
    while (!(a.size() == 1 && a[0] == 0) && a.size() >= divisor.size()) {
        size_t da = a.size() - 1;
        mpz_class coeff = mod_mul(a.back(), inv_lc, mod);
        size_t shift = da - db;
        q[shift] = coeff;
        if (coeff != 0) {
            for (size_t i = 0; i <= db; ++i) {
                a[shift + i] = mod_sub(a[shift + i], mod_mul(coeff, divisor[i], mod), mod);
            }
        }
        poly_trim(a);
    }
    poly_trim(q);
    return {q, a};
}

static Poly poly_gcd_unit(Poly a, Poly b, const mpz_class &mod) {
    a = poly_normalize_monic(std::move(a), mod);
    b = poly_normalize_monic(std::move(b), mod);
    while (!(b.size() == 1 && b[0] == 0)) {
        auto divres = poly_divmod_unit(a, b, mod);
        Poly r = divres.second;
        a = std::move(b);
        if (!(r.size() == 1 && r[0] == 0)) {
            b = poly_normalize_monic(std::move(r), mod);
        } else {
            b = {0};
        }
    }
    return a;
}

static mpz_class extract_linear_root(Poly p, const mpz_class &mod) {
    p = poly_normalize_monic(std::move(p), mod);
    if (p.size() != 2) throw std::runtime_error("polynomial is not linear");
    return mod_norm(-p[0], mod);
}

static Poly poly_mul_mod_xe(const Poly &a, const Poly &b, size_t e, const mpz_class &c1, const mpz_class &mod) {
    Poly out(e, 0);
#ifdef _OPENMP
    int threads = omp_get_max_threads();
    std::vector<Poly> locals((size_t)threads, Poly(e, 0));
    #pragma omp parallel
    {
        int tid = omp_get_thread_num();
        Poly &loc = locals[(size_t)tid];
        #pragma omp for schedule(static)
        for (long long i = 0; i < (long long)a.size(); ++i) {
            if (a[(size_t)i] == 0) continue;
            for (size_t j = 0; j < b.size(); ++j) {
                if (b[j] == 0) continue;
                mpz_class v = mod_mul(a[(size_t)i], b[j], mod);
                size_t idx = (size_t)i + j;
                if (idx < e) {
                    loc[idx] = mod_add(loc[idx], v, mod);
                } else {
                    loc[idx - e] = mod_add(loc[idx - e], mod_mul(v, c1, mod), mod);
                }
            }
        }
    }
    for (const auto &loc : locals) {
        for (size_t i = 0; i < e; ++i) out[i] = mod_add(out[i], loc[i], mod);
    }
#else
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] == 0) continue;
        for (size_t j = 0; j < b.size(); ++j) {
            if (b[j] == 0) continue;
            mpz_class v = mod_mul(a[i], b[j], mod);
            size_t idx = i + j;
            if (idx < e) {
                out[idx] = mod_add(out[idx], v, mod);
            } else {
                out[idx - e] = mod_add(out[idx - e], mod_mul(v, c1, mod), mod);
            }
        }
    }
#endif
    return out;
}

static std::vector<mpz_class> interpolate_monomial(const std::vector<mpz_class> &points, std::vector<mpz_class> values, const mpz_class &mod) {
    size_t n = points.size();
    for (size_t j = 1; j < n; ++j) {
        for (size_t i = n - 1; i >= j; --i) {
            mpz_class num = mod_sub(values[i], values[i - 1], mod);
            mpz_class den = mod_sub(points[i], points[i - j], mod);
            values[i] = mod_mul(num, mod_inv(den, mod), mod);
            if (i == j) break;
        }
    }

    std::vector<mpz_class> coeffs = {values[n - 1]};
    for (long long i = (long long)n - 2; i >= 0; --i) {
        std::vector<mpz_class> next(coeffs.size() + 1, 0);
        mpz_class negx = mod_norm(-points[(size_t)i], mod);
        for (size_t j = 0; j < coeffs.size(); ++j) {
            next[j] = mod_add(next[j], mod_mul(coeffs[j], negx, mod), mod);
            next[j + 1] = mod_add(next[j + 1], coeffs[j], mod);
        }
        next[0] = mod_add(next[0], values[(size_t)i], mod);
        coeffs.swap(next);
    }
    return coeffs;
}

static Poly eval_poly_paterson_stockmeyer(const std::vector<mpz_class> &coeffs, const Poly &point, size_t e, const mpz_class &c1, const mpz_class &mod) {
    size_t n = coeffs.size();
    size_t m = (size_t)std::sqrt((double)n) + 1;

    std::vector<Poly> powers(m, Poly(e, 0));
    powers[0][0] = 1;
    for (size_t i = 1; i < m; ++i) {
        powers[i] = poly_mul_mod_xe(powers[i - 1], point, e, c1, mod);
    }
    Poly q_poly = poly_mul_mod_xe(powers[m - 1], point, e, c1, mod);

    std::vector<Poly> blocks;
    for (size_t start = 0; start < n; start += m) {
        Poly block(e, 0);
        for (size_t j = 0; j < m && start + j < n; ++j) {
            if (coeffs[start + j] == 0) continue;
            for (size_t k = 0; k < e; ++k) {
                block[k] = mod_add(block[k], mod_mul(coeffs[start + j], powers[j][k], mod), mod);
            }
        }
        blocks.push_back(std::move(block));
    }

    Poly result(e, 0);
    for (long long i = (long long)blocks.size() - 1; i >= 0; --i) {
        result = poly_mul_mod_xe(result, q_poly, e, c1, mod);
        for (size_t k = 0; k < e; ++k) result[k] = mod_add(result[k], blocks[(size_t)i][k], mod);
    }
    return result;
}

static mpz_class resultant_unit(Poly p, Poly q, const mpz_class &mod) {
    mpz_class res = 1;
    while (true) {
        size_t n = q.size() - 1;
        if (n == 0) return mod_mul(res, mod_pow(q[0], p.size() - 1, mod), mod);
        auto divres = poly_divmod_unit(p, q, mod);
        Poly r = divres.second;
        if (r.size() == 1 && r[0] == 0) return 0;
        size_t m = p.size() - 1;
        size_t rd = r.size() - 1;
        mpz_class lc = q.back();
        if ((m * n) & 1) res = mod_norm(-res, mod);
        res = mod_mul(res, mod_pow(lc, m - rd, mod), mod);
        p.swap(q);
        q.swap(r);
    }
}

static Poly build_shifted_poly(const mpz_class &k, const mpz_class &c2, size_t e, const mpz_class &mod, const std::vector<mpz_class> &combs) {
    Poly p(e + 1, 0);
    for (size_t i = 0; i <= e; ++i) {
        p[i] = mod_mul(combs[i], mod_pow(k, e - i, mod), mod);
    }
    p[0] = mod_sub(p[0], c2, mod);
    return p;
}

struct Instance {
    mpz_class N, e, a, L, C1, C2;
};

static void parse_input(Instance &inst) {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        auto trim = [](std::string s) {
            s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
            s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
            return s;
        };
        key = trim(key);
        value = trim(value);
        int base = 10;
        if (value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
            value = value.substr(2);
            base = 16;
        }
        if (key == "N") inst.N.set_str(value, base);
        else if (key == "e") inst.e.set_str(value, base);
        else if (key == "a") inst.a.set_str(value, base);
        else if (key == "L") inst.L.set_str(value, base);
        else if (key == "C1") inst.C1.set_str(value, base);
        else if (key == "C2") inst.C2.set_str(value, base);
    }
}

int main() {
    Instance inst;
    parse_input(inst);
    size_t e = inst.e.get_ui();
    mpz_class mod = inst.N;
    bool timing = std::getenv("FAST_CORE_TIMING") != nullptr;
    auto t0 = std::chrono::steady_clock::now();

    std::vector<mpz_class> points_t(e + 1), points_k(e + 1);
    for (size_t i = 0; i <= e; ++i) {
        points_k[i] = mpz_class((unsigned long)(i + 1));
        points_t[i] = mod_pow(points_k[i], e, mod);
    }
    auto t1 = std::chrono::steady_clock::now();

    std::vector<mpz_class> combs(e + 1);
    for (size_t i = 0; i <= e; ++i) combs[i] = mpz_class((unsigned long)1);
    for (size_t i = 0; i <= e; ++i) {
        mpz_bin_uiui(combs[i].get_mpz_t(), e, i);
        combs[i] %= mod;
    }

    Poly qpoly(e + 1, 0);
    qpoly[0] = mod_norm(-inst.L, mod);
    qpoly[e] = 1;

    std::vector<mpz_class> values(e + 1);
    #pragma omp parallel for schedule(dynamic, 4)
    for (long long i = 0; i < (long long)points_k.size(); ++i) {
        Poly p = build_shifted_poly(points_k[(size_t)i], inst.C2, e, mod, combs);
        values[(size_t)i] = resultant_unit(std::move(p), qpoly, mod);
    }
    auto t2 = std::chrono::steady_clock::now();

    std::vector<mpz_class> coeffs = interpolate_monomial(points_t, values, mod);
    auto t3 = std::chrono::steady_clock::now();

    mpz_class ae = mod_pow(inst.a, e, mod);
    Poly point(e, 0);
    for (size_t i = 0; i < e; ++i) {
        mpz_class bin;
        mpz_bin_uiui(bin.get_mpz_t(), e, i);
        point[i] = mod_mul(ae, bin % mod, mod);
    }
    point[0] = mod_add(point[0], mod_mul(ae, inst.C1, mod), mod);

    Poly reduced = eval_poly_paterson_stockmeyer(coeffs, point, e, inst.C1, mod);
    auto t4 = std::chrono::steady_clock::now();

    Poly modulus(e + 1, 0);
    modulus[0] = mod_norm(-inst.C1, mod);
    modulus[e] = 1;

    Poly gx = poly_gcd_unit(modulus, reduced, mod);
    mpz_class s1 = extract_linear_root(gx, mod);
    auto t5 = std::chrono::steady_clock::now();

    mpz_class constant = mod_norm(inst.a * s1 + inst.a, mod);
    Poly ty1(e + 1, 0), ty2(e + 1, 0);
    ty1[0] = mod_norm(-inst.L, mod);
    ty1[e] = 1;
    for (size_t i = 0; i <= e; ++i) {
        mpz_class bin;
        mpz_bin_uiui(bin.get_mpz_t(), e, i);
        ty2[i] = mod_mul(bin % mod, mod_pow(constant, e - i, mod), mod);
    }
    ty2[0] = mod_sub(ty2[0], inst.C2, mod);

    Poly gy = poly_gcd_unit(ty1, ty2, mod);
    mpz_class t = extract_linear_root(gy, mod);
    mpz_class b = mod_norm(t + inst.a, mod);
    mpz_class s0 = mod_mul(mod_inv(inst.a, mod), mod_norm(s1 - b, mod), mod);
    auto t6 = std::chrono::steady_clock::now();

    std::cout << "s0=" << s0.get_str() << "\n";
    std::cout << "gcd_x_degree=" << (gx.size() - 1) << "\n";
    std::cout << "gcd_y_degree=" << (gy.size() - 1) << "\n";
    if (timing) {
        auto ms = [](auto a, auto b) {
            return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
        };
        std::cerr
            << "timing_ms choose_points=" << ms(t0, t1)
            << " eval=" << ms(t1, t2)
            << " interp=" << ms(t2, t3)
            << " subst=" << ms(t3, t4)
            << " gcdx=" << ms(t4, t5)
            << " gcdy=" << ms(t5, t6)
            << " total=" << ms(t0, t6)
            << "\n";
    }
    return 0;
}
