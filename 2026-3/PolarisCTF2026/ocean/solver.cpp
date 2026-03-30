#include <openssl/evp.h>
#include <openssl/md5.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <functional>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

using U64 = std::uint64_t;

U64 mask_for_bits(int n) {
    return n == 64 ? std::numeric_limits<U64>::max() : ((U64(1) << n) - 1);
}

int parity(U64 x) {
    return static_cast<int>(__builtin_popcountll(x) & 1U);
}

struct Stats {
    std::uint64_t nodes = 0;
    std::uint64_t contradictions = 0;
    std::uint64_t count_propagations = 0;
    std::uint64_t branch_choices = 0;
    std::uint64_t forced_runs = 0;
    std::uint64_t enum_calls = 0;
    std::uint64_t enum_candidates = 0;
    std::uint64_t pattern_relations = 0;
    std::uint64_t prefix_caps = 0;
    std::uint64_t pattern_splits = 0;
    std::uint64_t lookahead_prunes = 0;
    std::uint64_t beam_prunes = 0;
    std::uint64_t beam_kept = 0;
    int max_run = 0;
};

struct GF2System {
    int n = 0;
    U64 full_mask = 0;
    std::array<U64, 64> pivots{};
    U64 pivot_mask = 0;
    U64 rhs_mask = 0;
    int rank = 0;

    GF2System() = default;

    explicit GF2System(int bits) : n(bits), full_mask(mask_for_bits(bits)) {}

    std::pair<U64, int> reduce_row(U64 row) const {
        row &= full_mask;
        int value = 0;
        while (row) {
            int pivot = 63 - __builtin_clzll(row);
            if (((pivot_mask >> pivot) & 1ULL) == 0ULL) {
                break;
            }
            row ^= pivots[pivot];
            value ^= static_cast<int>((rhs_mask >> pivot) & 1ULL);
        }
        return {row, value};
    }

    std::optional<int> implied_value(U64 row) const {
        auto [reduced, value] = reduce_row(row);
        if (reduced == 0) {
            return value;
        }
        return std::nullopt;
    }

    bool add_equation(U64 row, int value) {
        auto [reduced, bias] = reduce_row(row);
        value ^= bias;
        if (reduced == 0) {
            return value == 0;
        }

        int pivot = 63 - __builtin_clzll(reduced);
        U64 bit = 1ULL << pivot;
        for (int other = 0; other < 64; ++other) {
            if (other == pivot) {
                continue;
            }
            if (((pivot_mask >> other) & 1ULL) == 0ULL) {
                continue;
            }
            if (((pivots[other] >> pivot) & 1ULL) == 0ULL) {
                continue;
            }
            pivots[other] ^= reduced;
            rhs_mask ^= (static_cast<U64>(value) << other);
        }

        pivots[pivot] = reduced;
        pivot_mask |= bit;
        rhs_mask &= ~bit;
        rhs_mask |= static_cast<U64>(value) << pivot;
        ++rank;
        return true;
    }

    U64 solution_from_free_mask(U64 free_mask_bits) const {
        U64 solution = 0;
        int free_index = 0;
        for (int bit = 0; bit < n; ++bit) {
            if (((pivot_mask >> bit) & 1ULL) != 0ULL) {
                continue;
            }
            if (((free_mask_bits >> free_index) & 1ULL) != 0ULL) {
                solution |= 1ULL << bit;
            }
            ++free_index;
        }

        for (int pivot = 0; pivot < n; ++pivot) {
            if (((pivot_mask >> pivot) & 1ULL) == 0ULL) {
                continue;
            }
            U64 row = pivots[pivot];
            U64 others = row ^ (1ULL << pivot);
            int bit_value = static_cast<int>((rhs_mask >> pivot) & 1ULL) ^ parity(others & solution);
            if (bit_value != 0) {
                solution |= 1ULL << pivot;
            }
        }
        return solution;
    }

    std::string signature() const {
        std::string out;
        out.reserve(64 * 18);
        out.append(reinterpret_cast<const char*>(&pivot_mask), sizeof(pivot_mask));
        out.append(reinterpret_cast<const char*>(&rhs_mask), sizeof(rhs_mask));
        for (int i = 0; i < n; ++i) {
            if (((pivot_mask >> i) & 1ULL) == 0ULL) {
                continue;
            }
            out.append(reinterpret_cast<const char*>(&pivots[i]), sizeof(U64));
        }
        return out;
    }
};

struct Run {
    int bit = 0;
    int start = 0;
    int end = 0;
    int length = 0;
    U64 parity_row = 0;
    std::vector<U64> time_rows;
    bool forced_first = false;
    bool last_of_value_run = false;
};

struct Option {
    GF2System system;
    int moved_after = 0;
};

struct State {
    int moved_before = 0;
    GF2System system;
};

struct Config {
    int n = 0;
    U64 mask1 = 0;
    U64 mask2 = 0;
    std::string outputs;
    std::vector<unsigned char> enc;
    int chunk_len = 6;
    int enum_threshold = 5;
    int beam_depth = 7;
    int beam_width = 8192;
    int per_moved = 128;
};

struct LFSR {
    int n = 0;
    U64 state = 0;
    U64 mask = 0;
    U64 full_mask = 0;

    int step() {
        int feedback = parity(state & mask);
        state = ((state << 1) & full_mask) | static_cast<U64>(feedback);
        return static_cast<int>(state & 1ULL);
    }

    int output() const {
        return static_cast<int>(state & 1ULL);
    }
};

std::vector<U64> output_rows(int n, U64 mask, int steps) {
    std::vector<U64> rows(steps + 1, 0);
    for (int basis_index = 0; basis_index < n; ++basis_index) {
        U64 basis_seed = 1ULL << (n - 1 - basis_index);
        LFSR lfsr{n, basis_seed, mask, mask_for_bits(n)};
        rows[0] |= static_cast<U64>(lfsr.output()) << (n - 1 - basis_index);
        for (int step = 1; step <= steps; ++step) {
            int bit = lfsr.step();
            rows[step] |= static_cast<U64>(bit) << (n - 1 - basis_index);
        }
    }
    return rows;
}

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    if (hex == "-" || hex.empty()) {
        return {};
    }
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int byte = 0;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byte;
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}

bool decrypt_and_check(const std::vector<unsigned char>& enc, U64 seed) {
    if (enc.empty()) {
        return true;
    }

    unsigned char key[MD5_DIGEST_LENGTH];
    std::string seed_string = std::to_string(seed);
    MD5(reinterpret_cast<const unsigned char*>(seed_string.data()), seed_string.size(), key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return false;
    }

    bool ok = false;
    std::vector<unsigned char> plaintext(enc.size() + 16);
    int out_len1 = 0;
    int out_len2 = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 1) == 1 &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &out_len1, enc.data(), static_cast<int>(enc.size())) == 1 &&
        EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2) == 1) {
        plaintext.resize(out_len1 + out_len2);
        if (plaintext.size() == 42 &&
            std::equal(plaintext.begin(), plaintext.begin() + 9, "fakeflag{") &&
            plaintext.back() == '}') {
            ok = true;
            for (std::size_t i = 9; i + 1 < plaintext.size(); ++i) {
                unsigned char c = plaintext[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                    ok = false;
                    break;
                }
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

class Solver {
  public:
    explicit Solver(Config cfg)
        : cfg_(std::move(cfg)),
          rows1_(output_rows(cfg_.n, cfg_.mask1, cfg_.n)),
          rows2_(output_rows(cfg_.n, cfg_.mask2, cfg_.n)) {
        runs_ = build_runs();
        depth_times_.push_back(0);
        for (const auto& run : runs_) {
            depth_times_.push_back(run.end + 1);
        }
        auto [min_prefix, max_prefix] = build_move_prefix_bounds();
        min_prefix_moves_ = std::move(min_prefix);
        max_prefix_moves_ = std::move(max_prefix);
        min_suffix_moves_ = build_move_suffix_bounds();
    }

    std::optional<U64> solve_beam_then_dfs() {
        auto beam = build_beam_frontier(cfg_.beam_depth, cfg_.beam_width, cfg_.per_moved);
        if (beam.empty()) {
            return std::nullopt;
        }

        std::sort(beam.begin(), beam.end(), [&](const State& lhs, const State& rhs) {
            auto lhs_key = std::make_tuple(lhs.system.rank, rough_option_count(cfg_.beam_depth, lhs.moved_before, lhs.system),
                                           lhs.moved_before);
            auto rhs_key = std::make_tuple(rhs.system.rank, rough_option_count(cfg_.beam_depth, rhs.moved_before, rhs.system),
                                           rhs.moved_before);
            return lhs_key < rhs_key;
        });

        for (const auto& state : beam) {
            auto candidate = search(cfg_.beam_depth, state.moved_before, state.system, cfg_.enum_threshold);
            if (candidate.has_value()) {
                return candidate;
            }
        }
        return std::nullopt;
    }

    bool verify_seed(U64 seed) const {
        int moved = 0;
        for (int t = 0; t < cfg_.n; ++t) {
            moved += parity(rows1_[t + 1] & seed);
            int out = parity(rows2_[moved] & seed);
            if (out != (cfg_.outputs[t] - '0')) {
                return false;
            }
        }
        return true;
    }

    bool accept_seed(U64 seed) const {
        return verify_seed(seed) && decrypt_and_check(cfg_.enc, seed);
    }

    const Stats& stats() const { return stats_; }

  private:
    Config cfg_;
    Stats stats_;
    std::vector<U64> rows1_;
    std::vector<U64> rows2_;
    std::vector<Run> runs_;
    std::vector<int> depth_times_;
    std::vector<int> min_prefix_moves_;
    std::vector<int> max_prefix_moves_;
    std::vector<int> min_suffix_moves_;
    std::array<std::array<std::vector<U64>, 65>, 65> pattern_cache_{};
    std::array<std::array<bool, 65>, 65> pattern_ready_{};

    std::vector<Run> build_runs() const {
        std::vector<std::tuple<int, int, int>> original_runs;
        int start = 0;
        for (int idx = 1; idx <= cfg_.n; ++idx) {
            if (idx == cfg_.n || cfg_.outputs[idx] != cfg_.outputs[start]) {
                original_runs.emplace_back(cfg_.outputs[start] - '0', start, idx - 1);
                start = idx;
            }
        }

        std::vector<Run> runs;
        for (std::size_t run_index = 0; run_index < original_runs.size(); ++run_index) {
            auto [bit, run_start, run_end] = original_runs[run_index];
            int chunk_len = cfg_.chunk_len > 0 ? cfg_.chunk_len : (run_end - run_start + 1);
            for (int chunk_start = run_start; chunk_start <= run_end; chunk_start += chunk_len) {
                int chunk_end = std::min(chunk_start + chunk_len - 1, run_end);
                Run run;
                run.bit = bit;
                run.start = chunk_start;
                run.end = chunk_end;
                run.length = chunk_end - chunk_start + 1;
                run.forced_first = run_index > 0 && chunk_start == run_start;
                run.last_of_value_run = chunk_end == run_end;
                run.parity_row = 0;
                for (int t = chunk_start; t <= chunk_end; ++t) {
                    run.time_rows.push_back(rows1_[t + 1]);
                    run.parity_row ^= rows1_[t + 1];
                }
                runs.push_back(std::move(run));
            }
        }
        return runs;
    }

    std::pair<std::vector<int>, std::vector<int>> build_move_prefix_bounds() const {
        std::vector<int> min_prefix{0};
        std::vector<int> max_prefix{0};
        int min_total = 0;
        int max_total = 0;
        for (std::size_t idx = 0; idx < runs_.size(); ++idx) {
            if (idx > 0 && runs_[idx].forced_first) {
                ++min_total;
            }
            max_total += runs_[idx].length;
            min_prefix.push_back(min_total);
            max_prefix.push_back(max_total);
        }
        return {min_prefix, max_prefix};
    }

    std::vector<int> build_move_suffix_bounds() const {
        std::vector<int> suffix(runs_.size() + 1, 0);
        int total = 0;
        for (int idx = static_cast<int>(runs_.size()) - 1; idx >= 0; --idx) {
            if (idx > 0 && runs_[idx].forced_first) {
                ++total;
            }
            suffix[idx] = total;
        }
        return suffix;
    }

    const std::vector<U64>& patterns_of_weight(int length, int weight) {
        if (!pattern_ready_[length][weight]) {
            std::vector<U64> patterns;
            std::function<void(int, int, U64)> dfs = [&](int pos, int left, U64 pattern) {
                if (left == 0) {
                    patterns.push_back(pattern);
                    return;
                }
                if (pos == length) {
                    return;
                }
                if (length - pos > left) {
                    dfs(pos + 1, left, pattern);
                }
                dfs(pos + 1, left - 1, pattern | (1ULL << pos));
            };
            dfs(0, weight, 0);
            pattern_cache_[length][weight] = std::move(patterns);
            pattern_ready_[length][weight] = true;
        }
        return pattern_cache_[length][weight];
    }

    std::vector<U64> surviving_patterns(const GF2System& system, const std::vector<U64>& time_rows, int required_ones) {
        std::vector<std::optional<int>> implied;
        implied.reserve(time_rows.size());
        for (U64 row : time_rows) {
            implied.push_back(system.implied_value(row));
        }

        std::vector<U64> survivors;
        for (U64 pattern : patterns_of_weight(static_cast<int>(time_rows.size()), required_ones)) {
            bool consistent = true;
            GF2System tmp = system;
            for (std::size_t idx = 0; idx < time_rows.size(); ++idx) {
                int bit = static_cast<int>((pattern >> idx) & 1ULL);
                if (implied[idx].has_value()) {
                    if (implied[idx].value() != bit) {
                        consistent = false;
                        break;
                    }
                } else if (!tmp.add_equation(time_rows[idx], bit)) {
                    consistent = false;
                    break;
                }
            }
            if (consistent) {
                survivors.push_back(pattern);
            }
        }
        return survivors;
    }

    int max_prefix_count(const GF2System& system, int bit, int start_count, int max_count) {
        GF2System probe = system;
        int last_ok = start_count - 1;
        for (int count = start_count; count <= max_count; ++count) {
            if (!probe.add_equation(rows2_[count], bit)) {
                break;
            }
            last_ok = count;
        }
        return last_ok;
    }

    std::pair<int, int> count_bounds(const GF2System& system, const std::vector<U64>& time_rows) const {
        int ones = 0;
        int unknowns = 0;
        for (U64 row : time_rows) {
            auto implied = system.implied_value(row);
            if (implied.has_value()) {
                ones += implied.value();
            } else {
                ++unknowns;
            }
        }
        return {ones, unknowns};
    }

    bool propagate_run_count(GF2System& system, const std::vector<U64>& time_rows, int required_ones) {
        while (true) {
            int ones = 0;
            std::vector<U64> unknown_rows;
            for (U64 row : time_rows) {
                auto implied = system.implied_value(row);
                if (implied.has_value()) {
                    ones += implied.value();
                } else {
                    unknown_rows.push_back(row);
                }
            }

            if (required_ones < ones || required_ones > ones + static_cast<int>(unknown_rows.size())) {
                ++stats_.contradictions;
                return false;
            }

            if (unknown_rows.empty()) {
                return ones == required_ones;
            }

            if (required_ones == ones) {
                stats_.count_propagations += unknown_rows.size();
                for (U64 row : unknown_rows) {
                    if (!system.add_equation(row, 0)) {
                        ++stats_.contradictions;
                        return false;
                    }
                }
                continue;
            }

            if (required_ones == ones + static_cast<int>(unknown_rows.size())) {
                stats_.count_propagations += unknown_rows.size();
                for (U64 row : unknown_rows) {
                    if (!system.add_equation(row, 1)) {
                        ++stats_.contradictions;
                        return false;
                    }
                }
                continue;
            }

            if (static_cast<int>(time_rows.size()) <= 6) {
                auto survivors = surviving_patterns(system, time_rows, required_ones);
                if (survivors.empty()) {
                    ++stats_.contradictions;
                    return false;
                }

                bool changed = false;
                U64 base = survivors.front();
                U64 limit = 1ULL << time_rows.size();
                for (U64 mask = 1; mask < limit; ++mask) {
                    int value = parity(base & mask);
                    bool same = true;
                    for (std::size_t idx = 1; idx < survivors.size(); ++idx) {
                        if (parity(survivors[idx] & mask) != value) {
                            same = false;
                            break;
                        }
                    }
                    if (!same) {
                        continue;
                    }
                    U64 row = 0;
                    for (std::size_t idx = 0; idx < time_rows.size(); ++idx) {
                        if (((mask >> idx) & 1ULL) != 0ULL) {
                            row ^= time_rows[idx];
                        }
                    }
                    int before = system.rank;
                    if (!system.add_equation(row, value)) {
                        ++stats_.contradictions;
                        return false;
                    }
                    if (system.rank > before) {
                        ++stats_.pattern_relations;
                        changed = true;
                    }
                }
                if (changed) {
                    continue;
                }
            }

            return true;
        }
    }

    std::vector<GF2System> split_small_pattern_family(const GF2System& system, const std::vector<U64>& time_rows, int required_ones) {
        if (static_cast<int>(time_rows.size()) > 6) {
            return {system};
        }
        auto survivors = surviving_patterns(system, time_rows, required_ones);
        if (survivors.size() <= 1 || survivors.size() > 6) {
            return {system};
        }

        std::vector<GF2System> out;
        std::unordered_set<std::string> seen;
        for (U64 pattern : survivors) {
            GF2System next = system;
            bool ok = true;
            for (std::size_t idx = 0; idx < time_rows.size(); ++idx) {
                int bit = static_cast<int>((pattern >> idx) & 1ULL);
                if (!next.add_equation(time_rows[idx], bit)) {
                    ok = false;
                    break;
                }
            }
            if (!ok) {
                continue;
            }
            std::string signature = next.signature();
            if (seen.insert(signature).second) {
                out.push_back(std::move(next));
            }
        }
        if (out.size() > 1) {
            stats_.pattern_splits += out.size();
            return out;
        }
        return {system};
    }

    std::optional<GF2System> extend_first_run(const GF2System& system, int run_index, const Run& run, int first_update, int moved_after) {
        GF2System next = system;
        if (!next.add_equation(rows1_[1], first_update)) {
            ++stats_.contradictions;
            return std::nullopt;
        }
        if (!next.add_equation(run.parity_row, moved_after & 1)) {
            ++stats_.contradictions;
            return std::nullopt;
        }

        int start_count = first_update;
        for (int count = start_count; count <= moved_after; ++count) {
            if (!next.add_equation(rows2_[count], run.bit)) {
                ++stats_.contradictions;
                return std::nullopt;
            }
        }
        if (run.last_of_value_run && run_index + 1 < static_cast<int>(runs_.size())) {
            if (!next.add_equation(rows2_[moved_after + 1], runs_[run_index + 1].bit)) {
                ++stats_.contradictions;
                return std::nullopt;
            }
        }

        if (first_update == 0 && moved_after == 0) {
            for (U64 row : run.time_rows) {
                if (!next.add_equation(row, 0)) {
                    ++stats_.contradictions;
                    return std::nullopt;
                }
            }
        } else if (first_update == 0 && moved_after == run.length - 1) {
            if (!next.add_equation(run.time_rows[0], 0)) {
                ++stats_.contradictions;
                return std::nullopt;
            }
            for (std::size_t idx = 1; idx < run.time_rows.size(); ++idx) {
                if (!next.add_equation(run.time_rows[idx], 1)) {
                    ++stats_.contradictions;
                    return std::nullopt;
                }
            }
        } else if (first_update == 1 && moved_after == 1) {
            if (!next.add_equation(run.time_rows[0], 1)) {
                ++stats_.contradictions;
                return std::nullopt;
            }
            for (std::size_t idx = 1; idx < run.time_rows.size(); ++idx) {
                if (!next.add_equation(run.time_rows[idx], 0)) {
                    ++stats_.contradictions;
                    return std::nullopt;
                }
            }
        } else if (first_update == 1 && moved_after == run.length) {
            for (U64 row : run.time_rows) {
                if (!next.add_equation(row, 1)) {
                    ++stats_.contradictions;
                    return std::nullopt;
                }
            }
        }

        if (!propagate_run_count(next, run.time_rows, moved_after)) {
            return std::nullopt;
        }
        return next;
    }

    std::optional<GF2System> extend_later_run(const GF2System& system, int run_index, const Run& run, int moved_before, int moved_after) {
        GF2System next = system;
        int delta = moved_after - moved_before;
        if (!next.add_equation(run.parity_row, delta & 1)) {
            ++stats_.contradictions;
            return std::nullopt;
        }
        for (int count = moved_before + 1; count <= moved_after; ++count) {
            if (!next.add_equation(rows2_[count], run.bit)) {
                ++stats_.contradictions;
                return std::nullopt;
            }
        }
        if (run.last_of_value_run && run_index + 1 < static_cast<int>(runs_.size())) {
            if (!next.add_equation(rows2_[moved_after + 1], runs_[run_index + 1].bit)) {
                ++stats_.contradictions;
                return std::nullopt;
            }
        }

        if (run.forced_first && delta == 1) {
            for (std::size_t idx = 1; idx < run.time_rows.size(); ++idx) {
                if (!next.add_equation(run.time_rows[idx], 0)) {
                    ++stats_.contradictions;
                    return std::nullopt;
                }
            }
        } else if (!run.forced_first && delta == 0) {
            for (U64 row : run.time_rows) {
                if (!next.add_equation(row, 0)) {
                    ++stats_.contradictions;
                    return std::nullopt;
                }
            }
        } else if (delta == run.length) {
            for (U64 row : run.time_rows) {
                if (!next.add_equation(row, 1)) {
                    ++stats_.contradictions;
                    return std::nullopt;
                }
            }
        }

        if (!propagate_run_count(next, run.time_rows, delta)) {
            return std::nullopt;
        }
        return next;
    }

    int rough_option_count(int run_index, int moved_before, const GF2System& system) {
        if (run_index >= static_cast<int>(runs_.size())) {
            return 1;
        }
        const Run& run = runs_[run_index];
        int remaining_min = min_suffix_moves_[run_index + 1];
        auto [known_ones, unknowns] = count_bounds(system, run.time_rows);
        auto parity_implied = system.implied_value(run.parity_row);
        int total = 0;

        if (run_index == 0) {
            auto first_implied = system.implied_value(rows1_[1]);
            std::array<int, 2> first_values{0, 1};
            int value_count = first_implied.has_value() ? 1 : 2;
            if (first_implied.has_value()) {
                first_values[0] = first_implied.value();
            }
            for (int idx = 0; idx < value_count; ++idx) {
                int first_update = first_values[idx];
                int min_after = first_update;
                int max_after = first_update == 0 ? run.length - 1 : run.length;
                max_after = std::min(max_after, max_prefix_count(system, run.bit, first_update, max_after));
                for (int moved_after = min_after; moved_after <= max_after; ++moved_after) {
                    if (moved_after < known_ones || moved_after > known_ones + unknowns) {
                        continue;
                    }
                    if (parity_implied.has_value() && ((moved_after & 1) != parity_implied.value())) {
                        continue;
                    }
                    if (moved_after + remaining_min > cfg_.n) {
                        continue;
                    }
                    ++total;
                }
            }
            return total;
        }

        int min_after = run.forced_first ? moved_before + 1 : moved_before;
        int max_after = moved_before + run.length;
        max_after = std::min(max_after, max_prefix_count(system, run.bit, moved_before + 1, max_after));
        for (int moved_after = min_after; moved_after <= max_after; ++moved_after) {
            int delta = moved_after - moved_before;
            if (delta < known_ones || delta > known_ones + unknowns) {
                continue;
            }
            if (parity_implied.has_value() && ((delta & 1) != parity_implied.value())) {
                continue;
            }
            if (moved_after + remaining_min > cfg_.n) {
                continue;
            }
            ++total;
        }
        return total;
    }

    std::vector<Option> order_options(int run_index, std::vector<Option> options) {
        if (run_index + 1 >= static_cast<int>(runs_.size())) {
            std::sort(options.begin(), options.end(), [&](const Option& lhs, const Option& rhs) {
                return lhs.system.rank > rhs.system.rank;
            });
            return options;
        }
        struct ScoredOption {
            int future = 0;
            int rank = 0;
            Option option;
        };
        std::vector<ScoredOption> scored;
        scored.reserve(options.size());
        for (auto& option : options) {
            int future = rough_option_count(run_index + 1, option.moved_after, option.system);
            if (future == 0) {
                ++stats_.lookahead_prunes;
                continue;
            }
            scored.push_back({future, option.system.rank, std::move(option)});
        }
        std::sort(scored.begin(), scored.end(), [&](const ScoredOption& lhs, const ScoredOption& rhs) {
            return std::tie(lhs.future, lhs.rank, lhs.option.moved_after) <
                   std::tie(rhs.future, rhs.rank, rhs.option.moved_after);
        });
        std::vector<Option> out;
        out.reserve(scored.size());
        for (auto& item : scored) {
            out.push_back(std::move(item.option));
        }
        return out;
    }

    std::vector<Option> generate_options(int run_index, int moved_before, const GF2System& system) {
        const Run& run = runs_[run_index];
        int remaining_min = min_suffix_moves_[run_index + 1];
        auto [known_ones, unknowns] = count_bounds(system, run.time_rows);
        auto parity_implied = system.implied_value(run.parity_row);
        std::vector<Option> options;

        if (run_index == 0) {
            auto first_implied = system.implied_value(rows1_[1]);
            std::array<int, 2> first_values{0, 1};
            int value_count = first_implied.has_value() ? 1 : 2;
            if (first_implied.has_value()) {
                first_values[0] = first_implied.value();
            }
            for (int idx = 0; idx < value_count; ++idx) {
                int first_update = first_values[idx];
                int min_after = first_update;
                int max_after = first_update == 0 ? run.length - 1 : run.length;
                int capped_after = max_prefix_count(system, run.bit, first_update, max_after);
                if (capped_after < max_after) {
                    ++stats_.prefix_caps;
                }
                max_after = std::min(max_after, capped_after);
                for (int moved_after = min_after; moved_after <= max_after; ++moved_after) {
                    if (moved_after < known_ones || moved_after > known_ones + unknowns) {
                        continue;
                    }
                    if (parity_implied.has_value() && ((moved_after & 1) != parity_implied.value())) {
                        continue;
                    }
                    if (moved_after + remaining_min > cfg_.n) {
                        continue;
                    }
                    auto next_system = extend_first_run(system, run_index, run, first_update, moved_after);
                    if (!next_system.has_value()) {
                        continue;
                    }
                    for (auto& refined : split_small_pattern_family(next_system.value(), run.time_rows, moved_after)) {
                        options.push_back({std::move(refined), moved_after});
                    }
                }
            }
            return options;
        }

        int min_after = run.forced_first ? moved_before + 1 : moved_before;
        int max_after = moved_before + run.length;
        int capped_after = max_prefix_count(system, run.bit, moved_before + 1, max_after);
        if (capped_after < max_after) {
            ++stats_.prefix_caps;
        }
        max_after = std::min(max_after, capped_after);
        for (int moved_after = min_after; moved_after <= max_after; ++moved_after) {
            int delta = moved_after - moved_before;
            if (delta < known_ones || delta > known_ones + unknowns) {
                continue;
            }
            if (parity_implied.has_value() && ((delta & 1) != parity_implied.value())) {
                continue;
            }
            if (moved_after + remaining_min > cfg_.n) {
                continue;
            }
            auto next_system = extend_later_run(system, run_index, run, moved_before, moved_after);
            if (!next_system.has_value()) {
                continue;
            }
            for (auto& refined : split_small_pattern_family(next_system.value(), run.time_rows, delta)) {
                options.push_back({std::move(refined), moved_after});
            }
        }
        return options;
    }

    std::vector<State> select_beam_states(int run_index, std::vector<State> states, int beam_width, int per_moved) {
        std::vector<State> unique;
        unique.reserve(states.size());
        std::unordered_set<std::string> seen;
        for (auto& state : states) {
            std::string key = std::to_string(state.moved_before);
            key.push_back('\0');
            key += state.system.signature();
            if (seen.insert(key).second) {
                unique.push_back(std::move(state));
            }
        }

        std::sort(unique.begin(), unique.end(), [&](const State& lhs, const State& rhs) {
            auto lhs_key = std::make_tuple(rough_option_count(run_index, lhs.moved_before, lhs.system),
                                           std::abs(2 * lhs.moved_before - depth_times_[run_index]),
                                           lhs.system.rank,
                                           cfg_.n - lhs.system.rank,
                                           lhs.moved_before);
            auto rhs_key = std::make_tuple(rough_option_count(run_index, rhs.moved_before, rhs.system),
                                           std::abs(2 * rhs.moved_before - depth_times_[run_index]),
                                           rhs.system.rank,
                                           cfg_.n - rhs.system.rank,
                                           rhs.moved_before);
            return lhs_key < rhs_key;
        });

        std::vector<State> selected;
        selected.reserve(std::min<int>(beam_width, unique.size()));
        std::vector<int> bucket_count(cfg_.n + 1, 0);
        int pruned = 0;
        for (auto& state : unique) {
            int moved_before = state.moved_before;
            if (moved_before < min_prefix_moves_[run_index] || moved_before > max_prefix_moves_[run_index]) {
                ++pruned;
                continue;
            }
            if (moved_before + min_suffix_moves_[run_index] > cfg_.n) {
                ++pruned;
                continue;
            }
            if (bucket_count[moved_before] >= per_moved) {
                ++pruned;
                continue;
            }
            selected.push_back(std::move(state));
            ++bucket_count[moved_before];
            if (static_cast<int>(selected.size()) >= beam_width) {
                break;
            }
        }
        stats_.beam_kept += selected.size();
        stats_.beam_prunes += pruned + std::max<int>(0, static_cast<int>(unique.size()) - static_cast<int>(selected.size()) - pruned);
        return selected;
    }

    std::vector<State> build_beam_frontier(int beam_depth, int beam_width, int per_moved) {
        GF2System system(cfg_.n);
        for (const auto& run : runs_) {
            if (!run.forced_first) {
                continue;
            }
            if (!system.add_equation(rows1_[run.start + 1], 1)) {
                ++stats_.contradictions;
                return {};
            }
        }

        std::vector<State> beam{{0, system}};
        int depth = std::min<int>(beam_depth, runs_.size());
        for (int run_index = 0; run_index < depth; ++run_index) {
            std::vector<State> next_states;
            for (const auto& state : beam) {
                auto options = generate_options(run_index, state.moved_before, state.system);
                if (options.empty()) {
                    ++stats_.contradictions;
                    continue;
                }
                if (options.size() == 1) {
                    ++stats_.forced_runs;
                } else {
                    stats_.branch_choices += options.size();
                    options = order_options(run_index, std::move(options));
                }
                for (auto& option : options) {
                    next_states.push_back({option.moved_after, std::move(option.system)});
                }
            }

            if (next_states.empty()) {
                return {};
            }
            beam = select_beam_states(run_index + 1, std::move(next_states), beam_width, per_moved);
            if (beam.empty()) {
                return {};
            }
        }
        return beam;
    }

    std::optional<U64> enumerate_and_verify(const GF2System& system, int enum_threshold) {
        int free_dim = cfg_.n - system.rank;
        if (free_dim > enum_threshold) {
            return std::nullopt;
        }
        ++stats_.enum_calls;
        U64 total = free_dim == 64 ? 0 : (1ULL << free_dim);
        stats_.enum_candidates += total;
        for (U64 mask = 0; mask < total; ++mask) {
            U64 candidate = system.solution_from_free_mask(mask);
            if (accept_seed(candidate)) {
                return candidate;
            }
        }
        ++stats_.contradictions;
        return std::nullopt;
    }

    std::optional<U64> search(int run_index, int moved_before, const GF2System& system, int enum_threshold) {
        GF2System current = system;
        int current_run = run_index;
        int current_moved = moved_before;
        while (true) {
            ++stats_.nodes;
            stats_.max_run = std::max(stats_.max_run, current_run);

            if (current.rank == cfg_.n) {
                U64 candidate = current.solution_from_free_mask(0);
                if (accept_seed(candidate)) {
                    return candidate;
                }
                ++stats_.contradictions;
                return std::nullopt;
            }

            if (current_run == static_cast<int>(runs_.size())) {
                return enumerate_and_verify(current, std::max(enum_threshold, 22));
            }

            int free_dim = cfg_.n - current.rank;
            if (free_dim <= enum_threshold) {
                return enumerate_and_verify(current, enum_threshold);
            }

            auto options = generate_options(current_run, current_moved, current);
            if (options.empty()) {
                ++stats_.contradictions;
                return std::nullopt;
            }

            if (options.size() == 1) {
                ++stats_.forced_runs;
                current = std::move(options[0].system);
                current_moved = options[0].moved_after;
                ++current_run;
                continue;
            }

            stats_.branch_choices += options.size();
            options = order_options(current_run, std::move(options));
            for (auto& option : options) {
                auto candidate = search(current_run + 1, option.moved_after, option.system, enum_threshold);
                if (candidate.has_value()) {
                    return candidate;
                }
            }
            return std::nullopt;
        }
    }
};

Config read_config() {
    Config cfg;
    std::string enc_hex;
    std::cin >> cfg.n;
    std::cin >> cfg.mask1;
    std::cin >> cfg.mask2;
    std::cin >> cfg.outputs;
    std::cin >> enc_hex;
    std::cin >> cfg.chunk_len;
    std::cin >> cfg.enum_threshold;
    std::cin >> cfg.beam_depth;
    std::cin >> cfg.beam_width;
    std::cin >> cfg.per_moved;
    cfg.enc = hex_to_bytes(enc_hex);
    return cfg;
}

}  // namespace

int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    Config cfg = read_config();
    Solver solver(cfg);
    auto seed = solver.solve_beam_then_dfs();
    const Stats& stats = solver.stats();

    if (seed.has_value()) {
        std::cout << "status=ok\n";
        std::cout << "seed=" << seed.value() << "\n";
    } else {
        std::cout << "status=none\n";
    }
    std::cout << "nodes=" << stats.nodes << "\n";
    std::cout << "contradictions=" << stats.contradictions << "\n";
    std::cout << "branch_choices=" << stats.branch_choices << "\n";
    std::cout << "forced_runs=" << stats.forced_runs << "\n";
    std::cout << "enum_candidates=" << stats.enum_candidates << "\n";
    std::cout << "pattern_relations=" << stats.pattern_relations << "\n";
    std::cout << "prefix_caps=" << stats.prefix_caps << "\n";
    std::cout << "pattern_splits=" << stats.pattern_splits << "\n";
    std::cout << "lookahead_prunes=" << stats.lookahead_prunes << "\n";
    std::cout << "beam_kept=" << stats.beam_kept << "\n";
    std::cout << "beam_prunes=" << stats.beam_prunes << "\n";
    std::cout << "max_run=" << stats.max_run << "\n";
    return 0;
}
