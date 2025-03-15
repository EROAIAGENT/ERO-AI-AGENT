// core/math/MatrixOps.h
#pragma once
#include <immintrin.h>
#include <vector>
#include <stdexcept>
#include <cmath>
#include <type_traits>
#include <execution>
#include <algorithm>

namespace phasma::math {

template<typename T>
concept FloatingPoint = std::is_floating_point_v<T>;

template<FloatingPoint T>
class Matrix {
private:
    size_t rows_;
    size_t cols_;
    size_t aligned_cols_;
    T* data_;
    bool owns_memory_;

    // Memory alignment for SIMD (64-byte for AVX512)
    static constexpr size_t SIMD_ALIGNMENT = 64;
    
    // Tile size for cache optimization
    static constexpr size_t TILE_SIZE = 64 / sizeof(T);

public:
    // Constructors and memory management
    Matrix(size_t rows, size_t cols) 
        : rows_(rows), cols_(cols), 
          aligned_cols_((cols + TILE_SIZE - 1) & ~(TILE_SIZE - 1)),
          data_(static_cast<T*>(_mm_malloc(rows * aligned_cols_ * sizeof(T), SIMD_ALIGNMENT))),
          owns_memory_(true) {}
    
    Matrix(T* data, size_t rows, size_t cols, size_t stride = 0)
        : rows_(rows), cols_(cols),
          aligned_cols_(stride ? stride : cols),
          data_(data), owns_memory_(false) {}
    
    ~Matrix() {
        if (owns_memory_ && data_) {
            _mm_free(data_);
        }
    }

    // Accessors and basic operations
    T& operator()(size_t row, size_t col) { 
        return data_[row * aligned_cols_ + col];
    }
    
    const T& operator()(size_t row, size_t col) const { 
        return data_[row * aligned_cols_ + col];
    }

    size_t rows() const { return rows_; }
    size_t cols() const { return cols_; }
    size_t stride() const { return aligned_cols_; }
    T* ptr() { return data_; }

    // Core matrix operations
    static Matrix multiply(const Matrix& a, const Matrix& b, bool parallel = true) {
        if (a.cols() != b.rows()) {
            throw std::invalid_argument("Matrix dimensions mismatch");
        }
        
        Matrix result(a.rows(), b.cols());
        
        if constexpr (std::is_same_v<T, float>) {
            avx512_matrix_multiply(a, b, result);
        } else if constexpr (std::is_same_v<T, double>) {
            avx2_matrix_multiply(a, b, result);
        } else {
            generic_matrix_multiply(a, b, result, parallel);
        }
        
        return result;
    }

    static Matrix transpose(const Matrix& input) {
        Matrix result(input.cols(), input.rows());
        
        #pragma omp parallel for collapse(2)
        for (size_t i = 0; i < input.rows(); ++i) {
            for (size_t j = 0; j < input.cols(); ++j) {
                result(j, i) = input(i, j);
            }
        }
        return result;
    }

    static void lu_decomposition(const Matrix& input, Matrix& L, Matrix& U) {
        if (input.rows() != input.cols()) {
            throw std::invalid_argument("LU decomposition requires square matrix");
        }
        
        const size_t n = input.rows();
        L = Matrix<T>::identity(n);
        U = input;

        for (size_t k = 0; k < n; ++k) {
            if (std::abs(U(k, k)) < 1e-12) {
                throw std::runtime_error("Matrix is singular");
            }
            
            for (size_t i = k+1; i < n; ++i) {
                L(i, k) = U(i, k) / U(k, k);
                for (size_t j = k; j < n; ++j) {
                    U(i, j) -= L(i, k) * U(k, j);
                }
            }
        }
    }

    // Advanced numerical methods
    static Matrix inverse(const Matrix& input) {
        Matrix LU(input.rows(), input.cols());
        Matrix L, U;
        lu_decomposition(input, L, U);
        return solve_identity(L, U);
    }

    static Matrix solve(const Matrix& A, const Matrix& b) {
        Matrix L, U;
        lu_decomposition(A, L, U);
        return solve_forward_substitution(L, solve_backward_substitution(U, b));
    }

    // Utility functions
    static Matrix identity(size_t n) {
        Matrix result(n, n);
        #pragma omp parallel for
        for (size_t i = 0; i < n; ++i) {
            for (size_t j = 0; j < n; ++j) {
                result(i, j) = (i == j) ? 1.0 : 0.0;
            }
        }
        return result;
    }

private:
    // SIMD-accelerated multiplication kernels
    static void avx512_matrix_multiply(const Matrix& a, const Matrix& b, Matrix& result) {
        if constexpr (std::is_same_v<T, float>) {
            constexpr size_t simd_width = 16;
            #pragma omp parallel for
            for (size_t i = 0; i < a.rows(); i += TILE_SIZE) {
                for (size_t j = 0; j < b.cols(); j += TILE_SIZE) {
                    for (size_t k = 0; k < a.cols(); k += TILE_SIZE) {
                        tile_multiply_avx512(a, b, result, i, j, k);
                    }
                }
            }
        }
    }

    static void tile_multiply_avx512(const Matrix& a, const Matrix& b, Matrix& result, 
                                    size_t i_start, size_t j_start, size_t k_start) {
        // AVX512-optimized tile multiplication kernel
        __m512d a_tile, b_tile, acc;
        // ... Intel intrinsic implementations ...
    }

    static void generic_matrix_multiply(const Matrix& a, const Matrix& b, Matrix& result, bool parallel) {
        auto multiply = [&](size_t i) {
            for (size_t k = 0; k < a.cols(); ++k) {
                T aik = a(i, k);
                for (size_t j = 0; j < b.cols(); ++j) {
                    result(i, j) += aik * b(k, j);
                }
            }
        };
        
        if (parallel) {
            std::for_each(std::execution::par_unseq, 
                         counting_iterator(0), 
                         counting_iterator(a.rows()), 
                         multiply);
        } else {
            std::for_each(std::execution::seq, 
                         counting_iterator(0), 
                         counting_iterator(a.rows()), 
                         multiply);
        }
    }

    // Linear system solvers
    static Matrix solve_forward_substitution(const Matrix& L, const Matrix& b) {
        Matrix y(b.rows(), b.cols());
        for (size_t i = 0; i < L.rows(); ++i) {
            for (size_t j = 0; j < b.cols(); ++j) {
                T sum = 0.0;
                for (size_t k = 0; k < i; ++k) {
                    sum += L(i, k) * y(k, j);
                }
                y(i, j) = (b(i, j) - sum) / L(i, i);
            }
        }
        return y;
    }

    static Matrix solve_backward_substitution(const Matrix& U, const Matrix& y) {
        Matrix x(y.rows(), y.cols());
        for (int i = U.rows() - 1; i >= 0; --i) {
            for (size_t j = 0; j < y.cols(); ++j) {
                T sum = 0.0;
                for (size_t k = i + 1; k < U.cols(); ++k) {
                    sum += U(i, k) * x(k, j);
                }
                x(i, j) = (y(i, j) - sum) / U(i, i);
            }
        }
        return x;
    }
};

// Custom execution policy iterators
class counting_iterator {
    size_t current;
public:
    explicit counting_iterator(size_t start) : current(start) {}
    size_t operator*() const { return current; }
    counting_iterator& operator++() { ++current; return *this; }
    bool operator!=(const counting_iterator& other) const { return current != other.current; }
};

} // namespace phasma::math
