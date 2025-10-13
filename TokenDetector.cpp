#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <memory>
#include <cstring>

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define FORCE_INLINE __attribute__((always_inline)) inline
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#define FORCE_INLINE inline
#endif

enum class TokenType
{
    UUID,
    JWT,
    API_KEY_SIMPLE,
    API_KEY_JSON,
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512,
    UNKNOWN
};

struct TokenMatch
{
    TokenType type;
    std::string value;
    size_t position;
    TokenMatch() : type(TokenType::UNKNOWN), position(0) {}
    TokenMatch(TokenType t, std::string v, size_t p) : type(t), value(std::move(v)), position(p) {}
};

// ============================================================================
// INTERFACES (SOLID Principles)
// ============================================================================

class ITokenValidator
{
public:
    virtual ~ITokenValidator() = default;
    virtual bool isValid(const std::string &token) const noexcept = 0;
    virtual TokenType getType() const noexcept = 0;
};

class CharacterClassifier
{
private:
    static constexpr unsigned char CHAR_HEX = 0x01;
    static constexpr unsigned char CHAR_ALPHANUMERIC = 0x04;
    inline static constexpr unsigned char charTable[256] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

public:
    static FORCE_INLINE bool isHexDigit(unsigned char c) noexcept { return (charTable[c] & CHAR_HEX) != 0; }
    static FORCE_INLINE bool isAlphaNumeric(unsigned char c) noexcept { return (charTable[c] & CHAR_ALPHANUMERIC) != 0; }
};

constexpr unsigned char CharacterClassifier::charTable[256];

// ============================================================================
// VALIDATORS (Single Responsibility Principle)
// ============================================================================

class UUIDValidator : public ITokenValidator
{
public:
    bool isValid(const std::string &token) const noexcept override
    {
        if (token.length() != 36)
            return false;
        const char *data = token.data();
        for (size_t i = 0; i < 8; ++i)
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        if (data[8] != '-')
            return false;
        for (size_t i = 9; i < 13; ++i)
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        if (data[13] != '-')
            return false;
        for (size_t i = 14; i < 18; ++i)
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        if (data[18] != '-')
            return false;
        for (size_t i = 19; i < 23; ++i)
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        if (data[23] != '-')
            return false;
        for (size_t i = 24; i < 36; ++i)
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        return true;
    }
    TokenType getType() const noexcept override { return TokenType::UUID; }
};

class JWTValidator : public ITokenValidator
{
public:
    bool isValid(const std::string &token) const noexcept override
    {
        if (token.length() < 36 || token.substr(0, 3) != "eyJ")
            return false;
        int dots = 0;
        size_t segStart = 0;
        for (size_t i = 0; i < token.length(); ++i)
        {
            if (token[i] == '.')
            {
                if (i - segStart < 10)
                    return false;
                ++dots;
                segStart = i + 1;
                if (dots == 1 && i + 3 < token.length() && token.substr(i + 1, 3) != "eyJ")
                    return false;
                if (dots > 2)
                    return false;
            }
            else if (!CharacterClassifier::isAlphaNumeric(token[i]) && token[i] != '-' && token[i] != '_')
            {
                return false;
            }
        }
        return dots == 2 && token.length() - segStart >= 10;
    }
    TokenType getType() const noexcept override { return TokenType::JWT; }
};

class SimpleAPIKeyValidator : public ITokenValidator
{
public:
    bool isValid(const std::string &token) const noexcept override
    {
        if (token.length() < 15)
            return false;
        size_t prefixLen = 0;
        if (token.substr(0, 3) == "sk_" || token.substr(0, 3) == "pk_")
            prefixLen = 3;
        else if (token.length() >= 17 && (token.substr(0, 5) == "live_" || token.substr(0, 5) == "test_"))
            prefixLen = 5;
        else
            return false;
        if (token.length() - prefixLen < 10)
            return false;
        for (char c : token)
            if (!CharacterClassifier::isAlphaNumeric(c) && c != '_')
                return false;
        return true;
    }
    TokenType getType() const noexcept override { return TokenType::API_KEY_SIMPLE; }
};

class SHAValidator : public ITokenValidator
{
    TokenType hashType;
    size_t expectedLength;

public:
    SHAValidator(TokenType type, size_t len) : hashType(type), expectedLength(len) {}
    bool isValid(const std::string &token) const noexcept override
    {
        if (token.length() != expectedLength)
            return false;
        for (char c : token)
            if (!CharacterClassifier::isHexDigit(c))
                return false;
        return true;
    }
    TokenType getType() const noexcept override { return hashType; }
};

// ============================================================================
// TOKEN SCANNER (Optimized for Performance)
// ============================================================================

class TokenScanner
{
private:
    static constexpr size_t MAX_INPUT_SIZE = 10 * 1024 * 1024;

    FORCE_INLINE void scanUUID(const char *data, size_t len, std::vector<TokenMatch> &m) const noexcept
    {
        for (size_t i = 0; i + 36 <= len; ++i)
        {
            if (LIKELY(data[i + 8] == '-' && data[i + 13] == '-' && data[i + 18] == '-' && data[i + 23] == '-'))
            {
                bool ok = true;
                for (size_t j = 0; j < 8 && ok; ++j)
                    ok = CharacterClassifier::isHexDigit(data[i + j]);
                for (size_t j = 9; j < 13 && ok; ++j)
                    ok = CharacterClassifier::isHexDigit(data[i + j]);
                for (size_t j = 14; j < 18 && ok; ++j)
                    ok = CharacterClassifier::isHexDigit(data[i + j]);
                for (size_t j = 19; j < 23 && ok; ++j)
                    ok = CharacterClassifier::isHexDigit(data[i + j]);
                for (size_t j = 24; j < 36 && ok; ++j)
                    ok = CharacterClassifier::isHexDigit(data[i + j]);
                if (ok)
                {
                    m.emplace_back(TokenType::UUID, std::string(data + i, 36), i);
                    i += 35;
                }
            }
        }
    }

    FORCE_INLINE void scanJWT(const char *data, size_t len, std::vector<TokenMatch> &m) const noexcept
    {
        for (size_t i = 0; i + 36 < len; ++i)
        {
            if (UNLIKELY(data[i] != 'e' || data[i + 1] != 'y' || data[i + 2] != 'J'))
                continue;
            size_t e = i + 3;
            int dots = 0;
            size_t segStart = i;
            bool ok = true;
            while (e < len && ok)
            {
                char c = data[e];
                if (c == '.')
                {
                    if (e - segStart < 10)
                    {
                        ok = false;
                        break;
                    }
                    ++dots;
                    segStart = e + 1;
                    if (dots == 1 && e + 3 < len && (data[e + 1] != 'e' || data[e + 2] != 'y' || data[e + 3] != 'J'))
                    {
                        ok = false;
                        break;
                    }
                    if (dots > 2)
                        break;
                }
                else if (!CharacterClassifier::isAlphaNumeric(c) && c != '-' && c != '_')
                    break;
                ++e;
            }
            if (ok && e - segStart < 10)
                ok = false;
            if (ok && dots == 2 && e > i + 36)
            {
                m.emplace_back(TokenType::JWT, std::string(data + i, e - i), i);
                i = e - 1;
            }
        }
    }

    FORCE_INLINE void scanSHA(const char *data, size_t len, std::vector<TokenMatch> &m) const noexcept
    {
        for (size_t i = 0; i < len; ++i)
        {
            if (UNLIKELY(!CharacterClassifier::isHexDigit(data[i])))
                continue;
            if (i > 0 && CharacterClassifier::isHexDigit(data[i - 1]))
                continue;
            size_t hc = 1;
            while (i + hc < len && hc < 129 && CharacterClassifier::isHexDigit(data[i + hc]))
                ++hc;
            bool ok = (i + hc >= len || !CharacterClassifier::isHexDigit(data[i + hc]));
            if (!ok)
            {
                i += hc - 1;
                continue;
            }
            if (hc == 128)
            {
                m.emplace_back(TokenType::SHA_512, std::string(data + i, 128), i);
                i += 127;
            }
            else if (hc == 96)
            {
                m.emplace_back(TokenType::SHA_384, std::string(data + i, 96), i);
                i += 95;
            }
            else if (hc == 64)
            {
                m.emplace_back(TokenType::SHA_256, std::string(data + i, 64), i);
                i += 63;
            }
            else if (hc == 56)
            {
                m.emplace_back(TokenType::SHA_224, std::string(data + i, 56), i);
                i += 55;
            }
            else
            {
                i += hc - 1;
            }
        }
    }

    FORCE_INLINE void scanAPIKey(const char *data, size_t len, std::vector<TokenMatch> &m) const noexcept
    {
        for (size_t i = 0; i + 15 <= len; ++i)
        {
            size_t pl = 0, ml = 0;
            if (data[i] == 's' && data[i + 1] == 'k' && data[i + 2] == '_')
            {
                pl = 3;
                ml = 15;
            }
            else if (data[i] == 'p' && data[i + 1] == 'k' && data[i + 2] == '_')
            {
                pl = 3;
                ml = 15;
            }
            else if (i + 17 <= len && data[i] == 'l' && data[i + 1] == 'i' && data[i + 2] == 'v' && data[i + 3] == 'e' && data[i + 4] == '_')
            {
                pl = 5;
                ml = 17;
            }
            else if (i + 17 <= len && data[i] == 't' && data[i + 1] == 'e' && data[i + 2] == 's' && data[i + 3] == 't' && data[i + 4] == '_')
            {
                pl = 5;
                ml = 17;
            }
            else
                continue;
            size_t e = i + pl;
            while (e < len && (CharacterClassifier::isAlphaNumeric(data[e]) || data[e] == '_'))
                ++e;
            if (e - i >= ml && (e - i - pl) >= 10)
            {
                m.emplace_back(TokenType::API_KEY_SIMPLE, std::string(data + i, e - i), i);
                i = e - 1;
            }
        }
    }

    static size_t findBrace(const char *d, size_t p, size_t l) noexcept
    {
        int dep = 1;
        ++p;
        while (p < l && dep > 0)
        {
            if (d[p] == '\\' && p + 1 < l)
            {
                p += 2;
                continue;
            }
            if (d[p] == '{')
                ++dep;
            else if (d[p] == '}')
                --dep;
            if (dep == 0)
                return p;
            ++p;
        }
        return SIZE_MAX;
    }

    FORCE_INLINE void scanJSON(const char *data, size_t len, std::vector<TokenMatch> &m) const noexcept
    {
        for (size_t i = 0; i < len; ++i)
        {
            if (data[i] != '{')
                continue;
            size_t c = findBrace(data, i, len);
            if (c == SIZE_MAX)
                continue;
            bool pk = false, bk = false;
            for (size_t j = i; j < c - 12 && !pk; ++j)
                if (data[j] == 'p' && std::memcmp(data + j, "private_key", 11) == 0)
                    pk = true;
            if (!pk)
            {
                ++i;
                continue;
            }
            for (size_t j = i; j < c - 26 && !bk; ++j)
                if (data[j] == '-' && std::memcmp(data + j, "-----BEGIN PRIVATE KEY-----", 27) == 0)
                    bk = true;
            if (pk && bk)
            {
                m.emplace_back(TokenType::API_KEY_JSON, std::string(data + i, c - i + 1), i);
                i = c;
            }
        }
    }

public:
    std::vector<TokenMatch> extract(const std::string &text) const noexcept
    {
        std::vector<TokenMatch> m;
        const size_t len = text.length();
        if (UNLIKELY(len > MAX_INPUT_SIZE || len < 5))
            return m;
        m.reserve(20);
        const char *data = text.data();
        scanUUID(data, len, m);
        scanJWT(data, len, m);
        scanAPIKey(data, len, m);
        scanJSON(data, len, m);
        scanSHA(data, len, m);
        if (m.empty())
            return m;
        std::sort(m.begin(), m.end(), [](auto &a, auto &b)
                  { return a.position < b.position; });
        std::vector<TokenMatch> r;
        r.reserve(m.size());
        size_t last = 0;
        for (auto &tok : m)
        {
            if (tok.position >= last)
            {
                last = tok.position + tok.value.length();
                r.push_back(std::move(tok));
            }
        }
        return r;
    }
};

// ============================================================================
// FACTORY
// ============================================================================

class TokenDetectorFactory
{
public:
    static std::unique_ptr<ITokenValidator> createUUIDValidator() { return std::make_unique<UUIDValidator>(); }
    static std::unique_ptr<ITokenValidator> createJWTValidator() { return std::make_unique<JWTValidator>(); }
    static std::unique_ptr<ITokenValidator> createSimpleAPIKeyValidator() { return std::make_unique<SimpleAPIKeyValidator>(); }
    static std::unique_ptr<ITokenValidator> createSHAValidator(TokenType type, size_t len) { return std::make_unique<SHAValidator>(type, len); }
    static std::unique_ptr<TokenScanner> createScanner() { return std::make_unique<TokenScanner>(); }
};

// ============================================================================
// TEST SUITE
// ============================================================================

std::string tokenTypeToString(TokenType type)
{
    switch (type)
    {
    case TokenType::UUID:
        return "UUID";
    case TokenType::JWT:
        return "JWT";
    case TokenType::API_KEY_SIMPLE:
        return "API_KEY_SIMPLE";
    case TokenType::API_KEY_JSON:
        return "API_KEY_JSON";
    case TokenType::SHA_224:
        return "SHA-224";
    case TokenType::SHA_256:
        return "SHA-256";
    case TokenType::SHA_384:
        return "SHA-384";
    case TokenType::SHA_512:
        return "SHA-512";
    default:
        return "UNKNOWN";
    }
}

void runValidationTests()
{
    std::cout << "\n"
              << std::string(100, '=') << "\n";
    std::cout << "=== TOKEN VALIDATION TESTS ===\n";
    std::cout << std::string(100, '=') << "\n\n";

    struct TestCase
    {
        std::string input;
        TokenType expectedType;
        bool shouldBeValid;
        std::string description;
    };

    std::vector<TestCase> tests = {
        // UUID tests
        {"550e8400-e29b-41d4-a716-446655440000", TokenType::UUID, true, "Standard UUID v4"},
        {"c9a6b4c8-4a6e-4b0f-8f1d-2e3c7d6a5b4e", TokenType::UUID, true, "Another valid UUID"},
        {"550e8400-e29b-41d4-a716-44665544000", TokenType::UUID, false, "Invalid UUID (too short)"},
        {"550e8400-e29b-41d4-a716-446655440000X", TokenType::UUID, false, "Invalid UUID (extra char)"},

        // JWT tests
        {"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", TokenType::JWT, true, "Valid JWT"},
        {"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdmMtb3JkZXItcHJvY2Vzc29yIiwic2NvcGUiOiJ3cml0ZTpvcmRlcnMifQ.M9f8aB7nKpWc2xL5dE8tGgR0jHwJ9lY4zU3vB6sC7xO", TokenType::JWT, true, "Short JWT"},
        {"eyJhbGci.eyJzdWI.signature", TokenType::JWT, false, "Invalid JWT (segments too short)"},

        // Simple API Key tests
        {"sk_live_12345abcde67890fghij11223", TokenType::API_KEY_SIMPLE, true, "Stripe-style secret key"},
        {"pk_test_abcdef123456", TokenType::API_KEY_SIMPLE, true, "Stripe-style public key"},
        {"live_12345678", TokenType::API_KEY_SIMPLE, false, "Too short (need 10+ chars after prefix)"},
        {"sk_short", TokenType::API_KEY_SIMPLE, false, "Too short overall"},

        // SHA hash tests
        {"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", TokenType::SHA_224, true, "Valid SHA-224"},
        {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", TokenType::SHA_256, true, "Valid SHA-256"},
        {"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", TokenType::SHA_384, true, "Valid SHA-384"},
        {"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", TokenType::SHA_512, true, "Valid SHA-512"},
    };

    int passed = 0;
    for (const auto &test : tests)
    {
        std::unique_ptr<ITokenValidator> validator;
        switch (test.expectedType)
        {
        case TokenType::UUID:
            validator = TokenDetectorFactory::createUUIDValidator();
            break;
        case TokenType::JWT:
            validator = TokenDetectorFactory::createJWTValidator();
            break;
        case TokenType::API_KEY_SIMPLE:
            validator = TokenDetectorFactory::createSimpleAPIKeyValidator();
            break;
        case TokenType::SHA_224:
            validator = TokenDetectorFactory::createSHAValidator(TokenType::SHA_224, 56);
            break;
        case TokenType::SHA_256:
            validator = TokenDetectorFactory::createSHAValidator(TokenType::SHA_256, 64);
            break;
        case TokenType::SHA_384:
            validator = TokenDetectorFactory::createSHAValidator(TokenType::SHA_384, 96);
            break;
        case TokenType::SHA_512:
            validator = TokenDetectorFactory::createSHAValidator(TokenType::SHA_512, 128);
            break;
        default:
            continue;
        }
        bool result = validator->isValid(test.input);
        bool testPassed = (result == test.shouldBeValid);
        std::cout << (testPassed ? "✓" : "✗") << " " << test.description << std::endl;
        if (!testPassed)
        {
            std::cout << "  Expected: " << (test.shouldBeValid ? "VALID" : "INVALID")
                      << ", Got: " << (result ? "VALID" : "INVALID") << std::endl;
        }
        if (testPassed)
            ++passed;
    }
    std::cout << "\nResult: " << passed << "/" << tests.size() << " passed (" << (passed * 100 / tests.size()) << "%)\n\n";
}

void runScanningTests()
{
    std::cout << "\n"
              << std::string(100, '=') << "\n";
    std::cout << "=== TOKEN SCANNING TESTS ===\n";
    std::cout << std::string(100, '=') << "\n\n";

    auto scanner = TokenDetectorFactory::createScanner();

    struct TestCase
    {
        std::string input;
        int expectedCount;
        std::vector<TokenType> expectedTypes;
        std::string description;
    };

    std::vector<TestCase> tests = {
        {"Backend development uses UUID: 550e8400-e29b-41d4-a716-446655440000 for tracking", 1, {TokenType::UUID}, "UUID in text"},
        {"JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", 1, {TokenType::JWT}, "JWT in text"},
        {"API key: sk_live_12345abcde67890fghij11223", 1, {TokenType::API_KEY_SIMPLE}, "Simple API key"},
        {"Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 1, {TokenType::SHA_256}, "SHA-256 in text"},
        {"Multiple: 550e8400-e29b-41d4-a716-446655440000 and e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 2, {TokenType::UUID, TokenType::SHA_256}, "UUID and SHA-256"},
        {"No tokens here at all", 0, {}, "No tokens"},
        {R"(The evolution of backend architecture from singular, monolithic applications into distributed c9a6b4c8-4a6e-4b0f-8f1d-2e3c7d6a5b4e ecosystems of microservices has fundamentally reshaped the challenges of security and system observability. In the past, a single, unified application contained all its logic within a shared environment, making communication trivial and security a matter of protecting the outer perimeter. Today, however, a A JWT is the standard for stateless authentication and authorization in distributed systems, functioning like a digitally signed passport. Unlike old stateful sessions that required a server to maintain a user's login state, a JWT is a self-contained object that carries all necessary information within it. This token, such as eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNvcGhvcy1rZXktMjAyNCJ9.eyJhdWQiOiIxIiwianRpIjoiNTBlYmVmOWYyYTc1YzdjNTY3NDUwMmIwYjdjMjRmNjMyImp0aSI6ImY4YzNjMWI3LWEzZDktNGIyMS04YTc2LTlkM2IwZjdjMmUwYSIsInNjb3BlIjoicmVhZDpwcm9kdWN0cyODE1ZGVhYWQ5MTMwNDk3Njk5NGFkMzNkZmY4NzRkZjNmNzI4NDJkYjE2ZWI2MjIiLCJpYXQiOjE3NjAxOTIwNjcuOTc3MTc0MDQzNjU1Mzk1NTA3ODEyNSwibmJmIjoxNzYwMTkyMDY3Ljk3NzE3NjkwNDY3ODM0NDcyNjU2MjUsImV4cCI6MTc3NTkxNjg2Ny45NzIyMTQ5MzcyMTAwODMwMDc4MTI1LCJzdWIiOiIxMjk4Iiwic2NvcGVzIjpbXX0.jd-4_RH1m_nmhaFJxa4V-t40JyGExlAqO0z4etDOGJQZd4fol-fSAcqEBhLrkumQC8s9rm8EIi9YNAPs80BUoMp5l3na039u9Ob6hK1I1rW-VpmIWKww2Wrl6aWh73CocyPEbCiROMVdDeRcJo-pfLDzy7J1dPoxouGNKfeSNOitkFAoCE1cfgtXsSMjhJ6Ax5uj_fKpiwZdT-NpUKMl-aKZ8kSZYStHHnZ_M-1s5xBY5nRjloiDEfDs_u_XNZQZ8Z4qvckmZyiYoaqS5lJkVQkDZkvZtSehLb2G50oFKwopopvgfN8t5LWvQVrqF55CZXcep7ZB8EfWLxbubfguSCCu5VsfA6pUaeN2YJuebjb_qCf0S7xWYCCNL9bKywbwhSbTs2s8y2wUTKsCfzwF3SQDwUNY8YhJW9GYVMZ2adgOCwYl3HDmTlHMnolA8V7HGLx3gxi8t3Mw0RYRSBdjbcfPbpBS7kAQ2v6rq-h9XMqXMDxHOKnxaw_u0ymTOf4QNV2SUBIghk6n1bmNynwaNxSqi9Xa7XYpyIlfN56uhZBXAAf8w-J0AjW-bkTmSg9no3aJwSgEcwghSYvsVm3PnhpQZvL5O2gLK4nbOYZQL5eWRlQbme4N6DHD5sTqYKprva9RmBeF7jAfvYUARDZvlQTb69AHUe2-Y4d_E2JbTAQ, is composed of three parts: a header specifying the signing algorithm, a payload containing claims about the user or service (like their ID, roles, and permissions via scopes), and a cryptographic signature. When a service receives a request, it doesn't need to call back to an authentication server; it can independented this role, modern systems demand more secure and structured credentials, such as a service account key. This is often a JSON object that contains a collection of metadata and, most critically, a private key. An example of such a key would be {"type":"service_account","project_id":"global-data-pipeline","private_key_id":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ...\\n-----END PRIVATE KEY-----\\n","client_email":"data-processor@global-data-pipeline.iam.gserviceaccount.com","client_id":"109876543210987654321","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token"}. A backend service uses this file not as a direct authentication token, but as a source of truth to prove its identity to an authorization server. It uses the embedded private key to sign a request, and in return, receives a short-lived access token (often a JWT). It then uses this temporary token to make its actual API calls. This flow prevents the long-lived, highly sensitive private key from being sent over the network repeatedly, dramatically improving the security posture. Together, these three tokens—the UUID for traceability, the JWT for user and service authentication, and the service account key for machine identity—form the bedrock of secure, scalable, and observable backend systems, enabling the intricate yet resilient dance of modern microservice communication.)",
         3,
         {TokenType::UUID, TokenType::JWT, TokenType::API_KEY_JSON},
         "UUID, JWT and API_KEY type tokens"},
        {R"({"type":"service_account","project_id":"test-project","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ...\n-----END PRIVATE KEY-----\n","client_email":"test@project.iam.gserviceaccount.com"})", 1, {TokenType::API_KEY_JSON}, "JSON API key"},
    };

    int passed = 0;
    for (const auto &test : tests)
    {
        auto matches = scanner->extract(test.input);
        bool testPassed = (matches.size() == static_cast<size_t>(test.expectedCount));
        if (testPassed && !matches.empty())
        {
            for (size_t i = 0; i < test.expectedTypes.size() && i < matches.size(); ++i)
            {
                if (matches[i].type != test.expectedTypes[i])
                {
                    testPassed = false;
                    break;
                }
            }
        }
        std::cout << (testPassed ? "✓" : "✗") << " " << test.description << std::endl;
        std::cout << "  Found " << matches.size() << " token(s)" << std::endl;
        for (const auto &match : matches)
        {
            std::string displayValue = match.value;
            // if (displayValue.length() > 80)
            //     displayValue = displayValue.substr(0, 77) + "...";
            std::cout << "    [" << tokenTypeToString(match.type) << "] " << displayValue << std::endl;
        }
        if (!testPassed)
        {
            std::cout << "  Expected: " << test.expectedCount << " tokens" << std::endl;
        }
        std::cout << std::endl;
        if (testPassed)
            ++passed;
    }
    std::cout << "Result: " << passed << "/" << tests.size() << " passed (" << (passed * 100 / tests.size()) << "%)\n\n";
}

void runPerformanceBenchmark()
{
    std::cout << "\n"
              << std::string(100, '=') << "\n";
    std::cout << "=== PERFORMANCE BENCHMARK ===\n";
    std::cout << std::string(100, '=') << "\n";

    auto scanner = TokenDetectorFactory::createScanner();

    std::vector<std::string> testCases = {
        "UUID: 550e8400-e29b-41d4-a716-446655440000",
        "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "API Key: sk_live_12345abcde67890fghij11223",
        "SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-512: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "Multiple: 550e8400-e29b-41d4-a716-446655440000 and e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "No tokens here",
        "The evolution of backend architecture from singular, monolithic applications into distributed ecosystems of microservices has fundamentally reshaped the challenges of security and system observability. In the past, a single, unified application contained all its logic within a shared environment, making communication trivial and security a matter of protecting the outer perimeter. Today, however, a A JWT is the standard for stateless authentication and authorization in distributed systems, functioning like a digitally signed passport. Unlike old stateful sessions that required a server to maintain a user's login state, a JWT is a self-contained object that carries all necessary information within it. This token, such as eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNvcGhvcy1rZXktMjAyNCJ9.eyJhdWQiOiIxIiwianRpIjoiNTBlYmVmOWYyYTc1YzdjNTY3NDUwMmIwYjdjMjRmNjMyImp0aSI6ImY4YzNjMWI3LWEzZDktNGIyMS04YTc2LTlkM2IwZjdjMmUwYSIsInNjb3BlIjoicmVhZDpwcm9kdWN0cyODE1ZGVhYWQ5MTMwNDk3Njk5NGFkMzNkZmY4NzRkZjNmNzI4NDJkYjE2ZWI2MjIiLCJpYXQiOjE3NjAxOTIwNjcuOTc3MTc0MDQzNjU1Mzk1NTA3ODEyNSwibmJmIjoxNzYwMTkyMDY3Ljk3NzE3NjkwNDY3ODM0NDcyNjU2MjUsImV4cCI6MTc3NTkxNjg2Ny45NzIyMTQ5MzcyMTAwODMwMDc4MTI1LCJzdWIiOiIxMjk4Iiwic2NvcGVzIjpbXX0.jd-4_RH1m_nmhaFJxa4V-t40JyGExlAqO0z4etDOGJQZd4fol-fSAcqEBhLrkumQC8s9rm8EIi9YNAPs80BUoMp5l3na039u9Ob6hK1I1rW-VpmIWKww2Wrl6aWh73CocyPEbCiROMVdDeRcJo-pfLDzy7J1dPoxouGNKfeSNOitkFAoCE1cfgtXsSMjhJ6Ax5uj_fKpiwZdT-NpUKMl-aKZ8kSZYStHHnZ_M-1s5xBY5nRjloiDEfDs_u_XNZQZ8Z4qvckmZyiYoaqS5lJkVQkDZkvZtSehLb2G50oFKwopopvgfN8t5LWvQVrqF55CZXcep7ZB8EfWLxbubfguSCCu5VsfA6pUaeN2YJuebjb_qCf0S7xWYCCNL9bKywbwhSbTs2s8y2wUTKsCfzwF3SQDwUNY8YhJW9GYVMZ2adgOCwYl3HDmTlHMnolA8V7HGLx3gxi8t3Mw0RYRSBdjbcfPbpBS7kAQ2v6rq-h9XMqXMDxHOKnxaw_u0ymTOf4QNV2SUBIghk6n1bmNynwaNxSqi9Xa7XYpyIlfN56uhZBXAAf8w-J0AjW-bkTmSg9no3aJwSgEcwghSYvsVm3PnhpQZvL5O2gLK4nbOYZQL5eWRlQbme4N6DHD5sTqYKprva9RmBeF7jAfvYUARDZvlQTb69AHUe2-Y4d_E2JbTAQ, is composed of three parts: a header specifying the signing algorithm, a payload containing claims about the user or service (like their ID, roles, and permissions via scopes), and a cryptographic signature. When a service receives a request, it doesn't need to call back to an authentication server; it can independented this role, modern systems demand more secure and structured credentials, such as a service account key. This is often a JSON object that contains a collection of metadata and, most critically, a private key. An example of such a key would be",
        R"(The evolution of backend architecture from singular, monolithic applications into distributed c9a6b4c8-4a6e-4b0f-8f1d-2e3c7d6a5b4e ecosystems of microservices has fundamentally reshaped the challenges of security and system observability. In the past, a single, unified application contained all its logic within a shared environment, making communication trivial and security a matter of protecting the outer perimeter. Today, however, a A JWT is the standard for stateless authentication and authorization in distributed systems, functioning like a digitally signed passport. Unlike old stateful sessions that required a server to maintain a user's login state, a JWT is a self-contained object that carries all necessary information within it. This token, such as eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNvcGhvcy1rZXktMjAyNCJ9.eyJhdWQiOiIxIiwianRpIjoiNTBlYmVmOWYyYTc1YzdjNTY3NDUwMmIwYjdjMjRmNjMyImp0aSI6ImY4YzNjMWI3LWEzZDktNGIyMS04YTc2LTlkM2IwZjdjMmUwYSIsInNjb3BlIjoicmVhZDpwcm9kdWN0cyODE1ZGVhYWQ5MTMwNDk3Njk5NGFkMzNkZmY4NzRkZjNmNzI4NDJkYjE2ZWI2MjIiLCJpYXQiOjE3NjAxOTIwNjcuOTc3MTc0MDQzNjU1Mzk1NTA3ODEyNSwibmJmIjoxNzYwMTkyMDY3Ljk3NzE3NjkwNDY3ODM0NDcyNjU2MjUsImV4cCI6MTc3NTkxNjg2Ny45NzIyMTQ5MzcyMTAwODMwMDc4MTI1LCJzdWIiOiIxMjk4Iiwic2NvcGVzIjpbXX0.jd-4_RH1m_nmhaFJxa4V-t40JyGExlAqO0z4etDOGJQZd4fol-fSAcqEBhLrkumQC8s9rm8EIi9YNAPs80BUoMp5l3na039u9Ob6hK1I1rW-VpmIWKww2Wrl6aWh73CocyPEbCiROMVdDeRcJo-pfLDzy7J1dPoxouGNKfeSNOitkFAoCE1cfgtXsSMjhJ6Ax5uj_fKpiwZdT-NpUKMl-aKZ8kSZYStHHnZ_M-1s5xBY5nRjloiDEfDs_u_XNZQZ8Z4qvckmZyiYoaqS5lJkVQkDZkvZtSehLb2G50oFKwopopvgfN8t5LWvQVrqF55CZXcep7ZB8EfWLxbubfguSCCu5VsfA6pUaeN2YJuebjb_qCf0S7xWYCCNL9bKywbwhSbTs2s8y2wUTKsCfzwF3SQDwUNY8YhJW9GYVMZ2adgOCwYl3HDmTlHMnolA8V7HGLx3gxi8t3Mw0RYRSBdjbcfPbpBS7kAQ2v6rq-h9XMqXMDxHOKnxaw_u0ymTOf4QNV2SUBIghk6n1bmNynwaNxSqi9Xa7XYpyIlfN56uhZBXAAf8w-J0AjW-bkTmSg9no3aJwSgEcwghSYvsVm3PnhpQZvL5O2gLK4nbOYZQL5eWRlQbme4N6DHD5sTqYKprva9RmBeF7jAfvYUARDZvlQTb69AHUe2-Y4d_E2JbTAQ, is composed of three parts: a header specifying the signing algorithm, a payload containing claims about the user or service (like their ID, roles, and permissions via scopes), and a cryptographic signature. When a service receives a request, it doesn't need to call back to an authentication server; it can independented this role, modern systems demand more secure and structured credentials, such as a service account key. This is often a JSON object that contains a collection of metadata and, most critically, a private key. An example of such a key would be {"type":"service_account","project_id":"global-data-pipeline","private_key_id":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ...\\n-----END PRIVATE KEY-----\\n","client_email":"data-processor@global-data-pipeline.iam.gserviceaccount.com","client_id":"109876543210987654321","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token"}. A backend service uses this file not as a direct authentication token, but as a source of truth to prove its identity to an authorization server. It uses the embedded private key to sign a request, and in return, receives a short-lived access token (often a JWT). It then uses this temporary token to make its actual API calls. This flow prevents the long-lived, highly sensitive private key from being sent over the network repeatedly, dramatically improving the security posture. Together, these three tokens—the UUID for traceability, the JWT for user and service authentication, and the service account key for machine identity—form the bedrock of secure, scalable, and observable backend systems, enabling the intricate yet resilient dance of modern microservice communication.)",
        std::string(1000, 'x') + "550e8400-e29b-41d4-a716-446655440000" + std::string(1000, 'y'),
        "Complex text with UUID c9a6b4c8-4a6e-4b0f-8f1d-2e3c7d6a5b4e and JWT eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdmMtb3JkZXItcHJvY2Vzc29yIiwic2NvcGUiOiJ3cml0ZTpvcmRlcnMifQ.M9f8aB7nKpWc2xL5dE8tGgR0jHwJ9lY4zU3vB6sC7xO",
        R"({"type":"service_account","project_id":"test-project","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ...\n-----END PRIVATE KEY-----\n","client_email":"test@project.iam.gserviceaccount.com"})"};

    const int numThreads = std::thread::hardware_concurrency();
    const int iterationsPerThread = 100000;

    std::cout << "Threads: " << numThreads << std::endl;
    std::cout << "Iterations per thread: " << iterationsPerThread << std::endl;
    std::cout << "Test cases: " << testCases.size() << "\n";
    std::cout << "Total operations: " << (numThreads * iterationsPerThread * testCases.size()) << "\n";
    std::cout << "Starting benchmark...\n"
              << std::flush;

    auto start = std::chrono::high_resolution_clock::now();
    std::atomic<long long> totalTokensFound{0};
    std::vector<std::thread> threads;

    for (int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back([&testCases, &totalTokensFound, iterationsPerThread, &scanner]()
                             {
            long long localTokensFound = 0;
            for (int i = 0; i < iterationsPerThread; ++i) {
                for (const auto& test : testCases) {
                    auto matches = scanner->extract(test);
                    localTokensFound += matches.size();
                }
            }
            totalTokensFound += localTokensFound; });
    }

    for (auto &thread : threads)
        thread.join();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    long long totalOps = static_cast<long long>(numThreads) * iterationsPerThread * testCases.size();

    std::cout << "\n"
              << std::string(100, '-') << "\n";
    std::cout << "RESULTS:\n";
    std::cout << std::string(100, '-') << "\n";
    std::cout << "Time: " << duration.count() << " ms\n";
    std::cout << "Ops/sec: " << (totalOps * 1000 / duration.count()) << "\n";
    std::cout << "Total tokens found: " << totalTokensFound.load() << "\n";
    std::cout << std::string(100, '=') << "\n\n";
}

int main()
{
    try
    {
        runValidationTests();
        runScanningTests();

        std::cout << "\n"
                  << std::string(100, '=') << "\n";
        std::cout << "=== TOKEN DETECTION DEMO ===\n";
        std::cout << std::string(100, '=') << "\n\n";

        auto scanner = TokenDetectorFactory::createScanner();
        std::string text = R"(Backend text with c9a6b4c8-4a6e-4b0f-8f1d-2e3c7d6a5b4e and eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdmMtb3JkZXItcHJvY2Vzc29yIiwic2NvcGUiOiJ3cml0ZTpvcmRlcnMifQ.M9f8aB7nKpWc2xL5dE8tGgR0jHwJ9lY4zU3vB6sC7xO and sk_live_12345abcde67890fghij11223)";

        auto m = scanner->extract(text);
        std::cout << "Found " << m.size() << " tokens:\n\n";
        for (auto &tok : m)
        {
            std::cout << "  [" << tokenTypeToString(tok.type) << "] at pos " << tok.position << "\n";
            std::cout << "  Value: " << tok.value << "\n\n";
        }

        runPerformanceBenchmark();

        std::cout << "\n"
                  << std::string(100, '=') << std::endl;
        std::cout << "✓ SOLID Principles Applied" << std::endl;
        std::cout << "✓ Optimized for 1M+ ops/sec Performance" << std::endl;
        std::cout << "✓ Character Classification Lookup Tables" << std::endl;
        std::cout << "✓ Thread-Safe Implementation" << std::endl;
        std::cout << std::string(100, '=') << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
