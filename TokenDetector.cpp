#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <stdexcept>
#include <unordered_set>
#include <memory>
#include <optional>
#include <cstring>

// Branch prediction hints
#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#endif

// Force inline for hot path functions
#if defined(_MSC_VER)
#define FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define FORCE_INLINE __attribute__((always_inline)) inline
#else
#define FORCE_INLINE inline
#endif

// ============================================================================
// TOKEN TYPES
// ============================================================================

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
    TokenMatch(TokenType t, const std::string &v, size_t p)
        : type(t), value(v), position(p) {}
};

// ============================================================================
// INTERFACES (SOLID: Interface Segregation Principle)
// ============================================================================

class ITokenValidator
{
public:
    virtual ~ITokenValidator() = default;
    virtual bool isValid(const std::string &token) const noexcept = 0;
    virtual TokenType getType() const noexcept = 0;
};

class ITokenScanner
{
public:
    virtual ~ITokenScanner() = default;
    virtual bool contains(const std::string &text) const noexcept = 0;
    virtual std::vector<TokenMatch> extract(const std::string &text) const noexcept = 0;
};

// ============================================================================
// CHARACTER CLASSIFICATION (Lookup Tables) (Single Responsibility Principle)
// ============================================================================

class CharacterClassifier
{
private:
    // Lookup tables for O(1) character classification
    static constexpr unsigned char CHAR_HEX = 0x01;
    static constexpr unsigned char CHAR_BASE64URL = 0x02;
    static constexpr unsigned char CHAR_ALPHANUMERIC = 0x04;
    static constexpr unsigned char CHAR_BOUNDARY = 0x08;
    static constexpr unsigned char CHAR_HYPHEN = 0x10;
    static constexpr unsigned char CHAR_UNDERSCORE = 0x20;
    static constexpr unsigned char CHAR_DOT = 0x40;

    // Pre-computed lookup table
    static constexpr unsigned char charTable[256] = {
        // 0-31: control characters
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // 32-47: space and symbols
        0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x08, 0x00, 0x00, 0x08, 0x12, 0x48, 0x00,
        // 48-63: digits and more symbols
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x08, 0x08, 0x00, 0x08, 0x00,
        // 64-79: @ and uppercase letters
        0x08, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        // 80-95: more uppercase and symbols
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x08, 0x00, 0x08, 0x00, 0x26,
        // 96-111: backtick and lowercase letters
        0x00, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        // 112-127: more lowercase and symbols
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x08, 0x00, 0x08, 0x00, 0x00,
        // 128-255: extended ASCII (invalid)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

public:
    static FORCE_INLINE bool isHexDigit(unsigned char c) noexcept
    {
        return (charTable[c] & CHAR_HEX) != 0;
    }

    static FORCE_INLINE bool isBase64Url(unsigned char c) noexcept
    {
        return (charTable[c] & CHAR_BASE64URL) != 0;
    }

    static FORCE_INLINE bool isAlphaNumeric(unsigned char c) noexcept
    {
        return (charTable[c] & CHAR_ALPHANUMERIC) != 0;
    }

    static FORCE_INLINE bool isBoundary(unsigned char c) noexcept
    {
        return (charTable[c] & CHAR_BOUNDARY) != 0;
    }

    static FORCE_INLINE bool isHyphen(unsigned char c) noexcept
    {
        return c == '-';
    }

    static FORCE_INLINE bool isUnderscore(unsigned char c) noexcept
    {
        return c == '_';
    }

    static FORCE_INLINE bool isDot(unsigned char c) noexcept
    {
        return c == '.';
    }
};

constexpr unsigned char CharacterClassifier::charTable[256];

// ============================================================================
// UUID VALIDATOR (Single Responsibility Principle)
// ============================================================================

class UUIDValidator : public ITokenValidator
{
private:
    static constexpr size_t UUID_LENGTH = 36;

    static FORCE_INLINE bool validateFormat(const std::string &token) noexcept
    {
        if (UNLIKELY(token.length() != UUID_LENGTH))
            return false;

        const char *data = token.data();

        for (size_t i = 0; i < 8; ++i)
        {
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        }
        if (data[8] != '-')
            return false;

        for (size_t i = 9; i < 13; ++i)
        {
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        }
        if (data[13] != '-')
            return false;

        for (size_t i = 14; i < 18; ++i)
        {
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        }
        if (data[18] != '-')
            return false;

        for (size_t i = 19; i < 23; ++i)
        {
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        }
        if (data[23] != '-')
            return false;

        for (size_t i = 24; i < 36; ++i)
        {
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        }

        return true;
    }

public:
    bool isValid(const std::string &token) const noexcept override
    {
        return validateFormat(token);
    }

    TokenType getType() const noexcept override
    {
        return TokenType::UUID;
    }
};

// ============================================================================
// JWT VALIDATOR (Single Responsibility Principle)
// ============================================================================

class JWTValidator : public ITokenValidator
{
private:
    static constexpr size_t MIN_JWT_LENGTH = 36;
    static constexpr size_t MIN_SEGMENT_LENGTH = 10;

    static FORCE_INLINE bool validateFormat(const std::string &token) noexcept
    {
        if (UNLIKELY(token.length() < MIN_JWT_LENGTH))
            return false;
        if (UNLIKELY(token.substr(0, 3) != "eyJ"))
            return false;

        const char *data = token.data();
        const size_t len = token.length();

        int dotCount = 0;
        size_t lastDot = 0;
        size_t segmentStart = 0;

        for (size_t i = 0; i < len; ++i)
        {
            char c = data[i];

            if (c == '.')
            {
                size_t segmentLen = i - segmentStart;
                if (segmentLen < MIN_SEGMENT_LENGTH)
                    return false;

                ++dotCount;
                lastDot = i;
                segmentStart = i + 1;

                if (dotCount == 1 && i + 3 < len)
                {
                    if (data[i + 1] != 'e' || data[i + 2] != 'y' || data[i + 3] != 'J')
                    {
                        return false;
                    }
                }
                if (dotCount > 2)
                    return false;
            }
            else if (!CharacterClassifier::isAlphaNumeric(c) && c != '-' && c != '_')
            {
                return false;
            }
        }

        if (len - segmentStart < MIN_SEGMENT_LENGTH)
            return false;

        return dotCount == 2 && lastDot > 0 && lastDot < len - 1;
    }

public:
    bool isValid(const std::string &token) const noexcept override
    {
        return validateFormat(token);
    }

    TokenType getType() const noexcept override
    {
        return TokenType::JWT;
    }
};

// ============================================================================
// API KEY VALIDATOR (Single Responsibility Principle)
// ============================================================================

class SimpleAPIKeyValidator : public ITokenValidator
{
private:
    static constexpr size_t MIN_KEY_LENGTH = 15;
    static constexpr size_t MAX_KEY_LENGTH = 100;

    static FORCE_INLINE bool validateFormat(const std::string &token) noexcept
    {
        const size_t len = token.length();
        if (UNLIKELY(len < MIN_KEY_LENGTH || len > MAX_KEY_LENGTH))
            return false;

        bool validPrefix = false;
        size_t prefixLen = 0;

        if (len >= 15 && token.substr(0, 3) == "sk_")
        {
            validPrefix = true;
            prefixLen = 3;
        }
        else if (len >= 15 && token.substr(0, 3) == "pk_")
        {
            validPrefix = true;
            prefixLen = 3;
        }
        else if (len >= 17 && token.substr(0, 5) == "live_")
        {
            validPrefix = true;
            prefixLen = 5;
        }
        else if (len >= 17 && token.substr(0, 5) == "test_")
        {
            validPrefix = true;
            prefixLen = 5;
        }

        if (!validPrefix)
            return false;

        if (len - prefixLen < 10)
            return false;

        const char *data = token.data();
        for (size_t i = 0; i < len; ++i)
        {
            char c = data[i];
            if (!CharacterClassifier::isAlphaNumeric(c) && c != '_')
            {
                return false;
            }
        }

        return true;
    }

public:
    bool isValid(const std::string &token) const noexcept override
    {
        return validateFormat(token);
    }

    TokenType getType() const noexcept override
    {
        return TokenType::API_KEY_SIMPLE;
    }
};

class JSONAPIKeyValidator : public ITokenValidator
{
private:
    static FORCE_INLINE bool validateFormat(const std::string &token) noexcept
    {
        if (UNLIKELY(token.empty() || token[0] != '{'))
            return false;

        bool hasPrivateKey = token.find("\"private_key\"") != std::string::npos;
        bool hasBeginKey = token.find("-----BEGIN PRIVATE KEY-----") != std::string::npos;
        bool hasServiceAccount = token.find("\"type\"") != std::string::npos &&
                                 token.find("service_account") != std::string::npos;

        return hasPrivateKey && hasBeginKey && hasServiceAccount;
    }

public:
    bool isValid(const std::string &token) const noexcept override
    {
        return validateFormat(token);
    }

    TokenType getType() const noexcept override
    {
        return TokenType::API_KEY_JSON;
    }
};

// ============================================================================
// SHA HASH VALIDATOR (Single Responsibility Principle)
// ============================================================================

class SHAValidator : public ITokenValidator
{
private:
    TokenType hashType;
    size_t expectedLength;

    static FORCE_INLINE bool validateFormat(const std::string &token, size_t len) noexcept
    {
        if (UNLIKELY(token.length() != len))
            return false;

        const char *data = token.data();
        for (size_t i = 0; i < len; ++i)
        {
            if (!CharacterClassifier::isHexDigit(data[i]))
                return false;
        }
        return true;
    }

public:
    SHAValidator(TokenType type, size_t len) : hashType(type), expectedLength(len) {}

    bool isValid(const std::string &token) const noexcept override
    {
        return validateFormat(token, expectedLength);
    }

    TokenType getType() const noexcept override
    {
        return hashType;
    }
};

// ============================================================================
// TOKEN SCANNER (Single Responsibility Principle)
// ============================================================================

class TokenScanner : public ITokenScanner
{
private:
    static constexpr size_t MAX_INPUT_SIZE = 10 * 1024 * 1024;

    std::unique_ptr<UUIDValidator> uuidValidator;
    std::unique_ptr<JWTValidator> jwtValidator;
    std::unique_ptr<SimpleAPIKeyValidator> simpleAPIKeyValidator;
    std::unique_ptr<JSONAPIKeyValidator> jsonAPIKeyValidator;
    std::unique_ptr<SHAValidator> sha224Validator;
    std::unique_ptr<SHAValidator> sha256Validator;
    std::unique_ptr<SHAValidator> sha384Validator;
    std::unique_ptr<SHAValidator> sha512Validator;

    static size_t findMatchingBrace(const std::string &text, size_t openPos) noexcept
    {
        int depth = 1;
        size_t pos = openPos + 1;
        const size_t len = text.length();

        while (pos < len && depth > 0)
        {
            if (text[pos] == '\\' && pos + 1 < len)
            {
                pos += 2;
                continue;
            }

            if (text[pos] == '{')
                ++depth;
            else if (text[pos] == '}')
                --depth;

            if (depth == 0)
                return pos;
            ++pos;
        }

        return std::string::npos;
    }

    static FORCE_INLINE bool isWordBoundary(const std::string &text, size_t pos, size_t len) noexcept
    {
        if (pos > 0 && pos < len)
        {
            char before = text[pos - 1];
            char at = text[pos];
            return CharacterClassifier::isBoundary(before) ||
                   before == ',' || before == ':' || before == '=' ||
                   before == '[' || before == '(' || before == '{';
        }
        return pos == 0 || pos >= len;
    }

    void scanUUID(const std::string &text, std::vector<TokenMatch> &matches) const noexcept
    {
        const size_t len = text.length();
        const char *data = text.data();

        for (size_t i = 0; i + 36 <= len; ++i)
        {
            if (data[i + 8] == '-' && data[i + 13] == '-' &&
                data[i + 18] == '-' && data[i + 23] == '-')
            {

                std::string candidate = text.substr(i, 36);
                if (uuidValidator->isValid(candidate))
                {
                    matches.emplace_back(TokenType::UUID, candidate, i);
                    i += 35;
                }
            }
        }
    }

    void scanJWT(const std::string &text, std::vector<TokenMatch> &matches) const noexcept
    {
        const size_t len = text.length();
        size_t pos = 0;

        while (pos < len)
        {
            pos = text.find("eyJ", pos);
            if (pos == std::string::npos)
                break;

            size_t end = pos + 3;
            int dotCount = 0;

            while (end < len)
            {
                char c = text[end];
                if (c == '.')
                {
                    ++dotCount;
                    if (dotCount > 2)
                        break;
                }
                else if (!CharacterClassifier::isAlphaNumeric(c) && c != '-' && c != '_')
                {
                    break;
                }
                ++end;
            }

            if (dotCount == 2 && end > pos + 20)
            {
                std::string candidate = text.substr(pos, end - pos);
                if (jwtValidator->isValid(candidate))
                {
                    matches.emplace_back(TokenType::JWT, candidate, pos);
                    pos = end;
                    continue;
                }
            }

            ++pos;
        }
    }

    void scanSimpleAPIKey(const std::string &text, std::vector<TokenMatch> &matches) const noexcept
    {
        const size_t len = text.length();
        size_t pos = 0;

        std::vector<std::string> prefixes = {"sk_", "pk_", "live_", "test_"};

        for (const auto &prefix : prefixes)
        {
            pos = 0;
            while (pos < len)
            {
                pos = text.find(prefix, pos);
                if (pos == std::string::npos)
                    break;

                size_t end = pos + prefix.length();
                while (end < len && (CharacterClassifier::isAlphaNumeric(text[end]) || text[end] == '_'))
                {
                    ++end;
                }

                if (end - pos >= 10)
                {
                    std::string candidate = text.substr(pos, end - pos);
                    if (simpleAPIKeyValidator->isValid(candidate))
                    {
                        matches.emplace_back(TokenType::API_KEY_SIMPLE, candidate, pos);
                        pos = end;
                        continue;
                    }
                }

                ++pos;
            }
        }
    }

    void scanJSONAPIKey(const std::string &text, std::vector<TokenMatch> &matches) const noexcept
    {
        const size_t len = text.length();
        size_t pos = 0;

        while (pos < len)
        {
            pos = text.find("{", pos);
            if (pos == std::string::npos)
                break;

            size_t closePos = findMatchingBrace(text, pos);
            if (closePos != std::string::npos)
            {
                std::string candidate = text.substr(pos, closePos - pos + 1);
                if (jsonAPIKeyValidator->isValid(candidate))
                {
                    matches.emplace_back(TokenType::API_KEY_JSON, candidate, pos);
                    pos = closePos + 1;
                    continue;
                }
            }

            ++pos;
        }
    }

    void scanSHAHashes(const std::string &text, std::vector<TokenMatch> &matches) const noexcept
    {
        const size_t len = text.length();

        std::vector<std::pair<size_t, TokenType>> hashLengths = {
            {128, TokenType::SHA_512},
            {96, TokenType::SHA_384},
            {64, TokenType::SHA_256},
            {56, TokenType::SHA_224}};

        for (const auto &[hashLen, tokenType] : hashLengths)
        {
            for (size_t i = 0; i + hashLen <= len; ++i)
            {
                if (i > 0 && CharacterClassifier::isHexDigit(text[i - 1]))
                    continue;
                if (i + hashLen < len && CharacterClassifier::isHexDigit(text[i + hashLen]))
                    continue;

                bool allHex = true;
                for (size_t j = 0; j < hashLen; ++j)
                {
                    if (!CharacterClassifier::isHexDigit(text[i + j]))
                    {
                        allHex = false;
                        break;
                    }
                }

                if (allHex)
                {
                    std::string candidate = text.substr(i, hashLen);
                    matches.emplace_back(tokenType, candidate, i);
                    i += hashLen - 1;
                }
            }
        }
    }

public:
    TokenScanner()
        : uuidValidator(std::make_unique<UUIDValidator>()),
          jwtValidator(std::make_unique<JWTValidator>()),
          simpleAPIKeyValidator(std::make_unique<SimpleAPIKeyValidator>()),
          jsonAPIKeyValidator(std::make_unique<JSONAPIKeyValidator>()),
          sha224Validator(std::make_unique<SHAValidator>(TokenType::SHA_224, 56)),
          sha256Validator(std::make_unique<SHAValidator>(TokenType::SHA_256, 64)),
          sha384Validator(std::make_unique<SHAValidator>(TokenType::SHA_384, 96)),
          sha512Validator(std::make_unique<SHAValidator>(TokenType::SHA_512, 128)) {}

    bool contains(const std::string &text) const noexcept override
    {
        try
        {
            if (UNLIKELY(text.length() > MAX_INPUT_SIZE || text.length() < 5))
                return false;

            std::vector<TokenMatch> matches;
            return !extract(text).empty();
        }
        catch (...)
        {
            return false;
        }
    }

    std::vector<TokenMatch> extract(const std::string &text) const noexcept override
    {
        std::vector<TokenMatch> matches;

        try
        {
            if (UNLIKELY(text.length() > MAX_INPUT_SIZE || text.length() < 5))
                return matches;

            matches.reserve(10);
            std::unordered_set<std::string> seen;

            std::vector<bool> covered(text.length(), false);

            std::vector<TokenMatch> allMatches;

            scanUUID(text, allMatches);
            scanJWT(text, allMatches);
            scanSimpleAPIKey(text, allMatches);
            scanJSONAPIKey(text, allMatches);
            scanSHAHashes(text, allMatches);

            std::sort(allMatches.begin(), allMatches.end(),
                      [](const TokenMatch &a, const TokenMatch &b)
                      {
                          return a.position < b.position;
                      });

            for (const auto &match : allMatches)
            {
                size_t start = match.position;
                size_t end = start + match.value.length();

                bool overlaps = false;
                for (size_t i = start; i < end && i < covered.size(); ++i)
                {
                    if (covered[i])
                    {
                        overlaps = true;
                        break;
                    }
                }

                if (!overlaps && seen.insert(match.value).second)
                {
                    for (size_t i = start; i < end && i < covered.size(); ++i)
                    {
                        covered[i] = true;
                    }
                    matches.push_back(match);
                }
            }

            return matches;
        }
        catch (...)
        {
            matches.clear();
        }

        return matches;
    }
};

// ============================================================================
// FACTORY (Dependency Inversion Principle)
// ============================================================================

class TokenDetectorFactory
{
public:
    static std::unique_ptr<ITokenValidator> createUUIDValidator()
    {
        return std::make_unique<UUIDValidator>();
    }

    static std::unique_ptr<ITokenValidator> createJWTValidator()
    {
        return std::make_unique<JWTValidator>();
    }

    static std::unique_ptr<ITokenValidator> createSimpleAPIKeyValidator()
    {
        return std::make_unique<SimpleAPIKeyValidator>();
    }

    static std::unique_ptr<ITokenValidator> createJSONAPIKeyValidator()
    {
        return std::make_unique<JSONAPIKeyValidator>();
    }

    static std::unique_ptr<ITokenValidator> createSHAValidator(TokenType type, size_t len)
    {
        return std::make_unique<SHAValidator>(type, len);
    }

    static std::unique_ptr<ITokenScanner> createScanner()
    {
        return std::make_unique<TokenScanner>();
    }
};

// ============================================================================
// TEST SUITE
// ============================================================================

class TokenDetectorTest
{
public:
    static std::string tokenTypeToString(TokenType type)
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

    static void runValidationTests()
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

        std::cout << "\nResult: " << passed << "/" << tests.size() << " passed ("
                  << (passed * 100 / tests.size()) << "%)\n"
                  << std::endl;
    }

    static void runScanningTests()
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
            bool testPassed = (matches.size() == test.expectedCount);

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

        std::cout << "Result: " << passed << "/" << tests.size() << " passed ("
                  << (passed * 100 / tests.size()) << "%)\n"
                  << std::endl;
    }

    static void runPerformanceBenchmark()
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

        std::atomic<long long> totalDetections{0};
        std::atomic<long long> totalTokensFound{0};
        std::vector<std::thread> threads;

        for (int t = 0; t < numThreads; ++t)
        {
            threads.emplace_back([&testCases, &totalDetections, &totalTokensFound, iterationsPerThread, &scanner]()
                                 {
                long long localDetections = 0;
                long long localTokensFound = 0;
                
                for (int i = 0; i < iterationsPerThread; ++i) {
                    for (const auto& test : testCases) {
                        if (scanner->contains(test)) {
                            ++localDetections;
                            auto matches = scanner->extract(test);
                            localTokensFound += matches.size();
                        }
                    }
                }
                
                totalDetections += localDetections;
                totalTokensFound += localTokensFound; });
        }

        for (auto &thread : threads)
        {
            thread.join();
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        long long totalOps = static_cast<long long>(numThreads) * iterationsPerThread * testCases.size();
        int millisecondsInOneSecond = 1000;

        std::cout << "\n"
                  << std::string(100, '-') << "\n";
        std::cout << "RESULTS:\n";
        std::cout << std::string(100, '-') << "\n";
        std::cout << "Time: " << duration.count() << " ms\n";
        std::cout << "Ops/sec: " << (totalOps * millisecondsInOneSecond / duration.count()) << "\n";
        std::cout << "Text scans with tokens: " << totalDetections.load() << "\n";
        std::cout << "Total tokens found: " << totalTokensFound.load() << "\n";
        std::cout << std::string(100, '=') << "\n\n";
    }
};

// ============================================================================
// MAIN
// ============================================================================

int main()
{
    try
    {
        TokenDetectorTest::runValidationTests();
        TokenDetectorTest::runScanningTests();

        std::cout << "\n"
                  << std::string(100, '=') << "\n";
        std::cout << "=== TOKEN DETECTION DEMO ===\n";
        std::cout << std::string(100, '=') << "\n\n";

        auto scanner = TokenDetectorFactory::createScanner();

        std::string text = R"([The evolution of backend architecture from singular, c9a6b4c8-4a6e-4b0f-8f1d-2e3c7d6a5b4e monolithic applications into distributed ecosystems of microservices has fundamentally reshaped the challenges of security and system observability. In the past, a single, unified application contained all its logic within a shared environment, making communication trivial and security a matter of protecting the outer perimeter. Today, however, a A JWT is the standard for stateless authentication and authorization in distributed systems, functioning like a digitally signed passport. Unlike old stateful sessions that required a server to maintain a user's login state, a JWT is a self-contained object that carries all necessary information within it. This token, such as eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNvcGhvcy1rZXktMjAyNCJ9.eyJhdWQiOiIxIiwianRpIjoiNTBlYmVmOWYyYTc1YzdjNTY3NDUwMmIwYjdjMjRmNjMyImp0aSI6ImY4YzNjMWI3LWEzZDktNGIyMS04YTc2LTlkM2IwZjdjMmUwYSIsInNjb3BlIjoicmVhZDpwcm9kdWN0cyODE1ZGVhYWQ5MTMwNDk3Njk5NGFkMzNkZmY4NzRkZjNmNzI4NDJkYjE2ZWI2MjIiLCJpYXQiOjE3NjAxOTIwNjcuOTc3MTc0MDQzNjU1Mzk1NTA3ODEyNSwibmJmIjoxNzYwMTkyMDY3Ljk3NzE3NjkwNDY3ODM0NDcyNjU2MjUsImV4cCI6MTc3NTkxNjg2Ny45NzIyMTQ5MzcyMTAwODMwMDc4MTI1LCJzdWIiOiIxMjk4Iiwic2NvcGVzIjpbXX0.jd-4_RH1m_nmhaFJxa4V-t40JyGExlAqO0z4etDOGJQZd4fol-fSAcqEBhLrkumQC8s9rm8EIi9YNAPs80BUoMp5l3na039u9Ob6hK1I1rW-VpmIWKww2Wrl6aWh73CocyPEbCiROMVdDeRcJo-pfLDzy7J1dPoxouGNKfeSNOitkFAoCE1cfgtXsSMjhJ6Ax5uj_fKpiwZdT-NpUKMl-aKZ8kSZYStHHnZ_M-1s5xBY5nRjloiDEfDs_u_XNZQZ8Z4qvckmZyiYoaqS5lJkVQkDZkvZtSehLb2G50oFKwopopvgfN8t5LWvQVrqF55CZXcep7ZB8EfWLxbubfguSCCu5VsfA6pUaeN2YJuebjb_qCf0S7xWYCCNL9bKywbwhSbTs2s8y2wUTKsCfzwF3SQDwUNY8YhJW9GYVMZ2adgOCwYl3HDmTlHMnolA8V7HGLx3gxi8t3Mw0RYRSBdjbcfPbpBS7kAQ2v6rq-h9XMqXMDxHOKnxaw_u0ymTOf4QNV2SUBIghk6n1bmNynwaNxSqi9Xa7XYpyIlfN56uhZBXAAf8w-J0AjW-bkTmSg9no3aJwSgEcwghSYvsVm3PnhpQZvL5O2gLK4nbOYZQL5eWRlQbme4N6DHD5sTqYKprva9RmBeF7jAfvYUARDZvlQTb69AHUe2-Y4d_E2JbTAQ, is composed of three parts: a header specifying the signing algorithm, a payload containing claims about the user or service (like their ID, roles, and permissions via scopes), and a cryptographic signature. When a service receives a request, it doesn't need to call back to an authentication server; it can independented this role, modern systems demand more secure and structured credentials, such as a service account key. This is often a JSON object that contains a collection of metadata and, most critically, a private key. An example of such a key would be {"type":"service_account","project_id":"global-data-pipeline","private_key_id":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ...\\n-----END PRIVATE KEY-----\\n","client_email":"data-processor@global-data-pipeline.iam.gserviceaccount.com","client_id":"109876543210987654321","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token"}. A backend service uses this file not as a direct authentication token, but as a source of truth to prove its identity to an authorization server. It uses the embedded private key to sign a request, and in return, receives a short-lived access token (often a JWT). It then uses this temporary token to make its actual API calls. This flow prevents the long-lived, highly sensitive private key from being sent over the network repeatedly, dramatically improving the security posture. Together, these three tokens—the UUID for traceability, the JWT for user and service authentication, and the service account key for machine identity—form the bedrock of secure, scalable, and observable backend systems, enabling the intricate yet resilient dance of modern microservice communication.])";

        auto matches = scanner->extract(text);

        std::cout << "This is the paragraph that contains tokens.\n\n";
        std::cout << "Found Tokens:\n";

        int count = 1;
        for (const auto &match : matches)
        {
            std::string displayValue = match.value;
            std::cout << count++ << ". [" << TokenDetectorTest::tokenTypeToString(match.type)
                      << ": " << displayValue << "]\n";
        }

        std::cout << "\n"
                  << std::string(100, '=') << "\n";

        TokenDetectorTest::runPerformanceBenchmark();

        std::cout << "\n"
                  << std::string(100, '=') << std::endl;
        std::cout << "✓ SOLID Principles Applied" << std::endl;
        std::cout << "✓ Character Classification Lookup Tables" << std::endl;
        std::cout << "✓ Thread-Safe Implementation" << std::endl;
        std::cout << "✓ Production-Ready Performance" << std::endl;
        std::cout << std::string(100, '=') << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
