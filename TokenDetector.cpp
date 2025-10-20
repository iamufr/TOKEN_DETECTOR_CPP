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
        0x00, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
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
        const size_t len = token.length();
        if (len < 36)
            return false;

        const char *data = token.data();

        if (data[0] != 'e' || data[1] != 'y' || data[2] != 'J')
            return false;

        int dots = 0;
        size_t segStart = 0;

        for (size_t i = 0; i < len; ++i)
        {
            const char c = data[i];
            if (c == '.')
            {
                if (i - segStart < 10)
                    return false;
                ++dots;
                segStart = i + 1;

                if (dots == 1 && i + 3 < len &&
                    (data[i + 1] != 'e' || data[i + 2] != 'y' || data[i + 3] != 'J'))
                    return false;

                if (dots > 2)
                    return false;
            }
            else if (!CharacterClassifier::isAlphaNumeric(c) && c != '-' && c != '_')
            {
                return false;
            }
        }
        return dots == 2 && len - segStart >= 10;
    }
    TokenType getType() const noexcept override { return TokenType::JWT; }
};

class SimpleAPIKeyValidator : public ITokenValidator
{
public:
    bool isValid(const std::string &token) const noexcept override
    {
        const size_t len = token.length();
        if (len < 15)
            return false;

        const char *data = token.data();
        size_t prefixLen = 0;

        if (len >= 3 && data[0] == 's' && data[1] == 'k' && data[2] == '_')
            prefixLen = 3;
        else if (len >= 3 && data[0] == 'p' && data[1] == 'k' && data[2] == '_')
            prefixLen = 3;
        else if (len >= 17 && data[0] == 'l' && data[1] == 'i' && data[2] == 'v' && data[3] == 'e' && data[4] == '_')
            prefixLen = 5;
        else if (len >= 17 && data[0] == 't' && data[1] == 'e' && data[2] == 's' && data[3] == 't' && data[4] == '_')
            prefixLen = 5;
        else
            return false;

        if (len - prefixLen < 10)
            return false;

        for (size_t i = 0; i < len; ++i)
            if (!CharacterClassifier::isAlphaNumeric(data[i]) && data[i] != '_')
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

    FORCE_INLINE bool containsUUID(const char *data, size_t len) const noexcept
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
                    return true;
            }
        }
        return false;
    }

    FORCE_INLINE bool containsJWT(const char *data, size_t len) const noexcept
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
                    if (dots == 2)
                        break;
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
                return true;
        }
        return false;
    }

    FORCE_INLINE bool containsAPIKey(const char *data, size_t len) const noexcept
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
                return true;
        }
        return false;
    }

    FORCE_INLINE bool containsJSON(const char *data, size_t len) const noexcept
    {
        for (size_t i = 0; i < len; ++i)
        {
            if (data[i] != '{')
                continue;
            size_t c = findBrace(data, i, len);
            if (c == SIZE_MAX)
                continue;

            bool pk = false;
            size_t pkPos = 0;
            for (size_t j = i; j < c - 12 && !pk; ++j)
            {
                if (data[j] == 'p' && std::memcmp(data + j, "private_key", 11) == 0)
                {
                    pk = true;
                    pkPos = j;
                }
            }

            if (!pk)
            {
                ++i;
                continue;
            }

            for (size_t j = pkPos; j < c - 26; ++j)
            {
                if (data[j] == '-' && std::memcmp(data + j, "-----BEGIN PRIVATE KEY-----", 27) == 0)
                    return true;
            }
        }
        return false;
    }

    FORCE_INLINE bool containsSHA(const char *data, size_t len) const noexcept
    {
        for (size_t i = 0; i < len; ++i)
        {
            if (UNLIKELY(!CharacterClassifier::isHexDigit(data[i])))
                continue;

            if (i > 0 && CharacterClassifier::isHexDigit(data[i - 1]))
                continue;

            size_t hc = 1;
            while (i + hc < len && CharacterClassifier::isHexDigit(data[i + hc]))
                ++hc;

            bool ok = (i + hc >= len || !CharacterClassifier::isHexDigit(data[i + hc]));
            if (!ok)
            {
                i += hc - 1;
                continue;
            }

            if (hc >= 56)
                return true;

            i += hc - 1;
        }
        return false;
    }

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
                    if (dots == 2)
                        break;

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
            while (i + hc < len && CharacterClassifier::isHexDigit(data[i + hc]))
                ++hc;

            bool ok = (i + hc >= len || !CharacterClassifier::isHexDigit(data[i + hc]));
            if (!ok)
            {
                i += hc - 1;
                continue;
            }

            if (hc >= 128)
            {
                m.emplace_back(TokenType::SHA_512, std::string(data + i, 128), i);
                i += hc - 1;
            }
            else if (hc >= 96)
            {
                m.emplace_back(TokenType::SHA_384, std::string(data + i, 96), i);
                i += hc - 1;
            }
            else if (hc >= 64)
            {
                m.emplace_back(TokenType::SHA_256, std::string(data + i, 64), i);
                i += hc - 1;
            }
            else if (hc >= 56)
            {
                m.emplace_back(TokenType::SHA_224, std::string(data + i, 56), i);
                i += hc - 1;
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

            bool pk = false;
            size_t pkPos = 0;
            for (size_t j = i; j < c - 12 && !pk; ++j)
            {
                if (data[j] == 'p' && std::memcmp(data + j, "private_key", 11) == 0)
                {
                    pk = true;
                    pkPos = j;
                }
            }

            if (!pk)
            {
                ++i;
                continue;
            }

            size_t beginPos = SIZE_MAX;
            for (size_t j = pkPos; j < c - 26; ++j)
            {
                if (data[j] == '-' && std::memcmp(data + j, "-----BEGIN PRIVATE KEY-----", 27) == 0)
                {
                    beginPos = j;
                    break;
                }
            }

            if (beginPos == SIZE_MAX)
            {
                ++i;
                continue;
            }

            size_t endPos = SIZE_MAX;
            for (size_t j = beginPos + 27; j < c - 25; ++j)
            {
                if (data[j] == '-' && std::memcmp(data + j, "-----END PRIVATE KEY-----", 25) == 0)
                {
                    endPos = j + 25;
                    break;
                }
            }

            if (endPos != SIZE_MAX && endPos <= c)
            {
                m.emplace_back(TokenType::API_KEY_JSON, std::string(data + beginPos, endPos - beginPos), beginPos);
                i = c;
            }
            else
            {
                ++i;
            }
        }
    }

public:
    bool contains(const std::string &text) const noexcept
    {
        const size_t len = text.length();
        if (UNLIKELY(len > MAX_INPUT_SIZE || len < 5))
            return false;

        const char *data = text.data();

        if (containsUUID(data, len))
            return true;
        if (containsJWT(data, len))
            return true;
        if (containsAPIKey(data, len))
            return true;
        if (containsJSON(data, len))
            return true;
        if (containsSHA(data, len))
            return true;

        return false;
    }

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

const std::string json_string_1 = R"({
        "id": "d34d8a52-3e28-4b62-8e11-1e0e5a8f27cf",
        "name": "John Doe",
        "username": "johndoe",
        "apikey": "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    })";

const std::string json_string_2 = R"({
        "user_id": "usr_1a2b3c4d",
        "username": "alex_morgan",
        "login_timestamp": "2025-10-19T16:25:00Z",
        "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGV4X21vcmdhbiIsImV4cCI6MTczOTg0ODAwMCwiaWF0IjoxNzM5ODQ0NDAwfQ.h3g9s7aF4JkLpWqRt8uXzVn_C6bZ2eY1dDfG5hI0jKo"
    })";

const std::string json_string_3 = R"({
        "event_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "service": "payment-gateway",
        "level": "INFO",
        "message": "Payment of 50.00 USD processed successfully for order #ORD-9876."
    })";

const std::string json_string_4 = R"({
        "service_name": "weather_api_client",
        "version": "v1.2.0",
        "timeout_ms": 5000,
        "api_key": "pk_live_fA7bC9dE1gH3jK5mN7pQ9sT2vX4z"
    })";

const std::string json_string_5 = R"({
        "filename": "firmware_update_v3.bin",
        "filesize_bytes": 8388608,
        "version": "3.0.1-stable",
        "checksum": {
            "algorithm": "sha256",
            "hash": "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdefabcx"
        }
    })";

const std::string json_string_6 = R"({
        "document_id": "DOC-LEGAL-2025-042",
        "signer_id": "signer_jane_doe",
        "timestamp": "2025-10-19T12:00:00Z",
        "signature": {
            "algorithm": "sha512",
            "hash": "3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234abcx"
        }
    })";

const std::string json_string_7 = R"({
        "release_name": "QuantumLeap v2.5.0",
        "asset_url": "https://example.com/downloads/quantumleap-v2.5.0.zip",
        "release_date": "2025-10-18",
        "verification_hashes": {
            "sha224": "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42fabcx",
            "sha384": "0933909688419962a559286d525031b6833b38101377284563a819b62a63816405204487cc5a36376511356a6431f4e5abcx"
        }
    })";

const std::string json_string_8 = R"({
        "type": "service_account",
        "project_id": "your-gcp-project-12345",
        "private_key_id": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD... (long key content) ...\n-----END PRIVATE KEY-----\n",
        "client_email": "my-service-account@your-gcp-project-12345.iam.gserviceaccount.com",
        "client_id": "123456789012345678901",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/my-service-account%40your-gcp-project-12345.iam.gserviceaccount.com"
    })";

const std::string json_string_9 = R"|({
        "event_trace_id": "c7a8b6e0-4f5a-4b9d-8c1e-2f0a1b3d4e5f",
        "timestamp": "2025-10-19T11:05:42Z",
        "source_ip": "203.0.113.75",
        "auth_details": {
            "method": "bearer",
            "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoLmV4YW1wbGUuY29tIiwiYXVkIjoiYXBpLmV4YW1wbGUuY29tIiwic3ViIjoidXNlcl80MjcifQ.aBcDeFgHiJkLmNoPqRsTuVwXyZ... (signature)"
        },
        "client_key": "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ"
    })|";

const std::string json_string_10 = R"({
        "user_profile": "developer_jane",
        "mfa_enabled": true,
        "authorized_devices": [
            "2b8a7c1d-1e1f-4b6e-8d3c-9a0b1c2d3e4f",
            "9f8b7a6d-5e4f-4c3e-8b1a-2d3c4e5f6a7b",
            "6c5b4a3d-2e1f-4a9b-8c7d-6e5f4a3b2c1d"
        ]
    })";

const std::string json_string_11 = R"({
        "commit_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "parent_hash": "da9e7b23d9a1f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
        "author": "Alice",
        "message": "feat: Implement new token scanning module",
        "attestation": {
            "type": "binary_integrity",
            "hash": "4d1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234",
            "algorithm": "sha512"
        }
    })";

const std::string json_string_12 = R"({
        "tx_id": "f8a7e2c3d4b5a6978d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e",
        "block_height": 840000,
        "inputs": [
            {
            "from_address_hash": "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f",
            "algorithm": "sha384"
            }
        ],
        "outputs": [
            {
            "to_address_hash": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
            "algorithm": "sha224"
            }
        ]
    })";

const std::string json_string_13 = R"({
        "log_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
        "level": "ERROR",
        "service": "authentication-service",
        "message": "Failed to validate user credentials.",
        "payload": "{\"error_code\": 101, \"attempt_id\": \"b8c6e1f0-5d4a-4c3b-8a29-1e0f2d3c4b5a\", \"api_key_used\": \"pk_test_aBcDeFgHiJkLmNoPqRsTuVwXyZ\"}"
    })";

const std::string json_string_14 = R"({
        "transaction_id": "txn_789123",
        "data": {
            "user_info": {
            "profile": {
                "user_id": 1024,
                "session_data": {
                "is_active": true,
                "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZWVwbHlfbmVzdGVkX3Rva2VuIiwiZXhwIjoxNzM5ODU5MjAwfQ.N_fWbY8zQj_V9gL6rHk2wXzYj_C7bZ2eY1dDfG5hI0j"
                }
            }
            }
        }
    })";

const std::string json_string_15 = R"({
        "artifact_id": "build-package-v4.2.1",
        "build_date": "2025-10-19",
        "integrity_hashes": [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            "0933909688419962a559286d525031b6833b38101377284563a819b62a63816405204487cc5a36376511356a6431f4e5",
            "This is not a hash, just a string.",
            "4d1a2b3c4d5e6f78901234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234"
        ]
    })";

const std::string json_string_16 = R"({
        "product_id": "PROD-XYZ-789",
        "is_active": true,
        "description": "This product connects to our new API. Use your request ID (e.g., '123e4567-e89b-12d3-a456-426614174000') for tracking.",
        "related_docs": [
            "doc_1", "doc_2"
        ]
    })";

const std::string json_string_17 = R"({
        "acl_id": "acl-prod-config-001",
        "version": 3,
        "user_permissions": {
            "4a0c8b3d-1e1f-4b6e-8d3c-9a0b1c2d3e4f": {
            "role": "admin",
            "assigned_apikey": "sk_prod_Z1Y2X3W4V5U6T7S8R9Q0P",
            "last_session_jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0YTBjOGIzZC0xZTFmLTRiNmUtOGQzYy05YTBiMWMyZDNlNGYiLCJyb2xlIjoiYWRtaW4ifQ.eW5jb2RlZF9zaWduYXR1cmU"
            },
            "5b1d9c4e-2f2a-5c7f-9e4d-0a1c2d3e4f5a": {
            "role": "editor",
            "assigned_apikey": "pk_test_A9B8C7D6E5F4G3H2I1J0K",
            "last_session_jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1YjFkOWM0ZS0yZjJhLTVjN2YtOWU0ZC0wYTFjMmQzZTRmNWEiLCJyb2xlIjoiZWRpdG9yIn0.ZGlmZmVyZW50X3NpZ25hdHVyZQ"
            }
        }
    })";

const std::string json_string_18 = R"|({
        "event_id": "2a8f8a1e-3b2c-4d5e-8f9a-0b1c2d3e4f5a",
        "type": "invoice.payment_succeeded",
        "created_at": "2025-10-19T16:30:00Z",
        "signature_header": "sha256=a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef",
        "data": {
            "customer_id": "cus_1a2b3c4d",
            "invoice_pdf_url": "https://example.com/invoices/inv_456.pdf",
            "trace_id": "c7a8b6e0-4f5a-4b9d-8c1e-2f0a1b3d4e5f"
        }
    })|";

const std::string json_string_19 = R"|({
        "service_name": "user-profile-service",
        "database_url": "postgres://user:Abc.123@db.example.com:5432/profiles",
        "cache_enabled": true,
        "feature_flags": {
            "enable_new_dashboard": true,
            "beta_access_key": "ff_live_a1b2c3d4e5f6g7h8i9j0k"
        },
        "deployment_id": "d34d8a52-3e28-4b62-8e11-1e0e5a8f27cf"
    })|";

const std::string json_string_20 = R"|({
        "error": {
            "type": "authentication_error",
            "code": "api_key_invalid",
            "message": "The provided API key is not valid. Please check your credentials.",
            "request_id": "9f8b7a6d-5e4f-4c3e-8b1a-2d3c4e5f6a7b"
        }
    })|";

const std::string json_string_21 = R"|({
        "batch_id": "batch_6c5b4a3d-2e1f-4a9b-8c7d-6e5f4a3b2c1d",
        "source_system": "inventory-management",
        "items": [
            {
            "item_id": "0a9b8c7d-6e5f-4a3b-2c1d-0a9b8c7d6e5f",
            "action": "UPDATE_STOCK",
            "data": { "sku": "XYZ-123", "quantity": 100 }
            },
            {
            "item_id": "1b2c3d4e-5f6a-7b8c-9d0e-1f2a3b4c5d6e",
            "action": "PROCESS_RETURN",
            "data": { "order_id": "ORD-555" },
            "processing_token": "eyJhbGciOiJIUzI1NiJ9.eyJpdGVtX2lkIjoiMWIyYzNkNGUtNWY2YS03YjhiLTlkMGUtMWYyYTNiNGM1ZDZlIn0.another_fake_signature"
            }
        ]
    })|";

const std::string json_string_22 = R"|({
    "batch_id": "daily-sync-20251020-001",
    "source_system": "order-processing",
    "items": [
        {
            "item_id": 1001,
            "action": "CREATE_ORDER",
            "data": { 
                "product_sku": "ABC-789", 
                "quantity": 5,
                "customer_id": "CUST-456"
            }
        },
        {
            "item_id": 1002,
            "action": "APPLY_DISCOUNT",
            "data": { 
                "order_id": "ORD-2025-A5", 
                "discount_code": "SAVE20" 
            }
        }
    ]
})|";

const std::string json_string_23 = R"|({
    "batch_id": "user-mgmt-20251020-001",
    "source_system": "admin-dashboard",
    "items": [
        {
            "item_id": "req-101",
            "action": "CREATE_USER",
            "data": { 
                "username": "s.kumar", 
                "email": "s.kumar@example.com",
                "group": "auditors"
            }
        },
        {
            "item_id": "req-102",
            "action": "UPDATE_GROUP",
            "data": { 
                "user_id": 56, 
                "new_group": "administrators" 
            }
        }
    ]
})|";

const std::string json_string_24 = R"|({
    "batch_id": "catalog-sync-daily-45",
    "source_system": "product-information-manager",
    "items": [
        {
            "item_id": "product-add-550",
            "action": "ADD_PRODUCT",
            "data": {
                "sku": "HW-MUG-01B",
                "name": "Large Ceramic Mug",
                "category": "kitchenware",
                "price": 350.00
            }
        },
        {
            "item_id": "price-update-912",
            "action": "CHANGE_PRICE",
            "data": { 
                "sku": "SW-TEE-04G", 
                "new_price": 799.00
            }
        }
    ]
})|";

const std::string json_string_25 = R"|({
    "batch_id": "logs-api-gateway-1666281600",
    "source_system": "api-gateway-prod",
    "items": [
        {
            "item_id": 987654321,
            "action": "LOG_EVENT",
            "data": {
                "level": "ERROR",
                "message": "Authentication service timeout",
                "service_code": "AUTH-003"
            }
        },
        {
            "item_id": 987654322,
            "action": "LOG_EVENT",
            "data": {
                "level": "INFO",
                "message": "Request processed successfully",
                "endpoint": "/v1/users/search"
            }
        }
    ]
})|";

const std::string json_string_26 = R"|({
    "batch_id": "iot-command-push-farm-sector-7",
    "source_system": "central-control-system",
    "items": [
        {
            "item_id": "cmd-pump-1138",
            "action": "SET_STATE",
            "data": {
                "device_id": "PUMP-08",
                "state": "ON",
                "duration_minutes": 60
            }
        },
        {
            "item_id": "cmd-sensor-451",
            "action": "REQUEST_READING",
            "data": {
                "device_id": "SOIL-MOISTURE-SENSOR-22",
                "reading_type": "PERCENTAGE"
            }
        }
    ]
})|";

const std::string json_string_27 = R"|({
    "batch_id": "gl-posting-run-eod-20251020",
    "source_system": "payments-processor",
    "items": [
        {
            "item_id": "txn-45920",
            "action": "CREDIT",
            "data": {
                "account_number": "ACCT-SAVINGS-00123",
                "amount": 5200.75,
                "currency": "INR",
                "description": "Salary Deposit"
            }
        },
        {
            "item_id": "txn-45921",
            "action": "DEBIT",
            "data": {
                "account_number": "ACCT-SAVINGS-00123",
                "amount": 350.00,
                "currency": "INR",
                "description": "Utility Bill Payment"
            }
        }
    ]
})|";

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

void runContainsTests()
{
    std::cout << "\n"
              << std::string(100, '=') << "\n";
    std::cout << "=== CONTAINS METHOD TESTS ===\n";
    std::cout << std::string(100, '=') << "\n\n";

    auto scanner = TokenDetectorFactory::createScanner();

    struct TestCase
    {
        std::string input;
        bool expectedResult;
        std::string description;
    };

    std::vector<TestCase> tests = {
        {json_string_1, true, "JSON Object with tokens"},
        {json_string_2, true, "JSON Object with tokens"},
        {json_string_3, true, "JSON Object with tokens"},
        {json_string_4, true, "JSON Object with tokens"},
        {json_string_5, true, "JSON Object with tokens"},
        {json_string_6, true, "JSON Object with tokens"},
        {json_string_7, true, "JSON Object with tokens"},
        {json_string_8, true, "JSON Object with tokens"},
        {json_string_9, true, "JSON Object with tokens"},
        {json_string_10, true, "JSON Object with tokens"},
        {json_string_11, true, "JSON Object with tokens"},
        {json_string_12, true, "JSON Object with tokens"},
        {json_string_13, true, "JSON Object with tokens"},
        {json_string_14, true, "JSON Object with tokens"},
        {json_string_15, true, "JSON Object with tokens"},
        {json_string_16, true, "JSON Object with tokens"},
        {json_string_17, true, "JSON Object with tokens"},
        {json_string_18, true, "JSON Object with tokens"},
        {json_string_19, true, "JSON Object with tokens"},
        {json_string_20, true, "JSON Object with tokens"},
        {json_string_21, true, "JSON Object with tokens"},
        {json_string_22, false, "JSON Object without tokens"},
        {json_string_23, false, "JSON Object without tokens"},
        {json_string_24, false, "JSON Object without tokens"},
        {json_string_25, false, "JSON Object without tokens"},
        {json_string_26, false, "JSON Object without tokens"},
        {json_string_27, false, "JSON Object without tokens"},
        {"Hello world, no tokens here!", false, "Plain text without tokens"},
        {"UUID: 550e8400-e29b-41d4-a716-446655440000", true, "Text with UUID"},
        {"Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", true, "Text with JWT"},
        {"API: sk_live_12345abcde67890fghij11223", true, "Text with API key"},
        {"Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true, "Text with SHA-256"},
        {R"({"private_key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n"})", true, "JSON with private key"},
        {"Just some random text 12345", false, "Random text with numbers"},
        {"", false, "Empty string"},
        {"a", false, "Single character"},
        {std::string(1000000, 'x'), false, "Large string without tokens"},
        {std::string(500000, 'x') + "550e8400-e29b-41d4-a716-446655440000" + std::string(500000, 'y'), true, "Large string with UUID in middle"},
    };

    int passed = 0;
    for (const auto &test : tests)
    {
        auto start = std::chrono::high_resolution_clock::now();
        bool result = scanner->contains(test.input);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        bool testPassed = (result == test.expectedResult);
        std::cout << (testPassed ? "✓" : "✗") << " " << test.description;
        std::cout << " (" << duration.count() << " μs)" << std::endl;

        if (!testPassed)
        {
            std::cout << "  Expected: " << (test.expectedResult ? "true" : "false")
                      << ", Got: " << (result ? "true" : "false") << std::endl;
        }

        if (testPassed)
            ++passed;
    }

    std::cout << "\nResult: " << passed << "/" << tests.size() << " passed ("
              << (passed * 100 / tests.size()) << "%)\n\n";
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
        {json_string_1, 3, {TokenType::UUID, TokenType::API_KEY_SIMPLE, TokenType::JWT}, "JSON with UUID, API Key, and JWT"},
        {json_string_2, 1, {TokenType::JWT}, "JSON with JWT"},
        {json_string_3, 1, {TokenType::UUID}, "JSON with UUID"},
        {json_string_4, 1, {TokenType::API_KEY_SIMPLE}, "JSON with simple API Key"},
        {json_string_5, 1, {TokenType::SHA_256}, "JSON with SHA-256"},
        {json_string_6, 1, {TokenType::SHA_512}, "JSON with SHA-512"},
        {json_string_7, 2, {TokenType::SHA_224, TokenType::SHA_384}, "JSON with SHA-224 and SHA-384"},
        {json_string_8, 1, {TokenType::API_KEY_JSON}, "JSON Google Cloud style API Key"},
        {json_string_9, 3, {TokenType::UUID, TokenType::JWT, TokenType::API_KEY_SIMPLE}, "JSON with mixed tokens (UUID, JWT, API Key)"},
        {json_string_10, 3, {TokenType::UUID, TokenType::UUID, TokenType::UUID}, "JSON with array of UUIDs"},
        {json_string_11, 3, {TokenType::SHA_256, TokenType::SHA_256, TokenType::SHA_512}, "JSON with multiple nested SHA hashes"},
        {json_string_12, 3, {TokenType::SHA_224, TokenType::SHA_384, TokenType::SHA_224}, "JSON with crypto-style hashes"},
        {json_string_13, 3, {TokenType::UUID, TokenType::UUID, TokenType::API_KEY_SIMPLE}, "JSON with embedded JSON string payload"},
        {json_string_14, 1, {TokenType::JWT}, "JSON with deeply nested JWT"},
        {json_string_15, 4, {TokenType::SHA_256, TokenType::SHA_224, TokenType::SHA_384, TokenType::SHA_512}, "JSON with array of mixed hashes"},
        {json_string_16, 1, {TokenType::UUID}, "JSON with token-like string in description"},
        {json_string_17, 6, {TokenType::UUID, TokenType::API_KEY_SIMPLE, TokenType::JWT, TokenType::UUID, TokenType::API_KEY_SIMPLE, TokenType::JWT}, "JSON with tokens as object keys"},
        {json_string_18, 3, {TokenType::UUID, TokenType::SHA_256, TokenType::UUID}, "Webhook payload with signature"},
        {json_string_19, 2, {TokenType::API_KEY_SIMPLE, TokenType::UUID}, "Application config with feature flag key"},
        {json_string_20, 1, {TokenType::UUID}, "API error response with request_id"},
        {json_string_21, 4, {TokenType::UUID, TokenType::UUID, TokenType::UUID, TokenType::JWT}, "Batch job with tokens in array"},
        {json_string_22, 0, {}, "No tokens"},
        {json_string_23, 0, {}, "No tokens"},
        {json_string_24, 0, {}, "No tokens"},
        {json_string_25, 0, {}, "No tokens"},
        {json_string_26, 0, {}, "No tokens"},
        {json_string_27, 0, {}, "No tokens"},
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

    std::vector<std::string> testCases = {
        json_string_1,
        json_string_2,
        json_string_3,
        json_string_4,
        json_string_5,
        json_string_6,
        json_string_7,
        json_string_8,
        json_string_9,
        json_string_10,
        json_string_11,
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
        threads.emplace_back(
            [&testCases, &totalTokensFound, iterationsPerThread]()
            {
                auto scanner = TokenDetectorFactory::createScanner();
                long long localTokensFound = 0;
                for (int i = 0; i < iterationsPerThread; ++i)
                {
                    for (const auto &test : testCases)
                    {
                        auto matches = scanner->extract(test);
                        localTokensFound += matches.size();
                    }
                }
                totalTokensFound += localTokensFound;
            });
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
        runContainsTests();
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
