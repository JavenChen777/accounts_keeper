#include <windows.h>
#include <commctrl.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <shlobj.h>
#include <shellapi.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "resource.h"

#pragma comment(lib, "Comctl32.lib")

namespace {

constexpr UINT WM_TRAYICON = WM_APP + 1;
constexpr int HOTKEY_ID = 42;
constexpr int TRAY_UID = 7;

enum ControlId {
    IDC_LIST = 1001,
    IDC_PRODUCT = 1002,
    IDC_USERNAME = 1003,
    IDC_PASSWORD = 1004,
    IDC_ADDITIONAL = 1005,
    IDC_REFRESH = 1006,
    IDC_NEW = 1007,
    IDC_SAVE = 1008,
    IDC_DELETE = 1009,
    IDC_COPY_USER = 1010,
    IDC_COPY_PASS = 1011,
    IDC_SHOW_PASS = 1012,
    IDC_PROXY_ENABLE = 1013,
    IDC_PROXY = 1014,
    IDC_PROXY_USER = 1015,
    IDC_PROXY_PASS = 1016,
    IDC_STARTUP = 1017,
    IDC_SAVE_SETTINGS = 1018,
};

enum TrayCommand {
    IDM_TRAY_TOGGLE = 2001,
    IDM_TRAY_EXIT = 2002,
};

struct Account {
    std::string id;
    std::string encryptedProduct;
    std::string encryptedUsername;
    std::string encryptedPassword;
    std::string encryptedAdditional;
    std::wstring product;
    std::wstring username;
    std::wstring password;
    std::wstring additional;
    std::wstring createdAt;
    bool decryptOk = true;
};

struct Settings {
    bool proxyEnabled = false;
    std::wstring proxy;
    std::wstring proxyUser;
    std::wstring proxyPassword;
    bool startup = false;
};

struct AppState {
    HINSTANCE instance = nullptr;
    HWND hwnd = nullptr;
    HWND list = nullptr;
    HWND product = nullptr;
    HWND username = nullptr;
    HWND password = nullptr;
    HWND additional = nullptr;
    HWND status = nullptr;
    HWND btnShowPass = nullptr;
    HWND chkProxy = nullptr;
    HWND proxy = nullptr;
    HWND proxyUser = nullptr;
    HWND proxyPass = nullptr;
    HWND chkStartup = nullptr;
    HFONT font = nullptr;
    HFONT titleFont = nullptr;
    HBRUSH bgBrush = nullptr;
    HANDLE singleInstanceMutex = nullptr;
    Settings settings;
    std::vector<Account> rows;
    int selected = -1;
    bool passwordVisible = true;
    bool exiting = false;
    std::wstring supabaseUrl;
    std::wstring supabaseKey;
    std::wstring configPath;
    std::wstring backupPath;
};

AppState g;

void ActivateExistingInstance() {
    HWND existing = FindWindowW(L"AccountsKeeperWindow", nullptr);
    if (!existing) return;

    ShowWindow(existing, IsIconic(existing) ? SW_RESTORE : SW_SHOWNORMAL);
    SetForegroundWindow(existing);
}

std::wstring Utf8ToWide(const std::string& input) {
    if (input.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (len <= 0) return L"";
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), out.data(), len);
    return out;
}

std::string WideToUtf8(const std::wstring& input) {
    if (input.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), out.data(), len, nullptr, nullptr);
    return out;
}

std::wstring GetWindowTextString(HWND hwnd) {
    int len = GetWindowTextLengthW(hwnd);
    std::wstring text(len + 1, L'\0');
    if (len > 0) GetWindowTextW(hwnd, text.data(), len + 1);
    text.resize(len);
    return text;
}

void SetStatus(const std::wstring& text) {
    if (g.status) SetWindowTextW(g.status, text.c_str());
}

std::wstring GetEnvVar(const wchar_t* name) {
    DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0) return L"";
    std::wstring value(needed - 1, L'\0');
    GetEnvironmentVariableW(name, value.data(), needed);
    return value;
}

std::wstring AppDataDir() {
    PWSTR base = nullptr;
    std::wstring dir;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &base))) {
        dir = base;
        CoTaskMemFree(base);
    } else {
        wchar_t fallback[MAX_PATH]{};
        GetModuleFileNameW(nullptr, fallback, MAX_PATH);
        dir = fallback;
        size_t slash = dir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) dir.resize(slash);
    }
    dir += L"\\AccountsKeeper";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

std::string Base64Encode(const std::vector<BYTE>& data) {
    if (data.empty()) return "";
    DWORD chars = 0;
    CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &chars);
    std::string out(chars, '\0');
    if (!CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &chars)) {
        return "";
    }
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

std::vector<BYTE> Base64Decode(const std::string& text) {
    DWORD bytes = 0;
    if (!CryptStringToBinaryA(text.c_str(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64, nullptr, &bytes, nullptr, nullptr)) {
        return {};
    }
    std::vector<BYTE> out(bytes);
    if (!CryptStringToBinaryA(text.c_str(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64, out.data(), &bytes, nullptr, nullptr)) {
        return {};
    }
    out.resize(bytes);
    return out;
}

DATA_BLOB EntropyBlob() {
    static const char entropy[] = "AccountsKeeper.dpapi.v1";
    DATA_BLOB blob{};
    blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(entropy));
    blob.cbData = static_cast<DWORD>(sizeof(entropy) - 1);
    return blob;
}

std::string ProtectUtf8(const std::string& plain) {
    DATA_BLOB in{};
    in.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()));
    in.cbData = static_cast<DWORD>(plain.size());
    DATA_BLOB entropy = EntropyBlob();
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"AccountsKeeper", &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return "";
    }
    std::vector<BYTE> bytes(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return "dpapi:v1:" + Base64Encode(bytes);
}

bool UnprotectUtf8(const std::string& cipher, std::string& plain) {
    const std::string prefix = "dpapi:v1:";
    if (cipher.rfind(prefix, 0) != 0) {
        plain = cipher;
        return true;
    }
    std::vector<BYTE> bytes = Base64Decode(cipher.substr(prefix.size()));
    if (bytes.empty()) return false;
    DATA_BLOB in{};
    in.pbData = bytes.data();
    in.cbData = static_cast<DWORD>(bytes.size());
    DATA_BLOB entropy = EntropyBlob();
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return false;
    }
    plain.assign(reinterpret_cast<char*>(out.pbData), reinterpret_cast<char*>(out.pbData + out.cbData));
    LocalFree(out.pbData);
    return true;
}

std::wstring ProtectWideForStore(const std::wstring& plain) {
    return Utf8ToWide(ProtectUtf8(WideToUtf8(plain)));
}

std::wstring UnprotectWideFromStore(const std::string& cipher, bool& ok) {
    std::string plain;
    ok = UnprotectUtf8(cipher, plain);
    return ok ? Utf8ToWide(plain) : L"(decrypt failed)";
}

std::wstring IniRead(const wchar_t* section, const wchar_t* key, const wchar_t* fallback = L"") {
    wchar_t buffer[2048]{};
    GetPrivateProfileStringW(section, key, fallback, buffer, static_cast<DWORD>(std::size(buffer)), g.configPath.c_str());
    return buffer;
}

void IniWrite(const wchar_t* section, const wchar_t* key, const std::wstring& value) {
    WritePrivateProfileStringW(section, key, value.c_str(), g.configPath.c_str());
}

std::wstring ExePath() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    return path;
}

bool IsStartupEnabled() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return false;
    }
    wchar_t value[MAX_PATH * 2]{};
    DWORD bytes = sizeof(value);
    DWORD type = 0;
    LONG rc = RegQueryValueExW(key, L"AccountsKeeper", nullptr, &type, reinterpret_cast<BYTE*>(value), &bytes);
    RegCloseKey(key);
    return rc == ERROR_SUCCESS && type == REG_SZ && std::wstring(value).find(ExePath()) != std::wstring::npos;
}

bool SetStartupEnabled(bool enabled) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        return false;
    }
    LONG rc = ERROR_SUCCESS;
    if (enabled) {
        std::wstring value = L"\"" + ExePath() + L"\"";
        rc = RegSetValueExW(key, L"AccountsKeeper", 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                            static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    } else {
        rc = RegDeleteValueW(key, L"AccountsKeeper");
        if (rc == ERROR_FILE_NOT_FOUND) rc = ERROR_SUCCESS;
    }
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

void LoadSettings() {
    g.configPath = AppDataDir() + L"\\settings.ini";
    g.backupPath = AppDataDir() + L"\\accounts_backup.json";
    g.settings.proxyEnabled = IniRead(L"proxy", L"enabled", L"0") == L"1";
    g.settings.proxy = IniRead(L"proxy", L"server");
    g.settings.proxyUser = IniRead(L"proxy", L"user");
    std::wstring protectedPassword = IniRead(L"proxy", L"password");
    bool ok = true;
    g.settings.proxyPassword = protectedPassword.empty() ? L"" : UnprotectWideFromStore(WideToUtf8(protectedPassword), ok);
    if (!ok) g.settings.proxyPassword.clear();
    g.settings.startup = IsStartupEnabled();
}

void SaveSettingsFromUi() {
    g.settings.proxyEnabled = SendMessageW(g.chkProxy, BM_GETCHECK, 0, 0) == BST_CHECKED;
    g.settings.proxy = GetWindowTextString(g.proxy);
    g.settings.proxyUser = GetWindowTextString(g.proxyUser);
    g.settings.proxyPassword = GetWindowTextString(g.proxyPass);
    g.settings.startup = SendMessageW(g.chkStartup, BM_GETCHECK, 0, 0) == BST_CHECKED;

    IniWrite(L"proxy", L"enabled", g.settings.proxyEnabled ? L"1" : L"0");
    IniWrite(L"proxy", L"server", g.settings.proxy);
    IniWrite(L"proxy", L"user", g.settings.proxyUser);
    IniWrite(L"proxy", L"password", g.settings.proxyPassword.empty() ? L"" : ProtectWideForStore(g.settings.proxyPassword));
    SetStartupEnabled(g.settings.startup);
    SetStatus(L"Settings saved");
}

std::string JsonEscape(const std::string& input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                const char* hex = "0123456789abcdef";
                out << "\\u00" << hex[(c >> 4) & 0xF] << hex[c & 0xF];
            } else {
                out << c;
            }
        }
    }
    return out.str();
}

std::string JsonString(const std::string& value) {
    return "\"" + JsonEscape(value) + "\"";
}

std::wstring RequestErrorMessage(const std::wstring& prefix, DWORD status, const std::wstring& error, const std::string& response) {
    std::wostringstream oss;
    oss << prefix;
    if (status) oss << L" (HTTP " << status << L")";
    if (!error.empty()) oss << L": " << error;
    if (!response.empty()) oss << L" " << Utf8ToWide(response.substr(0, 300));
    return oss.str();
}

bool ReadUtf8File(const std::wstring& path, std::string& text, std::wstring& error) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD last = GetLastError();
        if (last == ERROR_FILE_NOT_FOUND) {
            text.clear();
            return true;
        }
        std::wostringstream oss;
        oss << L"Open backup failed: " << last;
        error = oss.str();
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart > 16 * 1024 * 1024) {
        CloseHandle(file);
        error = L"Backup file is too large or unreadable";
        return false;
    }

    text.assign(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    BOOL ok = text.empty() || ReadFile(file, text.data(), static_cast<DWORD>(text.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok) {
        std::wostringstream oss;
        oss << L"Read backup failed: " << GetLastError();
        error = oss.str();
        return false;
    }
    text.resize(read);
    return true;
}

bool WriteUtf8File(const std::wstring& path, const std::string& text, std::wstring& error) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        std::wostringstream oss;
        oss << L"Open backup for write failed: " << GetLastError();
        error = oss.str();
        return false;
    }
    DWORD written = 0;
    BOOL ok = text.empty() || WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    CloseHandle(file);
    if (!ok || written != text.size()) {
        std::wostringstream oss;
        oss << L"Write backup failed: " << GetLastError();
        error = oss.str();
        return false;
    }
    return true;
}

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };
    Type type = Type::Null;
    bool boolean = false;
    std::string numberText;
    std::string string;
    std::vector<JsonValue> array;
    std::map<std::string, JsonValue> object;

    const JsonValue* Get(const std::string& key) const {
        auto it = object.find(key);
        return it == object.end() ? nullptr : &it->second;
    }

    std::string AsString() const {
        if (type == Type::String) return string;
        if (type == Type::Number) return numberText;
        if (type == Type::Bool) return boolean ? "true" : "false";
        return "";
    }
};

class JsonParser {
public:
    explicit JsonParser(std::string text) : text_(std::move(text)) {}

    bool Parse(JsonValue& out) {
        Skip();
        if (!ParseValue(out)) return false;
        Skip();
        return pos_ == text_.size();
    }

private:
    void Skip() {
        while (pos_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos_]))) ++pos_;
    }

    bool Consume(char ch) {
        Skip();
        if (pos_ < text_.size() && text_[pos_] == ch) {
            ++pos_;
            return true;
        }
        return false;
    }

    bool ParseValue(JsonValue& out) {
        Skip();
        if (pos_ >= text_.size()) return false;
        char ch = text_[pos_];
        if (ch == '"') {
            out.type = JsonValue::Type::String;
            return ParseString(out.string);
        }
        if (ch == '{') return ParseObject(out);
        if (ch == '[') return ParseArray(out);
        if (ch == 't' && Match("true")) {
            out.type = JsonValue::Type::Bool;
            out.boolean = true;
            return true;
        }
        if (ch == 'f' && Match("false")) {
            out.type = JsonValue::Type::Bool;
            out.boolean = false;
            return true;
        }
        if (ch == 'n' && Match("null")) {
            out.type = JsonValue::Type::Null;
            return true;
        }
        if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch))) {
            return ParseNumber(out);
        }
        return false;
    }

    bool Match(const char* literal) {
        size_t len = std::strlen(literal);
        if (text_.compare(pos_, len, literal) != 0) return false;
        pos_ += len;
        return true;
    }

    bool ParseString(std::string& out) {
        if (!Consume('"')) return false;
        std::ostringstream result;
        while (pos_ < text_.size()) {
            unsigned char ch = static_cast<unsigned char>(text_[pos_++]);
            if (ch == '"') {
                out = result.str();
                return true;
            }
            if (ch != '\\') {
                result << ch;
                continue;
            }
            if (pos_ >= text_.size()) return false;
            char esc = text_[pos_++];
            switch (esc) {
            case '"': result << '"'; break;
            case '\\': result << '\\'; break;
            case '/': result << '/'; break;
            case 'b': result << '\b'; break;
            case 'f': result << '\f'; break;
            case 'n': result << '\n'; break;
            case 'r': result << '\r'; break;
            case 't': result << '\t'; break;
            case 'u':
                if (!ParseUnicodeEscape(result)) return false;
                break;
            default:
                return false;
            }
        }
        return false;
    }

    bool ParseUnicodeEscape(std::ostringstream& out) {
        if (pos_ + 4 > text_.size()) return false;
        unsigned int cp = 0;
        for (int i = 0; i < 4; ++i) {
            char ch = text_[pos_++];
            cp <<= 4;
            if (ch >= '0' && ch <= '9') cp += ch - '0';
            else if (ch >= 'a' && ch <= 'f') cp += 10 + ch - 'a';
            else if (ch >= 'A' && ch <= 'F') cp += 10 + ch - 'A';
            else return false;
        }
        if (cp <= 0x7F) {
            out << static_cast<char>(cp);
        } else if (cp <= 0x7FF) {
            out << static_cast<char>(0xC0 | ((cp >> 6) & 0x1F));
            out << static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out << static_cast<char>(0xE0 | ((cp >> 12) & 0x0F));
            out << static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out << static_cast<char>(0x80 | (cp & 0x3F));
        }
        return true;
    }

    bool ParseNumber(JsonValue& out) {
        size_t start = pos_;
        if (text_[pos_] == '-') ++pos_;
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        if (pos_ < text_.size() && text_[pos_] == '.') {
            ++pos_;
            while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) ++pos_;
            while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        }
        out.type = JsonValue::Type::Number;
        out.numberText = text_.substr(start, pos_ - start);
        return true;
    }

    bool ParseArray(JsonValue& out) {
        if (!Consume('[')) return false;
        out.type = JsonValue::Type::Array;
        Skip();
        if (Consume(']')) return true;
        while (true) {
            JsonValue item;
            if (!ParseValue(item)) return false;
            out.array.push_back(std::move(item));
            if (Consume(']')) return true;
            if (!Consume(',')) return false;
        }
    }

    bool ParseObject(JsonValue& out) {
        if (!Consume('{')) return false;
        out.type = JsonValue::Type::Object;
        Skip();
        if (Consume('}')) return true;
        while (true) {
            std::string key;
            if (!ParseString(key)) return false;
            if (!Consume(':')) return false;
            JsonValue value;
            if (!ParseValue(value)) return false;
            out.object.emplace(std::move(key), std::move(value));
            if (Consume('}')) return true;
            if (!Consume(',')) return false;
        }
    }

    std::string text_;
    size_t pos_ = 0;
};

std::string UrlEncode(const std::string& input) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : input) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

class SupabaseClient {
public:
    SupabaseClient(std::wstring url, std::wstring key, Settings settings)
        : url_(std::move(url)), key_(std::move(key)), settings_(std::move(settings)) {
        ParseUrl();
    }

    bool IsReady() const {
        return ready_ && !key_.empty();
    }

    bool Request(const wchar_t* method, const std::wstring& path, const std::string& body,
                 DWORD& status, std::string& response, std::wstring& error) {
        if (!IsReady()) {
            error = L"Missing or invalid SUPABASE_URL/SUPABASE_KEY";
            return false;
        }

        DWORD accessType = settings_.proxyEnabled && !settings_.proxy.empty()
            ? WINHTTP_ACCESS_TYPE_NAMED_PROXY
            : WINHTTP_ACCESS_TYPE_NO_PROXY;
        std::wstring proxyName = settings_.proxy;

        HINTERNET session = WinHttpOpen(L"AccountsKeeper/1.0", accessType,
            proxyName.empty() ? WINHTTP_NO_PROXY_NAME : proxyName.c_str(),
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session) {
            error = L"WinHttpOpen failed";
            return false;
        }

        HINTERNET connect = WinHttpConnect(session, host_.c_str(), port_, 0);
        if (!connect) {
            WinHttpCloseHandle(session);
            error = L"WinHttpConnect failed";
            return false;
        }

        std::wstring fullPath = basePath_ + path;
        HINTERNET request = WinHttpOpenRequest(connect, method, fullPath.c_str(), nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            secure_ ? WINHTTP_FLAG_SECURE : 0);
        if (!request) {
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            error = L"WinHttpOpenRequest failed";
            return false;
        }

        DWORD timeout = 15000;
        WinHttpSetOption(request, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(request, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(request, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

        if (!settings_.proxyUser.empty()) {
            WinHttpSetCredentials(request, WINHTTP_AUTH_TARGET_PROXY, WINHTTP_AUTH_SCHEME_BASIC,
                settings_.proxyUser.c_str(), settings_.proxyPassword.c_str(), nullptr);
        }

        std::wstring headers =
            L"apikey: " + key_ + L"\r\n"
            L"Authorization: Bearer " + key_ + L"\r\n"
            L"Content-Type: application/json\r\n"
            L"Accept: application/json\r\n";
        if (body.empty()) {
            headers += L"Prefer: return=representation\r\n";
        } else {
            headers += L"Prefer: return=representation\r\n";
        }

        BOOL ok = WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(headers.size()),
            body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
            static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0);
        if (ok) ok = WinHttpReceiveResponse(request, nullptr);
        if (!ok) {
            DWORD last = GetLastError();
            std::wostringstream oss;
            oss << L"HTTP request failed: " << last;
            error = oss.str();
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return false;
        }

        DWORD statusSize = sizeof(status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);

        response.clear();
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
            std::string chunk(available, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read)) break;
            chunk.resize(read);
            response += chunk;
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return status >= 200 && status < 300;
    }

private:
    void ParseUrl() {
        URL_COMPONENTSW comps{};
        wchar_t host[256]{};
        wchar_t path[1024]{};
        comps.dwStructSize = sizeof(comps);
        comps.lpszHostName = host;
        comps.dwHostNameLength = static_cast<DWORD>(std::size(host));
        comps.lpszUrlPath = path;
        comps.dwUrlPathLength = static_cast<DWORD>(std::size(path));
        if (!WinHttpCrackUrl(url_.c_str(), 0, 0, &comps)) return;
        host_.assign(comps.lpszHostName, comps.dwHostNameLength);
        basePath_.assign(comps.lpszUrlPath, comps.dwUrlPathLength);
        if (basePath_ == L"/") basePath_.clear();
        port_ = comps.nPort;
        secure_ = comps.nScheme == INTERNET_SCHEME_HTTPS;
        ready_ = !host_.empty();
    }

    std::wstring url_;
    std::wstring key_;
    Settings settings_;
    std::wstring host_;
    std::wstring basePath_;
    INTERNET_PORT port_ = INTERNET_DEFAULT_HTTPS_PORT;
    bool secure_ = true;
    bool ready_ = false;
};

std::string NewGuidString() {
    GUID guid{};
    if (FAILED(CoCreateGuid(&guid))) return "";
    wchar_t buffer[39]{};
    if (StringFromGUID2(guid, buffer, static_cast<int>(std::size(buffer))) <= 0) return "";
    std::wstring wide(buffer);
    if (!wide.empty() && wide.front() == L'{') wide.erase(wide.begin());
    if (!wide.empty() && wide.back() == L'}') wide.pop_back();
    std::transform(wide.begin(), wide.end(), wide.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return WideToUtf8(wide);
}

std::wstring UtcNowIso() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    wchar_t buffer[32]{};
    swprintf_s(buffer, L"%04u-%02u-%02uT%02u:%02u:%02uZ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buffer;
}

std::string AccountJsonObject(const Account& account) {
    return "{"
        "\"id\":" + JsonString(account.id) + ","
        "\"product_name_url\":" + JsonString(account.encryptedProduct) + ","
        "\"username\":" + JsonString(account.encryptedUsername) + ","
        "\"password\":" + JsonString(account.encryptedPassword) + ","
        "\"additional\":" + JsonString(account.encryptedAdditional) + ","
        "\"created_at\":" + JsonString(WideToUtf8(account.createdAt)) +
        "}";
}

bool IsIntegerId(const std::string& id) {
    return !id.empty() && std::all_of(id.begin(), id.end(), [](unsigned char ch) {
        return std::isdigit(ch) != 0;
    });
}

std::string AccountStoreBody(const Account& account, bool includeId) {
    std::ostringstream out;
    out << "{";
    bool wrote = false;
    auto field = [&](const std::string& key, const std::string& value) {
        if (wrote) out << ",";
        out << JsonString(key) << ":" << JsonString(value);
        wrote = true;
    };
    if (includeId) field("id", account.id);
    field("product_name_url", account.encryptedProduct);
    field("username", account.encryptedUsername);
    field("password", account.encryptedPassword);
    field("additional", account.encryptedAdditional);
    field("created_at", WideToUtf8(account.createdAt));
    out << "}";
    return out.str();
}

std::string AccountsJsonArray(const std::vector<Account>& accounts) {
    std::ostringstream out;
    out << "[";
    for (size_t i = 0; i < accounts.size(); ++i) {
        if (i) out << ",";
        out << AccountJsonObject(accounts[i]);
    }
    out << "]";
    return out.str();
}

std::string AccountBody(const Account& account, bool update) {
    return AccountStoreBody(account, update || IsIntegerId(account.id));
}

void SortAccounts(std::vector<Account>& accounts) {
    std::sort(accounts.begin(), accounts.end(), [](const Account& a, const Account& b) {
        return a.createdAt > b.createdAt;
    });
}

Account AccountFromUi() {
    std::wstring product = GetWindowTextString(g.product);
    std::wstring username = GetWindowTextString(g.username);
    std::wstring password = GetWindowTextString(g.password);
    std::wstring additional = GetWindowTextString(g.additional);

    Account account;
    bool update = g.selected >= 0 && g.selected < static_cast<int>(g.rows.size()) && !g.rows[g.selected].id.empty();
    account.id = update ? g.rows[g.selected].id : "local:" + NewGuidString();
    account.createdAt = update ? g.rows[g.selected].createdAt : UtcNowIso();
    account.encryptedProduct = WideToUtf8(ProtectWideForStore(product));
    account.encryptedUsername = WideToUtf8(ProtectWideForStore(username));
    account.encryptedPassword = WideToUtf8(ProtectWideForStore(password));
    account.encryptedAdditional = WideToUtf8(ProtectWideForStore(additional));
    account.product = product;
    account.username = username;
    account.password = password;
    account.additional = additional;
    account.decryptOk = true;
    return account;
}

void ClearEditor() {
    g.selected = -1;
    SetWindowTextW(g.product, L"");
    SetWindowTextW(g.username, L"");
    SetWindowTextW(g.password, L"");
    SetWindowTextW(g.additional, L"");
    ListView_SetItemState(g.list, -1, 0, LVIS_SELECTED);
}

void FillEditor(const Account& account) {
    SetWindowTextW(g.product, account.product.c_str());
    SetWindowTextW(g.username, account.username.c_str());
    SetWindowTextW(g.password, account.password.c_str());
    SetWindowTextW(g.additional, account.additional.c_str());
}

std::wstring SingleLinePreview(std::wstring value) {
    for (wchar_t& ch : value) {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t') {
            ch = L' ';
        }
    }
    return value;
}

void AddListRow(int index, const Account& account) {
    std::wstring additional = SingleLinePreview(account.additional);
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = index;
    item.pszText = const_cast<wchar_t*>(account.product.c_str());
    ListView_InsertItem(g.list, &item);
    ListView_SetItemText(g.list, index, 1, const_cast<wchar_t*>(account.username.c_str()));
    ListView_SetItemText(g.list, index, 2, const_cast<wchar_t*>(account.password.c_str()));
    ListView_SetItemText(g.list, index, 3, const_cast<wchar_t*>(additional.c_str()));
    ListView_SetItemText(g.list, index, 4, const_cast<wchar_t*>(account.createdAt.c_str()));
    if (!account.decryptOk) {
        ListView_SetItemText(g.list, index, 0, const_cast<wchar_t*>(L"(decrypt failed)"));
    }
}

void PopulateList() {
    ListView_DeleteAllItems(g.list);
    for (int i = 0; i < static_cast<int>(g.rows.size()); ++i) {
        AddListRow(i, g.rows[i]);
    }
}

bool ParseAccounts(const std::string& json, std::vector<Account>& out, std::wstring& error) {
    JsonValue root;
    JsonParser parser(json);
    if (!parser.Parse(root) || root.type != JsonValue::Type::Array) {
        error = L"Supabase returned invalid JSON";
        return false;
    }

    out.clear();
    for (const auto& item : root.array) {
        if (item.type != JsonValue::Type::Object) continue;
        Account account;
        const JsonValue* id = item.Get("id");
        const JsonValue* product = item.Get("product_name_url");
        const JsonValue* username = item.Get("username");
        const JsonValue* password = item.Get("password");
        const JsonValue* additional = item.Get("additional");
        const JsonValue* created = item.Get("created_at");

        account.id = id ? id->AsString() : "";
        account.encryptedProduct = product ? product->AsString() : "";
        account.encryptedUsername = username ? username->AsString() : "";
        account.encryptedPassword = password ? password->AsString() : "";
        account.encryptedAdditional = additional ? additional->AsString() : "";
        bool okProduct = true;
        bool okUser = true;
        bool okPass = true;
        bool okAdditional = true;
        account.product = product ? UnprotectWideFromStore(account.encryptedProduct, okProduct) : L"";
        account.username = username ? UnprotectWideFromStore(account.encryptedUsername, okUser) : L"";
        account.password = password ? UnprotectWideFromStore(account.encryptedPassword, okPass) : L"";
        account.additional = additional ? UnprotectWideFromStore(account.encryptedAdditional, okAdditional) : L"";
        account.createdAt = created ? Utf8ToWide(created->AsString()) : L"";
        account.decryptOk = okProduct && okUser && okPass && okAdditional;
        out.push_back(std::move(account));
    }
    return true;
}

bool LoadBackupAccounts(std::vector<Account>& rows, std::wstring& error) {
    std::string json;
    if (!ReadUtf8File(g.backupPath, json, error)) return false;
    if (json.empty()) {
        rows.clear();
        return true;
    }
    return ParseAccounts(json, rows, error);
}

bool SaveBackupAccounts(std::vector<Account> rows, std::wstring& error) {
    SortAccounts(rows);
    return WriteUtf8File(g.backupPath, AccountsJsonArray(rows), error);
}

void UpsertAccount(std::vector<Account>& rows, const Account& account) {
    for (auto& row : rows) {
        if (row.id == account.id) {
            row = account;
            return;
        }
    }
    rows.push_back(account);
}

void RemoveAccount(std::vector<Account>& rows, const std::string& id) {
    rows.erase(std::remove_if(rows.begin(), rows.end(), [&](const Account& row) {
        return row.id == id;
    }), rows.end());
}

bool FetchRemoteAccounts(SupabaseClient& client, std::vector<Account>& rows, DWORD& status, std::string& response, std::wstring& error) {
    response.clear();
    bool ok = client.Request(L"GET", L"/rest/v1/accounts?select=*&order=created_at.desc", "", status, response, error);
    if (!ok) return false;
    return ParseAccounts(response, rows, error);
}

bool ParseFirstAccount(const std::string& response, Account& account, std::wstring& error) {
    std::vector<Account> rows;
    if (!ParseAccounts(response, rows, error) || rows.empty()) return false;
    account = rows.front();
    return true;
}

bool PushRemoteAccount(SupabaseClient& client, const Account& account, Account& uploaded, std::wstring& error) {
    DWORD status = 0;
    std::string response;
    bool ok = client.Request(L"POST", L"/rest/v1/accounts", AccountBody(account, false), status, response, error);
    if (!ok) {
        error = RequestErrorMessage(L"Upload local backup failed", status, error, response);
        return false;
    }
    std::wstring parseError;
    if (ParseFirstAccount(response, uploaded, parseError)) return true;
    uploaded = account;
    return true;
}

bool RefreshAccounts() {
    SupabaseClient client(g.supabaseUrl, g.supabaseKey, g.settings);
    DWORD status = 0;
    std::string response;
    std::wstring error;
    SetStatus(L"Loading accounts...");

    std::vector<Account> remoteRows;
    bool ok = FetchRemoteAccounts(client, remoteRows, status, response, error);
    if (!ok) {
        std::wstring remoteError = RequestErrorMessage(L"Refresh failed", status, error, response);
        std::vector<Account> localRows;
        std::wstring localError;
        if (!LoadBackupAccounts(localRows, localError)) {
            SetStatus(remoteError + L"; backup failed: " + localError);
            return false;
        }
        SortAccounts(localRows);
        g.rows = std::move(localRows);
        PopulateList();
        ClearEditor();
        std::wostringstream oss;
        oss << remoteError << L"; loaded " << g.rows.size() << L" local backup account(s)";
        SetStatus(oss.str());
        return false;
    }

    std::vector<Account> localRows;
    std::wstring localError;
    bool localOk = LoadBackupAccounts(localRows, localError);
    std::map<std::string, bool> remoteIds;
    for (const auto& row : remoteRows) remoteIds[row.id] = true;
    std::map<std::string, bool> localIds;
    for (const auto& row : localRows) localIds[row.id] = true;

    int uploaded = 0;
    int uploadFailed = 0;
    if (localOk) {
        for (const auto& row : localRows) {
            if (row.id.empty() || remoteIds[row.id]) continue;
            std::wstring uploadError;
            Account uploadedRow;
            if (PushRemoteAccount(client, row, uploadedRow, uploadError)) {
                ++uploaded;
                UpsertAccount(remoteRows, uploadedRow);
                remoteIds[uploadedRow.id] = true;
            } else {
                ++uploadFailed;
                UpsertAccount(remoteRows, row);
                if (localError.empty()) localError = uploadError;
            }
        }
    }

    int downloaded = 0;
    for (const auto& row : remoteRows) {
        if (!localIds[row.id]) ++downloaded;
    }

    if (localOk) {
        std::wstring saveError;
        if (!SaveBackupAccounts(remoteRows, saveError)) {
            localOk = false;
            localError = saveError;
        }
    }

    SortAccounts(remoteRows);
    g.rows = std::move(remoteRows);
    PopulateList();
    ClearEditor();
    std::wostringstream oss;
    oss << L"Loaded " << g.rows.size() << L" account(s)";
    if (uploaded) oss << L", uploaded " << uploaded << L" local";
    if (downloaded) oss << L", backed up " << downloaded << L" remote";
    if (!localOk) oss << L"; local backup failed: " << localError;
    if (uploadFailed) oss << L"; " << uploadFailed << L" local upload(s) failed: " << localError;
    SetStatus(oss.str());
    return uploadFailed == 0 && localOk;
}

bool SaveAccount() {
    if (GetWindowTextLengthW(g.product) == 0) {
        SetStatus(L"Product or URL is required");
        return false;
    }
    SupabaseClient client(g.supabaseUrl, g.supabaseKey, g.settings);
    DWORD status = 0;
    std::string response;
    std::wstring error;

    bool update = g.selected >= 0 && g.selected < static_cast<int>(g.rows.size()) && !g.rows[g.selected].id.empty();
    Account account = AccountFromUi();
    if (account.id.empty()) {
        SetStatus(L"Save failed: could not create account id");
        return false;
    }
    std::string body = AccountBody(account, update);
    std::wstring path = L"/rest/v1/accounts";
    const wchar_t* method = L"POST";
    if (update) {
        method = L"PATCH";
        path += L"?id=eq." + Utf8ToWide(UrlEncode(account.id));
    }

    SetStatus(update ? L"Updating account..." : L"Creating account...");
    bool remoteOk = client.Request(method, path, body, status, response, error);
    std::wstring remoteError;
    Account storedAccount = account;
    if (!remoteOk) {
        remoteError = RequestErrorMessage(L"remote save failed", status, error, response);
    } else {
        std::wstring parseError;
        if (!ParseFirstAccount(response, storedAccount, parseError)) {
            remoteOk = false;
            remoteError = L"remote save returned invalid account: " + parseError;
        }
    }

    std::vector<Account> localRows;
    std::wstring localError;
    bool localOk = LoadBackupAccounts(localRows, localError);
    if (localOk) {
        if (remoteOk && storedAccount.id != account.id) {
            RemoveAccount(localRows, account.id);
        }
        UpsertAccount(localRows, remoteOk ? storedAccount : account);
        localOk = SaveBackupAccounts(localRows, localError);
    }

    if (!remoteOk || !localOk) {
        if (remoteOk || localOk) {
            if (remoteOk && storedAccount.id != account.id) {
                RemoveAccount(g.rows, account.id);
            }
            UpsertAccount(g.rows, remoteOk ? storedAccount : account);
            SortAccounts(g.rows);
            PopulateList();
        }
        std::wostringstream oss;
        oss << L"Save incomplete:";
        if (!remoteOk) oss << L" " << remoteError;
        if (!localOk) oss << L" local backup failed: " << localError;
        SetStatus(oss.str());
        return false;
    }
    RefreshAccounts();
    SetStatus(L"Saved to remote and local");
    return true;
}

bool DeleteAccount() {
    if (g.selected < 0 || g.selected >= static_cast<int>(g.rows.size())) {
        SetStatus(L"Select an account first");
        return false;
    }
    if (MessageBoxW(g.hwnd, L"Delete the selected account?", L"AccountsKeeper", MB_ICONWARNING | MB_YESNO) != IDYES) {
        return false;
    }

    SupabaseClient client(g.supabaseUrl, g.supabaseKey, g.settings);
    DWORD status = 0;
    std::string response;
    std::wstring error;
    std::string id = g.rows[g.selected].id;
    std::wstring path = L"/rest/v1/accounts?id=eq." + Utf8ToWide(UrlEncode(id));
    SetStatus(L"Deleting account...");
    bool remoteOk = client.Request(L"DELETE", path, "", status, response, error);
    std::wstring remoteError;
    if (!remoteOk) {
        remoteError = RequestErrorMessage(L"remote delete failed", status, error, response);
    }

    std::vector<Account> localRows;
    std::wstring localError;
    bool localOk = LoadBackupAccounts(localRows, localError);
    if (localOk) {
        RemoveAccount(localRows, id);
        localOk = SaveBackupAccounts(localRows, localError);
    }

    if (!remoteOk || !localOk) {
        std::wostringstream oss;
        oss << L"Delete incomplete:";
        if (!remoteOk) oss << L" " << remoteError;
        if (!localOk) oss << L" local backup failed: " << localError;
        SetStatus(oss.str());
        return false;
    }
    RefreshAccounts();
    SetStatus(L"Deleted from remote and local");
    return true;
}

void CopyToClipboard(const std::wstring& text) {
    if (!OpenClipboard(g.hwnd)) return;
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (mem) {
        void* ptr = GlobalLock(mem);
        std::memcpy(ptr, text.c_str(), bytes);
        GlobalUnlock(mem);
        SetClipboardData(CF_UNICODETEXT, mem);
    }
    CloseClipboard();
}

HWND MakeControl(const wchar_t* cls, const wchar_t* text, DWORD style, DWORD exStyle, HWND parent, int id) {
    HWND hwnd = CreateWindowExW(exStyle, cls, text, style, 0, 0, 0, 0, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g.instance, nullptr);
    SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);
    return hwnd;
}

HWND MakeLabel(HWND parent, const wchar_t* text) {
    return MakeControl(L"STATIC", text, WS_CHILD | WS_VISIBLE, 0, parent, 0);
}

void ResizeChild(HWND hwnd, int x, int y, int w, int h) {
    MoveWindow(hwnd, x, y, std::max(0, w), std::max(0, h), TRUE);
}

void Layout(HWND hwnd) {
    RECT rc{};
    GetClientRect(hwnd, &rc);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    int pad = 16;
    int toolbarH = 42;
    int statusH = 26;
    int listW = std::max(330, width * 42 / 100);
    int rightX = pad + listW + pad;
    int rightW = width - rightX - pad;
    int contentTop = pad + toolbarH;
    int contentH = height - contentTop - statusH - pad;

    HWND ids[] = {
        GetDlgItem(hwnd, IDC_REFRESH), GetDlgItem(hwnd, IDC_NEW), GetDlgItem(hwnd, IDC_SAVE),
        GetDlgItem(hwnd, IDC_DELETE), GetDlgItem(hwnd, IDC_COPY_USER), GetDlgItem(hwnd, IDC_COPY_PASS)
    };
    int x = pad;
    int buttonW[] = { 86, 70, 74, 76, 96, 104 };
    for (int i = 0; i < 6; ++i) {
        ResizeChild(ids[i], x, pad, buttonW[i], 30);
        x += buttonW[i] + 8;
    }

    ResizeChild(g.list, pad, contentTop, listW, contentH);

    int y = contentTop;
    int labelH = 18;
    int editH = 28;
    int gap = 8;
    int labelW = 110;
    auto placeRow = [&](int labelId, HWND edit, int h = 28) {
        ResizeChild(GetDlgItem(hwnd, labelId), rightX, y + 5, labelW, labelH);
        ResizeChild(edit, rightX + labelW, y, rightW - labelW, h);
        y += h + gap;
    };

    placeRow(3001, g.product);
    placeRow(3002, g.username);
    ResizeChild(GetDlgItem(hwnd, 3003), rightX, y + 5, labelW, labelH);
    ResizeChild(g.password, rightX + labelW, y, rightW - labelW - 42, editH);
    ResizeChild(g.btnShowPass, rightX + rightW - 34, y, 34, editH);
    y += editH + gap;
    ResizeChild(GetDlgItem(hwnd, 3004), rightX, y + 5, labelW, labelH);
    ResizeChild(g.additional, rightX + labelW, y, rightW - labelW, std::max(72, contentH / 4));
    y += std::max(72, contentH / 4) + 18;

    ResizeChild(GetDlgItem(hwnd, 3005), rightX, y, rightW, labelH);
    y += 24;
    ResizeChild(g.chkProxy, rightX, y, 112, 24);
    ResizeChild(g.proxy, rightX + 118, y, rightW - 118, 26);
    y += 32;
    ResizeChild(GetDlgItem(hwnd, 3006), rightX, y + 5, labelW, labelH);
    ResizeChild(g.proxyUser, rightX + labelW, y, rightW - labelW, 26);
    y += 32;
    ResizeChild(GetDlgItem(hwnd, 3007), rightX, y + 5, labelW, labelH);
    ResizeChild(g.proxyPass, rightX + labelW, y, rightW - labelW, 26);
    y += 34;
    ResizeChild(g.chkStartup, rightX, y, 130, 24);
    ResizeChild(GetDlgItem(hwnd, IDC_SAVE_SETTINGS), rightX + 140, y - 2, 104, 28);

    ResizeChild(g.status, 0, height - statusH, width, statusH);
}

void InitListColumns() {
    ListView_SetExtendedListViewStyle(g.list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    LVCOLUMNW col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.pszText = const_cast<wchar_t*>(L"Product / URL");
    col.cx = 210;
    ListView_InsertColumn(g.list, 0, &col);
    col.pszText = const_cast<wchar_t*>(L"Username");
    col.cx = 150;
    col.iSubItem = 1;
    ListView_InsertColumn(g.list, 1, &col);
    col.pszText = const_cast<wchar_t*>(L"Password");
    col.cx = 140;
    col.iSubItem = 2;
    ListView_InsertColumn(g.list, 2, &col);
    col.pszText = const_cast<wchar_t*>(L"Additional");
    col.cx = 180;
    col.iSubItem = 3;
    ListView_InsertColumn(g.list, 3, &col);
    col.pszText = const_cast<wchar_t*>(L"Created");
    col.cx = 150;
    col.iSubItem = 4;
    ListView_InsertColumn(g.list, 4, &col);
}

void AddTrayIcon() {
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g.hwnd;
    nid.uID = TRAY_UID;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIconW(g.instance, MAKEINTRESOURCEW(IDI_ACCOUNT_KEEPER));
    wcscpy_s(nid.szTip, L"AccountsKeeper");
    Shell_NotifyIconW(NIM_ADD, &nid);
}

void RemoveTrayIcon() {
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g.hwnd;
    nid.uID = TRAY_UID;
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

void ToggleWindow() {
    if (IsWindowVisible(g.hwnd) && !IsIconic(g.hwnd)) {
        ShowWindow(g.hwnd, SW_HIDE);
    } else {
        ShowWindow(g.hwnd, SW_SHOWNORMAL);
        SetForegroundWindow(g.hwnd);
        SetFocus(g.list);
    }
}

void ShowTrayMenu() {
    POINT pt{};
    GetCursorPos(&pt);
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, IDM_TRAY_TOGGLE, IsWindowVisible(g.hwnd) ? L"Hide" : L"Open");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_TRAY_EXIT, L"Exit");
    SetForegroundWindow(g.hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, g.hwnd, nullptr);
    DestroyMenu(menu);
}

void TogglePasswordVisibility() {
    g.passwordVisible = !g.passwordVisible;
    SendMessageW(g.password, EM_SETPASSWORDCHAR, g.passwordVisible ? 0 : L'*', 0);
    SetWindowTextW(g.btnShowPass, g.passwordVisible ? L"Hide" : L"Show");
    InvalidateRect(g.password, nullptr, TRUE);
}

void LoadSettingsToUi() {
    SendMessageW(g.chkProxy, BM_SETCHECK, g.settings.proxyEnabled ? BST_CHECKED : BST_UNCHECKED, 0);
    SetWindowTextW(g.proxy, g.settings.proxy.c_str());
    SetWindowTextW(g.proxyUser, g.settings.proxyUser.c_str());
    SetWindowTextW(g.proxyPass, g.settings.proxyPassword.c_str());
    SendMessageW(g.chkStartup, BM_SETCHECK, g.settings.startup ? BST_CHECKED : BST_UNCHECKED, 0);
}

void CreateUi(HWND hwnd) {
    NONCLIENTMETRICSW metrics{};
    metrics.cbSize = sizeof(metrics);
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0);
    g.font = CreateFontIndirectW(&metrics.lfMessageFont);

    g.bgBrush = CreateSolidBrush(RGB(246, 248, 250));

    MakeControl(L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, hwnd, IDC_REFRESH);
    MakeControl(L"BUTTON", L"New", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, hwnd, IDC_NEW);
    MakeControl(L"BUTTON", L"Save", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 0, hwnd, IDC_SAVE);
    MakeControl(L"BUTTON", L"Delete", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, hwnd, IDC_DELETE);
    MakeControl(L"BUTTON", L"Copy user", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, hwnd, IDC_COPY_USER);
    MakeControl(L"BUTTON", L"Copy pass", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, hwnd, IDC_COPY_PASS);

    g.list = MakeControl(WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER, 0, hwnd, IDC_LIST);
    InitListColumns();

    HWND label = MakeLabel(hwnd, L"Product / URL");
    SetWindowLongPtrW(label, GWLP_ID, 3001);
    label = MakeLabel(hwnd, L"Username");
    SetWindowLongPtrW(label, GWLP_ID, 3002);
    label = MakeLabel(hwnd, L"Password");
    SetWindowLongPtrW(label, GWLP_ID, 3003);
    label = MakeLabel(hwnd, L"Additional");
    SetWindowLongPtrW(label, GWLP_ID, 3004);
    label = MakeLabel(hwnd, L"Settings");
    SetWindowLongPtrW(label, GWLP_ID, 3005);
    label = MakeLabel(hwnd, L"Proxy user");
    SetWindowLongPtrW(label, GWLP_ID, 3006);
    label = MakeLabel(hwnd, L"Proxy pass");
    SetWindowLongPtrW(label, GWLP_ID, 3007);

    g.product = MakeControl(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, hwnd, IDC_PRODUCT);
    g.username = MakeControl(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, hwnd, IDC_USERNAME);
    g.password = MakeControl(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, hwnd, IDC_PASSWORD);
    g.additional = MakeControl(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL, WS_EX_CLIENTEDGE, hwnd, IDC_ADDITIONAL);
    g.btnShowPass = MakeControl(L"BUTTON", L"Hide", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, hwnd, IDC_SHOW_PASS);

    g.chkProxy = MakeControl(L"BUTTON", L"Proxy", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, hwnd, IDC_PROXY_ENABLE);
    g.proxy = MakeControl(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, hwnd, IDC_PROXY);
    g.proxyUser = MakeControl(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, hwnd, IDC_PROXY_USER);
    g.proxyPass = MakeControl(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, WS_EX_CLIENTEDGE, hwnd, IDC_PROXY_PASS);
    g.chkStartup = MakeControl(L"BUTTON", L"Startup", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, hwnd, IDC_STARTUP);
    MakeControl(L"BUTTON", L"Save settings", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, hwnd, IDC_SAVE_SETTINGS);

    g.status = MakeControl(L"STATIC", L"Ready", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, hwnd, 0);
    LoadSettingsToUi();
    Layout(hwnd);
}

void OnCommand(WPARAM wParam) {
    switch (LOWORD(wParam)) {
    case IDC_REFRESH:
        RefreshAccounts();
        break;
    case IDC_NEW:
        ClearEditor();
        SetFocus(g.product);
        SetStatus(L"New account");
        break;
    case IDC_SAVE:
        SaveAccount();
        break;
    case IDC_DELETE:
        DeleteAccount();
        break;
    case IDC_COPY_USER:
        CopyToClipboard(GetWindowTextString(g.username));
        SetStatus(L"Username copied");
        break;
    case IDC_COPY_PASS:
        CopyToClipboard(GetWindowTextString(g.password));
        SetStatus(L"Password copied");
        break;
    case IDC_SHOW_PASS:
        TogglePasswordVisibility();
        break;
    case IDC_SAVE_SETTINGS:
        SaveSettingsFromUi();
        break;
    case IDM_TRAY_TOGGLE:
        ToggleWindow();
        break;
    case IDM_TRAY_EXIT:
        g.exiting = true;
        DestroyWindow(g.hwnd);
        break;
    }
}

void OnNotify(LPARAM lParam) {
    auto* hdr = reinterpret_cast<NMHDR*>(lParam);
    if (hdr->idFrom == IDC_LIST && hdr->code == LVN_ITEMCHANGED) {
        auto* item = reinterpret_cast<NMLISTVIEW*>(lParam);
        if ((item->uChanged & LVIF_STATE) && (item->uNewState & LVIS_SELECTED)) {
            g.selected = item->iItem;
            if (g.selected >= 0 && g.selected < static_cast<int>(g.rows.size())) {
                FillEditor(g.rows[g.selected]);
            }
        }
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        g.hwnd = hwnd;
        CreateUi(hwnd);
        AddTrayIcon();
        RegisterHotKey(hwnd, HOTKEY_ID, MOD_CONTROL | MOD_ALT, 'K');
        RefreshAccounts();
        return 0;
    case WM_SIZE:
        Layout(hwnd);
        return 0;
    case WM_COMMAND:
        OnCommand(wParam);
        return 0;
    case WM_NOTIFY:
        OnNotify(lParam);
        return 0;
    case WM_HOTKEY:
        if (wParam == HOTKEY_ID) ToggleWindow();
        return 0;
    case WM_TRAYICON:
        if (lParam == WM_LBUTTONDBLCLK) ToggleWindow();
        if (lParam == WM_RBUTTONUP) ShowTrayMenu();
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        SetBkMode(hdc, TRANSPARENT);
        return reinterpret_cast<LRESULT>(g.bgBrush);
    }
    case WM_CLOSE:
        if (g.exiting) {
            DestroyWindow(hwnd);
        } else {
            ShowWindow(hwnd, SW_HIDE);
            SetStatus(L"Hidden to tray. Ctrl+Alt+K toggles the window.");
        }
        return 0;
    case WM_DESTROY:
        UnregisterHotKey(hwnd, HOTKEY_ID);
        RemoveTrayIcon();
        if (g.font) DeleteObject(g.font);
        if (g.titleFont) DeleteObject(g.titleFont);
        if (g.bgBrush) DeleteObject(g.bgBrush);
        if (g.singleInstanceMutex) {
            CloseHandle(g.singleInstanceMutex);
            g.singleInstanceMutex = nullptr;
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

} // namespace

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    g.instance = hInstance;
    g.singleInstanceMutex = CreateMutexW(nullptr, TRUE, L"Local\\AccountsKeeper.SingleInstance");
    if (!g.singleInstanceMutex) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        ActivateExistingInstance();
        CloseHandle(g.singleInstanceMutex);
        g.singleInstanceMutex = nullptr;
        return 0;
    }

    g.supabaseUrl = GetEnvVar(L"SUPABASE_URL");
    g.supabaseKey = GetEnvVar(L"SUPABASE_KEY");
    LoadSettings();

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ACCOUNT_KEEPER));
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"AccountsKeeperWindow";
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"AccountsKeeper", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 980, 620, nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) {
        CloseHandle(g.singleInstanceMutex);
        g.singleInstanceMutex = nullptr;
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}
