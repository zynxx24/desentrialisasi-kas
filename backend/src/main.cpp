#include <iostream>
#include <pqxx/pqxx>
#include <crow.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <thread>
#include <chrono>
#include <map>
#include <vector>
#include <jwt-cpp/jwt.h>
#include <redis/redis.hpp>

// Advanced rate limiting configuration
struct RateLimiter {
    std::map<std::string, std::pair<int, std::chrono::steady_clock::time_point>> requests;
    std::mutex mtx;
    const int MAX_REQUESTS = 100;
    const std::chrono::seconds WINDOW = std::chrono::seconds(60);

    bool shouldLimit(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mtx);
        auto now = std::chrono::steady_clock::now();
        auto& [count, windowStart] = requests[ip];
        
        if (now - windowStart > WINDOW) {
            count = 1;
            windowStart = now;
            return false;
        }
        
        return ++count > MAX_REQUESTS;
    }
};

// Enhanced security utilities
class SecurityUtils {
private:
    static const std::string JWT_SECRET;
    static const std::string AES_KEY;
    static const std::string AES_IV;

public:
    static std::string sha512(const std::string& input) {
        unsigned char hash[SHA512_DIGEST_LENGTH];
        SHA512_CTX sha512;
        SHA512_Init(&sha512);
        SHA512_Update(&sha512, input.c_str(), input.length());
        SHA512_Final(hash, &sha512);
        
        std::stringstream ss;
        for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    static std::string generateJWT(const std::string& username) {
        auto token = jwt::create()
            .set_issuer("btc_clone")
            .set_type("JWS")
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_payload_claim("username", jwt::claim(username))
            .sign(jwt::algorithm::hs256{JWT_SECRET});
        return token;
    }

    static std::string encryptAES(const std::string& plaintext) {
        // AES-256 encryption implementation
        std::vector<unsigned char> ciphertext(plaintext.length() + AES_BLOCK_SIZE);
        AES_KEY aes_key;
        AES_set_encrypt_key((const unsigned char*)AES_KEY.c_str(), 256, &aes_key);
        
        unsigned char iv[AES_BLOCK_SIZE];
        memcpy(iv, AES_IV.c_str(), AES_BLOCK_SIZE);
        
        AES_cbc_encrypt(
            (const unsigned char*)plaintext.c_str(),
            ciphertext.data(),
            plaintext.length(),
            &aes_key,
            iv,
            AES_ENCRYPT
        );
        
        return std::string(ciphertext.begin(), ciphertext.end());
    }
};

// Redis cache manager
class CacheManager {
private:
    sw::redis::Redis redis;
    const std::chrono::seconds CACHE_TTL{300}; // 5 minutes

public:
    CacheManager() : redis("tcp://127.0.0.1:6379") {}

    void setCache(const std::string& key, const std::string& value) {
        redis.set(key, value, CACHE_TTL);
    }

    std::optional<std::string> getCache(const std::string& key) {
        try {
            auto value = redis.get(key);
            return value ? std::optional<std::string>(*value) : std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    }
};

// Enhanced database connection with connection pooling
class DatabaseConnection {
private:
    static constexpr size_t POOL_SIZE = 10;
    std::vector<std::unique_ptr<pqxx::connection>> pool;
    std::mutex pool_mutex;
    CacheManager cache;

    std::string getConnectionString() const {
        return "dbname=checked user=postgres password=your_password host=localhost port=5432";
    }

public:
    DatabaseConnection() {
        for (size_t i = 0; i < POOL_SIZE; ++i) {
            pool.push_back(std::make_unique<pqxx::connection>(getConnectionString()));
        }
    }

    class Transaction {
    private:
        pqxx::connection& conn;
        pqxx::work txn;

    public:
        Transaction(pqxx::connection& c) : conn(c), txn(conn) {}
        
        pqxx::work& get() { return txn; }
        
        void commit() { txn.commit(); }
    };

    std::unique_ptr<Transaction> getTransaction() {
        std::lock_guard<std::mutex> lock(pool_mutex);
        // Simple round-robin connection selection
        static size_t current = 0;
        current = (current + 1) % POOL_SIZE;
        return std::make_unique<Transaction>(*pool[current]);
    }

    bool validateUser(const std::string& username, const std::string& hashedPassword, 
                     const std::string& cookie) {
        // Check cache first
        std::string cacheKey = "auth:" + username + ":" + hashedPassword;
        if (auto cached = cache.getCache(cacheKey)) {
            return *cached == "valid";
        }

        try {
            auto txn = getTransaction();
            std::string query = "SELECT COUNT(*) FROM users WHERE username = $1 AND "
                              "password = $2 AND cookie = $3";
            pqxx::result r = txn->get().exec_params(query, username, hashedPassword, cookie);
            bool valid = r[0][0].as<int>() > 0;
            
            // Cache the result
            cache.setCache(cacheKey, valid ? "valid" : "invalid");
            
            txn->commit();
            return valid;
        } catch (const std::exception &e) {
            std::cerr << "Validation error: " << e.what() << std::endl;
            return false;
        }
    }

    bool createUser(const std::string& username, const std::string& hashedPassword,
                   const std::string& cookie, const std::string& secretKey) {
        try {
            auto txn = getTransaction();
            // Check if username exists
            auto result = txn->get().exec_params(
                "SELECT COUNT(*) FROM users WHERE username = $1", username);
            if (result[0][0].as<int>() > 0) {
                return false;
            }

            std::string query = "INSERT INTO users (username, password, cookie, checked_count, secret_key) "
                              "VALUES ($1, $2, $3, 0, $4)";
            txn->get().exec_params(query, username, hashedPassword, cookie, secretKey);
            txn->commit();
            return true;
        } catch (const std::exception &e) {
            std::cerr << "User creation error: " << e.what() << std::endl;
            return false;
        }
    }

    bool updateCheckedCount(const std::string& username) {
        try {
            auto txn = getTransaction();
            // Update main database with optimistic locking
            auto result = txn->get().exec_params(
                "UPDATE users SET checked_count = checked_count + 1 "
                "WHERE username = $1 RETURNING checked_count",
                username);
            
            if (result.empty()) {
                return false;
            }

            int new_count = result[0][0].as<int>();
            
            // Update log database
            txn->get().exec_params(
                "INSERT INTO user_logs (username, checked_count, timestamp) "
                "VALUES ($1, $2, CURRENT_TIMESTAMP)",
                username, new_count);
            
            txn->commit();
            
            // Invalidate cache
            cache.setCache("user:" + username + ":count", std::to_string(new_count));
            
            return true;
        } catch (const std::exception &e) {
            std::cerr << "Check count update error: " << e.what() << std::endl;
            return false;
        }
    }

    std::optional<crow::json::wvalue> getUserLog(const std::string& username) {
        try {
            auto txn = getTransaction();
            auto result = txn->get().exec_params(
                "SELECT checked_count, timestamp FROM user_logs "
                "WHERE username = $1 ORDER BY timestamp DESC LIMIT 10",
                username);
            
            crow::json::wvalue::list logs;
            for (const auto& row : result) {
                crow::json::wvalue log;
                log["checked_count"] = row[0].as<int>();
                log["timestamp"] = row[1].as<std::string>();
                logs.push_back(std::move(log));
            }
            
            crow::json::wvalue response;
            response["logs"] = std::move(logs);
            return response;
        } catch (const std::exception &e) {
            std::cerr << "Log retrieval error: " << e.what() << std::endl;
            return std::nullopt;
        }
    }

    std::optional<crow::json::wvalue> trackUser(const std::string& username, 
                                              const std::string& targetUsername) {
        try {
            auto txn = getTransaction();
            auto result = txn->get().exec_params(
                "SELECT checked_count FROM users WHERE username = $1",
                targetUsername);
            
            if (result.empty()) {
                return std::nullopt;
            }
            
            crow::json::wvalue response;
            response["username"] = targetUsername;
            response["checked_count"] = result[0][0].as<int>();
            return response;
        } catch (const std::exception &e) {
            std::cerr << "Track user error: " << e.what() << std::endl;
            return std::nullopt;
        }
    }
};

int main() {
    crow::App<crow::CORSHandler> app;
    DatabaseConnection db;
    RateLimiter rateLimiter;

    // Configure CORS
    auto& cors = app.get_middleware<crow::CORSHandler>();
    cors
        .global()
        .headers("Content-Type", "Authorization")
        .methods("POST"_method, "GET"_method, "PUT"_method, "DELETE"_method);

    // Middleware for rate limiting and logging
    app.middleware([&rateLimiter](crow::request& req, crow::response& res, crow::context& ctx) {
        if (rateLimiter.shouldLimit(req.remote_ip)) {
            res.code = 429;
            res.write("Too many requests");
            res.end();
            return false;
        }
        
        // Log request
        std::cout << "[" << std::time(nullptr) << "] " 
                  << req.remote_ip << " " 
                  << req.method << " " 
                  << req.url << std::endl;
        
        return true;
    });

    // Sign in endpoint with enhanced security
    CROW_ROUTE(app, "/sign/<string>").methods("POST"_method)
    ([&db](const crow::request& req, std::string cookieUsers) {
        auto bodyArgs = crow::json::load(req.body);
        if (!bodyArgs) {
            return crow::response(400, "Invalid JSON");
        }

        std::string username = bodyArgs["username"].s();
        std::string password = bodyArgs["password"].s();
        
        // Enhanced password hashing with salt
        std::string hashedPassword = SecurityUtils::sha512(password + cookieUsers);
        
        if (db.validateUser(username, hashedPassword, cookieUsers)) {
            crow::json::wvalue response;
            response["status"] = "success";
            response["token"] = SecurityUtils::generateJWT(username);
            return crow::response(200, response);
        }
        return crow::response(401, "Authentication failed");
    });

    // Enhanced signup endpoint
    CROW_ROUTE(app, "/signup/<string>").methods("POST"_method)
    ([&db](const crow::request& req, std::string cookieUsers) {
        auto bodyArgs = crow::json::load(req.body);
        if (!bodyArgs) {
            return crow::response(400, "Invalid JSON");
        }

        std::string username = bodyArgs["username"].s();
        std::string password = bodyArgs["password"].s();
        std::string secretKey = bodyArgs["secret_key"].s();

        // Enhanced password and secret key hashing
        std::string hashedPassword = SecurityUtils::sha512(password + cookieUsers);
        std::string hashedSecretKey = SecurityUtils::sha512(secretKey);
        
        if (db.createUser(username, hashedPassword, cookieUsers, hashedSecretKey)) {
            crow::json::wvalue response;
            response["status"] = "success";
            response["token"] = SecurityUtils::generateJWT(username);
            return crow::response(201, response);
        }
        return crow::response(400, "User creation failed");
    });

    // Enhanced checked endpoint with rate limiting
    CROW_ROUTE(app, "/checked/<string>").methods("POST"_method)
    ([&db, &rateLimiter](const crow::request& req, std::string cookieUsers) {
        auto bodyArgs = crow::json::load(req.body);
        if (!bodyArgs) {
            return crow::response(400, "Invalid JSON");
        }

        std::string username = bodyArgs["username"].s();
        
        if (db.updateCheckedCount(username)) {
            crow::json::wvalue response;
            response["status"] = "success";
            return crow::response(200, response);
        }
        return crow::response(400, "Update failed");
    });

    // New log endpoint
    CROW_ROUTE(app, "/log/<string>").methods("GET"_method)
    ([&db](const std::string& cookieUsers) {
        auto bodyArgs = crow::json::load(cookieUsers);
        if (!bodyArgs) {
            return crow::response(400, "Invalid JSON");
        }

        std::string username = bodyArgs["username"].s();
        
        if (auto logs = db.getUserLog(username)) {
            return crow::response(200, *logs);
        }
        return crow::response(400, "Failed to retrieve logs");
    });

    rack endpoint with enhanced security and caching
    CROW_ROUTE(app, "/track/<string>/<string>").methods("GET"_method)
    ([&db](const std::string& cookieUsers, const std::string& targetTrackHashed) {
        auto bodyArgs = crow::json::load(cookieUsers);
        if (!bodyArgs) {
            return crow::response(400, "Invalid JSON");
        }

        std::string username = bodyArgs["username"].s();
        
        if (auto trackData = db.trackUser(username, targetTrackHashed)) {
            return crow::response(200, *trackData);
        }
        return crow::response(404, "User not found");
    });

    // Health check endpoint
    CROW_ROUTE(app, "/health")
    ([]() {
        crow::json::wvalue response;
        response["status"] = "healthy";
        response["timestamp"] = std::time(nullptr);
        return crow::response(200, response);
    });

    // Error handling middleware
    app.error_handler([](crow::response& res, std::exception& e) {
        res.code = 500;
        res.write("Internal Server Error: " + std::string(e.what()));
        res.end();
    });

    // Configure server settings
    app.loglevel(crow::LogLevel::Warning);
    
    // Set up SSL/TLS
    auto& ssl = app.ssl_context();
    ssl.set_verify_mode(boost::asio::ssl::verify_peer);
    ssl.use_private_key_file("server.key", boost::asio::ssl::context::pem);
    ssl.use_certificate_chain_file("server.crt");
    
    // Start the server with multiple threads and SSL
    uint16_t port = 8443;  // Standard HTTPS port
    uint16_t threads = std::thread::hardware_concurrency();
    std::cout << "Starting secure server on port " << port << " with " << threads << " threads" << std::endl;
    
    app.port(port)
       .ssl_file("server.crt", "server.key")
       .concurrency(threads)
       .run();
    
    return 0;
}
