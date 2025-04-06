#include <curl/curl.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iomanip>


#include "libraries/parson/parson.c"
#include "libraries/parson/parson.h"

#define VIRUSTOTAL_API_KEY "28ab61a2b12ffbb0866fc66cf0fdc8a4d63bc60404a9134ff978e9832e96da2d"

std::string compute_sha256(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return "";

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)))
        SHA256_Update(&sha256, buffer, file.gcount());
    SHA256_Update(&sha256, buffer, file.gcount()); // update remaining

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::ostringstream result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return result.str();
}

std::string send_virustotal_request(const std::string& hash, const char* api_key) {
    CURL* curl = curl_easy_init();
    std::string response;

    if (curl) {
        std::string url = "https://www.virustotal.com/api/v3/files/" + hash;
        struct curl_slist* headers = nullptr;
        std::string auth_header = "Authorization: Bearer ";
        auth_header += api_key;
        headers = curl_slist_append(headers, auth_header.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](char* ptr, size_t size, size_t nmemb, std::string* data) {
            data->append(ptr, size * nmemb);
            return size * nmemb;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return response;
}


void parse_response(const std::string& json) {
    JSON_Value* root = json_parse_string(json.c_str());
    if (!root) {
        printf("Failed to parse JSON.\n");
        return;
    }

    JSON_Object* data = json_object_get_object(json_object(root), "data");
    JSON_Object* attr = json_object_get_object(data, "attributes");
    JSON_Object* stats = json_object_get_object(attr, "last_analysis_stats");

    int malicious = (int)json_object_get_number(stats, "malicious");
    int undetected = (int)json_object_get_number(stats, "undetected");

    printf("🚨 Malicious: %d\n✅ Undetected: %d\n", malicious, undetected);

    json_value_free(root);
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}






int print_help() {
    printf("EZ Scanner Help:\n\n");
    printf("Command syntax: EZScanner file_to_scan\n\n");
    printf("- yoann256\n");

    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        // Print an error and return
        print_help();
        
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0) {
        print_help();

        return 1;
    }

    const char* filename = argv[1];
    std::ifstream file(filename);

    if (!file) {
        std::cerr << "Error: Cannot open file " << filename << "\n";
        return 1;
    }

    std::string hash = compute_sha256(argv[1]);
    if (hash.empty()) {
        printf("Failed to compute hash.\n");
        return 1;
    }
    
    std::string json = send_virustotal_request(hash, VIRUSTOTAL_API_KEY);
    parse_response(json);
    

    file.close();
    return 0;
}

