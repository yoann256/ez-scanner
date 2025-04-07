#include <curl/curl.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <unistd.h> // for sleep

#include "libraries/parson/parson.c"
#include "libraries/parson/parson.h"

#define VIRUSTOTAL_API_KEY "28ab61a2b12ffbb0866fc66cf0fdc8a4d63bc60404a9134ff978e9832e96da2d"

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

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
        std::string auth_header = "x-apikey: ";
        auth_header += api_key;
        headers = curl_slist_append(headers, auth_header.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return response;
}

std::string upload_file_to_virustotal(const std::string& file_path, const char* api_key) {
    CURL* curl = curl_easy_init();
    std::string response;

    if (curl) {
        std::string url = "https://www.virustotal.com/api/v3/files";
        struct curl_slist* headers = nullptr;
        std::string auth_header = "x-apikey: ";
        auth_header += api_key;
        headers = curl_slist_append(headers, auth_header.c_str());

        // Open the file to upload
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            std::cerr << "Error: Cannot open file for upload: " << file_path << "\n";
            return "";
        }

        curl_httppost* formpost = NULL;
        curl_httppost* lastptr = NULL;
        curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "file", CURLFORM_FILE, file_path.c_str(), CURLFORM_END);

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);

        if (res != CURLE_OK) {
            std::cerr << "Error uploading file to VirusTotal: " << curl_easy_strerror(res) << "\n";
            return "";
        }

        return response;
    }
    return "";
}

std::string check_file_analysis_status(const std::string& analysis_id, const char* api_key) {
    CURL* curl = curl_easy_init();
    std::string response;

    if (curl) {
        std::string url = "https://www.virustotal.com/api/v3/analyses/" + analysis_id;
        struct curl_slist* headers = nullptr;
        std::string auth_header = "x-apikey: ";
        auth_header += api_key;
        headers = curl_slist_append(headers, auth_header.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);

        if (res != CURLE_OK) {
            std::cerr << "Error checking file analysis status: " << curl_easy_strerror(res) << "\n";
            return "";
        }
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
    if (!data) {
        std::cerr << "❌ No 'data' object in response.\n";
        std::cerr << "Response: " << json << "\n";  // Debugging the response to check its structure
        json_value_free(root);
        return;
    }

    JSON_Object* attr = json_object_get_object(data, "attributes");
    JSON_Object* stats = json_object_get_object(attr, "last_analysis_stats");

    int malicious = (int)json_object_get_number(stats, "malicious");
    int undetected = (int)json_object_get_number(stats, "undetected");

    printf("🚨 Malicious: %d\n✅ Undetected: %d\n", malicious, undetected);

    json_value_free(root);
}

int print_help() {
    printf("EZ Scanner Help:\n\n");
    printf("Command syntax: EZScanner file_to_scan\n\n");
    printf("- yoann256\n");

    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
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

    // First, check if the file exists on VirusTotal by hash
    std::string json = send_virustotal_request(hash, VIRUSTOTAL_API_KEY);

    // If not found, upload the file
    if (json.find("data") == std::string::npos) {
        std::cout << "File not found on VirusTotal. Uploading for analysis...\n";
        json = upload_file_to_virustotal(filename, VIRUSTOTAL_API_KEY);
        if (json.empty()) {
            std::cerr << "Failed to upload file to VirusTotal.\n";
            return 1;
        }

        // Debugging: Print out the full response to understand the structure
        std::cout << "Upload Response: " << json << "\n";

        // Parse the analysis ID from the response (ensure the response is valid)
        JSON_Value* root = json_parse_string(json.c_str());
        if (!root) {
            std::cerr << "Error parsing response after upload.\n";
            return 1;
        }

        JSON_Object* data = json_object_get_object(json_object(root), "data");
        if (!data) {
            std::cerr << "❌ No 'data' object found in upload response.\n";
            json_value_free(root);
            return 1;
        }

        std::string analysis_id = json_object_get_string(data, "id");
        json_value_free(root);

        if (analysis_id.empty()) {
            std::cerr << "❌ No analysis ID found in the response.\n";
            return 1;
        }

        std::cout << "File uploaded. Please wait for analysis to complete.\n";

        // Poll until analysis is complete
        bool analysis_done = false;
        while (!analysis_done) {
            std::string status_json = check_file_analysis_status(analysis_id, VIRUSTOTAL_API_KEY);

            // Debugging: Print out the full status response
            std::cout << "Status Response: " << status_json << "\n";

            // Parse the status
            root = json_parse_string(status_json.c_str());
            if (!root) {
                std::cerr << "Error parsing status response.\n";
                break;
            }

            JSON_Object* status_data = json_object_get_object(json_object(root), "data");
            if (!status_data) {
                std::cerr << "❌ No 'data' object in status response.\n";
                json_value_free(root);
                break;
            }

            std::string status = json_object_get_string(status_data, "attributes.status");

            if (status == "completed") {
                analysis_done = true;
                std::cout << "Analysis complete.\n";
            } else {
                std::cout << "Analysis in progress. Retrying...\n";
                sleep(5); // Retry every 5 seconds
            }

            json_value_free(root);
        }
    }

    // Get the full analysis result (whether uploaded or found)
    json = send_virustotal_request(hash, VIRUSTOTAL_API_KEY);
    parse_response(json);

    return 0;
}
