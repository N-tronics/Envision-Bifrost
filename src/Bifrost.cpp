#include <DiffieHellman.hpp>
#include <HMAC_SHA1.hpp>
#include <random.hpp>
#include <typedefs.hpp>
#include <utilities.hpp>

#include <ctime>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;

string generateTOTP(Bytes key, Diffie_Hellman &dh) {
    // TOTP
    time_t timestamp = time(NULL);

    cpp_int timestep = timestamp / 30;

    //Bytes message = dh.cpp_int_to_bytes(timestep);
    Bytes message(8);
    for(int i=7;i>-1;i--){
        message[i]=(timestep & 0xFF).convert_to<Byte>();
        timestep>>=8;
    }

    Bytes hmac_bytes = hmac_sha1(key, message);

    int offset = hmac_bytes[hmac_bytes.size() - 1] & 0x0F;

    Bytes sample_bytes;

    for (int i = offset; i < offset + 4; i++) {
        sample_bytes.push_back(hmac_bytes[i]);
    }

    sample_bytes[0] &= 0x7f;

    cpp_int sample = bytesToCppInt(sample_bytes);

    int OTP = (sample % 1000000).convert_to<int>();

    string otp_string = to_string(OTP);

    while (otp_string.length() < 6) {
        otp_string = "0" + otp_string;
    }

    return otp_string;
}

int main() {
    try {
        string registrationCode;

        cout << "Enter 6-digit registration code: ";
        cin >> registrationCode;

        if (registrationCode.length() != 6) {
            throw runtime_error("Registration code must be 6 digits.");
        }

        Diffie_Hellman bifrostDH;

        string bifrostPublicKeyHex = cppIntToHex(bifrostDH.public_key);

        json requestBody;

        requestBody["bifrost-public-key"] = bifrostPublicKeyHex;

        string url = "http://localhost:8080/signup/" + registrationCode;

        cout << "\nSending POST request to:\n";
        cout << url << endl;

        cout << "\nBifrost public key:\n";
        cout << bifrostPublicKeyHex << endl;

        cpr::Response response =
            cpr::Post(cpr::Url{url}, cpr::Body{requestBody.dump()},
                      cpr::Header{{"Content-Type", "application/json"}});

        if (response.error) {
            throw runtime_error(response.error.message);
        }

        if (response.status_code != 200) {
            cout << "\nServer response:\n";
            cout << response.text << endl;

            throw runtime_error("Server returned status code " +
                                to_string(response.status_code));
        }

        json responseJson = json::parse(response.text);

        if (!responseJson.contains("server-public-key")) {
            throw runtime_error(
                "Response JSON does not contain server-public-key.");
        }

        string serverPublicKeyHex = responseJson["server-public-key"];

        cpp_int serverPublicKey = hexToCppInt(serverPublicKeyHex);

        cpp_int sharedSecret = bifrostDH.compute_shared_secret(serverPublicKey);


        Bytes key = bifrostDH.cpp_int_to_bytes(sharedSecret);

        key = bifrostDH.resizeKey(key, nBytes);

        string sharedSecret_hex = bytesToHex(key);

        ofstream file("shared_secret.txt");

        if (!file) {
            throw runtime_error("Could not create shared_secret.txt");
        }

        file << sharedSecret_hex;
        file.close();

        ifstream saved_file("shared_secret.txt");
        if(!saved_file){
            throw runtime_error("couldn't open shared_secret.txt");
        }
        string loaded_secret;
        getline(saved_file,loaded_secret);
        saved_file.close();

        string otp = generateTOTP(hexToBytes(loaded_secret), bifrostDH);

        cout << "\nServer public key:\n";
        cout << serverPublicKeyHex << endl;

        cout << "\nShared secret saved in shared_secret.txt" << endl;

        cout << "\nGenerated OTP: " << otp << endl;
    } catch (const exception &e) {
        cerr << "\nError: " << e.what() << endl;
        return 1;
    }

    return 0;
}
