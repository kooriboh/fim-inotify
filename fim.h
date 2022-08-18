#include <exception>
#include <dirent.h>
#include <iostream>
#include <chrono>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <thread>
#include <vector>
#include <string.h>
#include <string> 
#include <iomanip>
#include <set>
#include <unordered_map>
#include <algorithm>
#include <openssl/md5.h>
#include <sstream> 

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated"
#pragma GCC diagnostic pop

#include "nlohmann/json.hpp"
#include "inotify-cxx.h"

using namespace std;
using json = nlohmann::json;

#define BUFFSIZE 16384
#define ITEM_TYPE_DIR 1
#define ITEM_TYPE_FILE 0

class fim
{
private:
    set<string> mask_set{"IN_ACCESS", "IN_MODIFY", "IN_ATTRIB", "IN_CLOSE",
                    "IN_CLOSE_WRITE", "IN_CLOSE_NOWRITE", "IN_OPEN",
                    "IN_MOVE", "IN_MOVED_TO", "IN_MOVED_FROM", "IN_CREATE",
                    "IN_DELETE", "IN_DELETE_SELF", "IN_MOVE_SELF"};

    struct metadata_info_struct
    {
        string path;
        string owner;
        string group;
        string permission;
        string size;
        string md5;
    };

    struct excluded_item_struct
    {
        string path;
        string mask;
    };

    unordered_map<string, metadata_info_struct> metadata_info_map;
    unordered_map<string, excluded_item_struct> excluded_item_map;
    unordered_map<string, int> mask_map;

    int check_path(string path);
    string path_append(const string& path_1, const string& path_2);
    string get_host_name();
    string get_file_size(string path);
    string get_md5hash(const string& file_path);
    void get_metadata_file(string file_path, struct metadata_info_struct *f_metadata_info);
    void get_metadata_dir(string dir_name, struct metadata_info_struct *f_metadata_info);
    void make_metadata_log(string monitor_path);
    static void file_integrity_monitoring(string monitor_path, string monitor_mask, bool excluded_list_exist);

public:
    void run_fim();
};