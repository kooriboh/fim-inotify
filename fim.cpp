#include "fim.h"

// check if file's metadata already existed
int fim::check_path(string path)
{
    struct stat info;
    if (stat(path.c_str(), &info) == 0)
    {
        if (info.st_mode & S_IFDIR)
        {
            return 1; //it's a directory
        }
        else if(info.st_mode & S_IFREG)
        {
            return 0; //it's a file
        }
        else
        {
            return 2; //something else
        }
    }
    else
    {
        return 2; //error
    }
}

string fim::path_append(const string& path_1, const string& path_2) 
{

    char sep = '/';
    string tmp = path_1;

#ifdef _WIN32
    sep = '\\';
#endif

    if (path_1[path_1.length()] != sep) // Need to add a path separator
    {
        tmp += sep;
        return(tmp + path_2);
    }
    else
    {
        return(path_1 + path_2);
    }
}

string fim::get_host_name()
{
    char hname[1024];
    gethostname(hname, sizeof(hname) - 1);

    string hostname(hname);
    return hostname;
}

string fim::get_file_size(string path) 
{
    struct stat info;
    int rc = stat(path.c_str(), &info);
    return rc == 0 ? to_string(info.st_size) : to_string(-1);
}

string fim::get_md5hash(const string& file_path)
{
    char buffer[BUFFSIZE];
    unsigned char digest[MD5_DIGEST_LENGTH];

    stringstream ss;
    string md5string;

    ifstream ifs(file_path, std::ifstream::binary); 
    MD5_CTX md5Context;

    MD5_Init(&md5Context);

    while (ifs.good())
    {
        ifs.read(buffer, BUFFSIZE);

        MD5_Update(&md5Context, buffer, ifs.gcount());
    }

    ifs.close();

    int res = MD5_Final(digest, &md5Context);

    if (res == 0)
    {
        return {};
    }

    ss << hex << std::setfill('0');

    for (unsigned char uc: digest)
    {
        ss << setw(2) << (int)uc;
    }

    md5string = ss.str();

    return md5string;
}

void fim::get_metadata_file(string file_path, struct metadata_info_struct *f_metadata_info)
{
    f_metadata_info->path = file_path;
    f_metadata_info->owner = "";
    f_metadata_info->group = "";
    f_metadata_info->permission = "";

    struct stat info;

    if(stat(f_metadata_info->path.c_str(), &info) == 0)
    {
        struct passwd *pw = getpwuid(info.st_uid);
        f_metadata_info->owner += pw->pw_name;

        struct group *gr = getgrgid(info.st_gid);
        f_metadata_info->group += gr->gr_name;

        char *modeval = (char*)malloc(sizeof(char) * 9 + 1);

        mode_t perm = info.st_mode;
        modeval[0] = (perm & S_IRUSR) ? 'r' : '-';
        modeval[1] = (perm & S_IWUSR) ? 'w' : '-';
        modeval[2] = (perm & S_IXUSR) ? 'x' : '-';
        modeval[3] = (perm & S_IRGRP) ? 'r' : '-';
        modeval[4] = (perm & S_IWGRP) ? 'w' : '-';
        modeval[5] = (perm & S_IXGRP) ? 'x' : '-';
        modeval[6] = (perm & S_IROTH) ? 'r' : '-';
        modeval[7] = (perm & S_IWOTH) ? 'w' : '-';
        modeval[8] = (perm & S_IXOTH) ? 'x' : '-';
        modeval[9] = '\0';

        f_metadata_info->permission += modeval;
        free(modeval);
    }

    string file_size = get_file_size(file_path);
    f_metadata_info->size = file_size;

    if (file_size.size() <= 8)
    {
        f_metadata_info->md5 = get_md5hash(file_path);
    }
    else
    {
        f_metadata_info->md5 = "-1";
    }
}

void fim::get_metadata_dir(string dir_name, struct metadata_info_struct *f_metadata_info)
{
    f_metadata_info->path = dir_name;
    f_metadata_info->owner = "";
    f_metadata_info->group = "";
    f_metadata_info->permission = "";

    struct stat info;

    if(stat(f_metadata_info->path.c_str(), &info) == 0)
    {
        struct passwd *pw = getpwuid(info.st_uid);
        f_metadata_info->owner += pw->pw_name;

        struct group *gr = getgrgid(info.st_gid);
        f_metadata_info->group += gr->gr_name;

        char *modeval = (char*)malloc(sizeof(char) * 9 + 1);

        mode_t perm = info.st_mode;
        modeval[0] = (perm & S_IRUSR) ? 'r' : '-';
        modeval[1] = (perm & S_IWUSR) ? 'w' : '-';
        modeval[2] = (perm & S_IXUSR) ? 'x' : '-';
        modeval[3] = (perm & S_IRGRP) ? 'r' : '-';
        modeval[4] = (perm & S_IWGRP) ? 'w' : '-';
        modeval[5] = (perm & S_IXGRP) ? 'x' : '-';
        modeval[6] = (perm & S_IROTH) ? 'r' : '-';
        modeval[7] = (perm & S_IWOTH) ? 'w' : '-';
        modeval[8] = (perm & S_IXOTH) ? 'x' : '-';
        modeval[9] = '\0';

        f_metadata_info->permission += modeval;
        free(modeval);
    }

    f_metadata_info->size = "-1";
    f_metadata_info->md5 = "-1";
}

void fim::make_metadata_log(string monitor_path)
{
    struct metadata_info_struct f_metadata_info;

    int dir_check = check_path(monitor_path);

    if (dir_check == ITEM_TYPE_DIR)  //monitor_path is a dir
    {
        get_metadata_dir(monitor_path, &f_metadata_info);
        metadata_info_map[monitor_path] = f_metadata_info;

        if (auto dir = opendir(monitor_path.c_str())) 
        {
            while (auto dir_item = readdir(dir)) 
            {
                if (!dir_item->d_name || strcmp(dir_item->d_name, ".") == 0|| strcmp(dir_item->d_name, "..") == 0)
                {
                    continue;
                }
                string monitor_item(dir_item->d_name);
                string monitor_item_path = "";

                if (monitor_path == "/")
                {
                    monitor_item_path += monitor_path;
                    monitor_item_path += monitor_item;
                }
                else
                {
                    monitor_item_path += path_append(monitor_path, monitor_item);
                }

                struct metadata_info_struct f_item_metadata_info;

                int dir_check = check_path(monitor_item_path);
                if (dir_check == ITEM_TYPE_DIR)
                {
                    get_metadata_dir(monitor_item_path, &f_item_metadata_info);
                    metadata_info_map[monitor_item_path] = f_item_metadata_info;
                }
                else if (dir_check == ITEM_TYPE_FILE)
                {
                    get_metadata_file(monitor_item_path, &f_item_metadata_info);
                    metadata_info_map[monitor_item_path] = f_item_metadata_info;                
                }
            }
            closedir(dir);
        }
    }
    else if (dir_check == ITEM_TYPE_FILE)   //monitor_path is a file
    {
        get_metadata_file(monitor_path, &f_metadata_info);
        metadata_info_map[monitor_path] = f_metadata_info;
    }
    else
    {
        cout << "Can not open " << monitor_path << endl;
    }
}

void fim::file_integrity_monitoring(string monitor_path, string monitor_mask, bool excluded_list_exist)
{
    try 
    {
        int temp_length = monitor_mask.length();
        int space_count = count(monitor_mask.begin(), monitor_mask.end(), ' ');
        remove(monitor_mask.begin(), monitor_mask.end(), ' ');
        monitor_mask.resize(temp_length - space_count);

        int curr_index = 0, index = 0;
        int start_index = 0, end_index = 0;
        string sub_monitor_mask[14];

        while (index <= monitor_mask.length())
        {
            if (monitor_mask[index] == '|' || index == monitor_mask.length())
            {
                end_index = index;
                string sub_str = "";

                sub_str.append(monitor_mask, start_index, end_index - start_index);

                if (mask_set.find(sub_str) != mask_set.end())
                {
                    if (sub_str == "IN_CLOSE")
                    {
                        sub_monitor_mask[curr_index] = "IN_CLOSE_WRITE";
                        curr_index += 1;
                        sub_monitor_mask[curr_index] = "IN_CLOSE_NOWRITE";
                        curr_index += 1;
                    }
                    else if (sub_str == "IN_MOVE")
                    {
                        sub_monitor_mask[curr_index] = "IN_MOVED_FROM";
                        curr_index += 1;
                        sub_monitor_mask[curr_index] = "IN_MOVED_TO";
                        curr_index += 1;
                    }
                    else
                    {
                        sub_monitor_mask[curr_index] = sub_str;
                        curr_index += 1;
                    }
                }
                else
                {
                    cout << "Invalid mask at monitoring-item " << monitor_path << endl;
                }
                start_index = end_index + 1;
            }
            index++;
        }

        mask_map["IN_ACCESS"] = 0x00000001;
        mask_map["IN_MODIFY"] = 0x00000002;
        mask_map["IN_ATTRIB"] = 0x00000004;
        mask_map["IN_CLOSE_WRITE"] = 0x00000008;
        mask_map["IN_CLOSE_NOWRITE"] = 0x00000010;
        mask_map["IN_OPEN"] = 0x00000020;
        mask_map["IN_MOVED_FROM"] = 0x00000040;
        mask_map["IN_MOVED_TO"] = 0x00000080;
        mask_map["IN_CREATE"] = 0x00000100;
        mask_map["IN_DELETE"] = 0x00000200;
        mask_map["IN_DELETE_SELF"] = 0x00000400;
        mask_map["IN_MOVE_SELF"] = 0x00000800;

        InotifyWatch monitor("/", IN_MODIFY);

        if (curr_index == 1)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]]);
        }
        else if (curr_index == 2)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]]);
        }
        else if (curr_index == 3)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]]);
        }
        else if (curr_index == 4)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]]);
        }
        else if (curr_index == 5)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]] | mask_map[sub_monitor_mask[4]]);
        }
        else if (curr_index == 6)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]] | mask_map[sub_monitor_mask[4]] | mask_map[sub_monitor_mask[5]]);
        }
        else if (curr_index == 7)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]] | mask_map[sub_monitor_mask[4]] | mask_map[sub_monitor_mask[5]] |
                                mask_map[sub_monitor_mask[6]]);
        }
        else if (curr_index == 8)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]] | mask_map[sub_monitor_mask[4]] | mask_map[sub_monitor_mask[5]] |
                                mask_map[sub_monitor_mask[6]] | mask_map[sub_monitor_mask[7]]);
        }
        else if (curr_index == 9)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]] | mask_map[sub_monitor_mask[4]] | mask_map[sub_monitor_mask[5]] |
                                mask_map[sub_monitor_mask[6]] | mask_map[sub_monitor_mask[7]] | mask_map[sub_monitor_mask[8]]);
        }
        else if (curr_index == 10)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]] | mask_map[sub_monitor_mask[4]] | mask_map[sub_monitor_mask[5]] |
                                mask_map[sub_monitor_mask[6]] | mask_map[sub_monitor_mask[7]] | mask_map[sub_monitor_mask[8]] |
                                mask_map[sub_monitor_mask[9]]);
        }
        else if (curr_index == 11)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]] | mask_map[sub_monitor_mask[4]] | mask_map[sub_monitor_mask[5]] |
                                mask_map[sub_monitor_mask[6]] | mask_map[sub_monitor_mask[7]] | mask_map[sub_monitor_mask[8]] |
                                mask_map[sub_monitor_mask[9]] | mask_map[sub_monitor_mask[10]]);
        }
        else if (curr_index == 12)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]] | mask_map[sub_monitor_mask[4]] | mask_map[sub_monitor_mask[5]] |
                                mask_map[sub_monitor_mask[6]] | mask_map[sub_monitor_mask[7]] | mask_map[sub_monitor_mask[8]] |
                                mask_map[sub_monitor_mask[9]] | mask_map[sub_monitor_mask[10]] | mask_map[sub_monitor_mask[11]]);
        }
        else if (curr_index == 13)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]] | mask_map[sub_monitor_mask[4]] | mask_map[sub_monitor_mask[5]] |
                                mask_map[sub_monitor_mask[6]] | mask_map[sub_monitor_mask[7]] | mask_map[sub_monitor_mask[8]] |
                                mask_map[sub_monitor_mask[9]] | mask_map[sub_monitor_mask[10]] | mask_map[sub_monitor_mask[11]] |
                                mask_map[sub_monitor_mask[12]]);
        }
        else if (curr_index == 14)
        {
            monitor = InotifyWatch(monitor_path, mask_map[sub_monitor_mask[0]] | mask_map[sub_monitor_mask[1]] |  mask_map[sub_monitor_mask[2]] |
                                mask_map[sub_monitor_mask[3]] | mask_map[sub_monitor_mask[4]] | mask_map[sub_monitor_mask[5]] |
                                mask_map[sub_monitor_mask[6]] | mask_map[sub_monitor_mask[7]] | mask_map[sub_monitor_mask[8]] |
                                mask_map[sub_monitor_mask[9]] | mask_map[sub_monitor_mask[10]] | mask_map[sub_monitor_mask[11]] |
                                mask_map[sub_monitor_mask[12]] | mask_map[sub_monitor_mask[13]]);
        }
        else
        {
            monitor = InotifyWatch(monitor_path, IN_MODIFY | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO |
                                IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF);
        }

        Inotify notify;
        notify.Add(monitor);

        cout << "Monitoring directory " << monitor_path << endl << endl;

        for (;;) 
        {
            notify.WaitForEvents();

            size_t event_count = notify.GetEventCount();
            while (event_count > 0) 
            {
                InotifyEvent event;
                bool got_event = notify.GetEvent(&event);

                if (got_event) 
                {
                    struct metadata_info_struct f_metadata_info;
                    string mask_str;
                    event.DumpTypes(mask_str);
                    string monitor_item = event.GetName();
                    string monitor_item_path = "";
                    string log_data = "";

                    uint64_t ev_time = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

                    if (monitor_item == "")
                    {
                        monitor_item_path += monitor_path;
                    }
                    else
                    {
                        if (monitor_path == "/")
                        {
                            monitor_item_path += monitor_path;
                            monitor_item_path += monitor_item;
                        }
                        else
                        {
                            monitor_item_path += path_append(monitor_path, monitor_item);
                        }
                    }

                    // excluded list check
                    if ((excluded_list_exist == false) || 
                        (((excluded_item_map.find(monitor_item_path) != excluded_item_map.end()) && (excluded_item_map[monitor_item_path].mask.find(mask_str) == string::npos)) || (excluded_item_map.find(monitor_item_path) == excluded_item_map.end())))
                    {
                        string hostname = get_host_name();

                        if (mask_str.substr(mask_str.length() - 3).compare("DIR") == 0) //it's a directory
                        {
                            get_metadata_dir(monitor_item_path, &f_metadata_info);

                            // get old metadata
                            string old_owner;
                            string old_group;
                            string old_permission;

                            if (metadata_info_map.find(monitor_item_path) == metadata_info_map.end())
                            {
                                old_owner = "-1";
                                old_group = "-1";
                                old_permission = "-1";

                                metadata_info_map[monitor_item_path] = f_metadata_info;
                            }
                            else
                            {
                                old_owner = metadata_info_map[monitor_item_path].owner;
                                old_group = metadata_info_map[monitor_item_path].group;
                                old_permission = metadata_info_map[monitor_item_path].permission;

                                metadata_info_map[monitor_item_path] = f_metadata_info;
                            }

                            string header = "\"header\":{\"logsource\":\"falco\",\"time\":" + std::to_string(ev_time);
                            header += ",\"syscall\":\"inotify\"";
                            header += ",\"source\":\"" + monitor_path + "\"}";

                            string body = "\"body\":{\"hostname\":\"" + hostname;

                            body += "\",\"dir\":\"" + f_metadata_info.path;
                            body += "\",\"owner\":\"" + f_metadata_info.owner;
                            body += "\",\"old_owner\":\"" + old_owner;
                            body += "\",\"group\":\"" + f_metadata_info.group;
                            body += "\",\"old_group\":\"" + old_group;
                            body += "\",\"perm\":\"" + f_metadata_info.permission;
                            body += "\",\"old_perm\":\"" + old_permission;
                            body += "\",\"mask\":\"" + mask_str + "\"}";

                            log_data += "{" + header + "," + body + "}\n";
                        }
                        else //it's a file
                        {
                            get_metadata_file(monitor_item_path, &f_metadata_info);

                            // get old metadata
                            string old_owner;
                            string old_group;
                            string old_permission;
                            string old_size;
                            string old_md5;
                            
                            if (metadata_info_map.find(monitor_item_path) == metadata_info_map.end())
                            {
                                old_owner = "-1";
                                old_group = "-1";
                                old_permission = "-1";
                                old_size = "-1";
                                old_md5 = "-1";

                                metadata_info_map[monitor_item_path] = f_metadata_info;
                            }
                            else
                            {
                                old_owner = metadata_info_map[monitor_item_path].owner;
                                old_group = metadata_info_map[monitor_item_path].group;
                                old_permission = metadata_info_map[monitor_item_path].permission;
                                old_size = metadata_info_map[monitor_item_path].size;
                                old_md5 = metadata_info_map[monitor_item_path].md5;

                                metadata_info_map[monitor_item_path] = f_metadata_info;
                            }

                            string header = "\"header\":{\"logsource\":\"falco\",\"time\":" + std::to_string(ev_time);
                            header += ",\"syscall\":\"inotify\"";
                            header += ",\"source\":\"" + monitor_path + "\"}";

                            string body = "\"body\":{\"hostname\":\"" + hostname;


                            body += "\",\"file\":\"" + f_metadata_info.path;
                            body += "\",\"owner\":\"" + f_metadata_info.owner;
                            body += "\",\"old_owner\":\"" + old_owner;
                            body += "\",\"group\":\"" + f_metadata_info.group;
                            body += "\",\"old_group\":\"" + old_group;
                            body += "\",\"perm\":\"" + f_metadata_info.permission;
                            body += "\",\"old_perm\":\"" + old_permission;
                            body += "\",\"size\":\"" + f_metadata_info.size;
                            body += "\",\"old_size\":\"" + old_size;
                            body += "\",\"md5\":\"" + f_metadata_info.md5;
                            body += "\",\"old_md5\":\"" + old_md5;
                            body += "\",\"mask\":\"" + mask_str + "\"}";

                            log_data += "{" + header + "," + body + "}\n";
                        }
                        cout << log_data;
                    }
                }
                event_count--;
            }
        }
    } 
    catch (InotifyException &e) 
    {
        cerr << "Inotify exception occured: " << e.GetMessage() << endl;
    } 
    catch (exception &e) 
    {
        cerr << "STL exception occured: " << e.what() << endl;
    } 
    catch (...) 
    {
        cerr << "unknown exception occured" << endl;
    }

    pthread_exit(NULL);
}

void fim::run_fim()
{
    int item_count = 0;
    int thread_count = 0;
    vector<string> monitor_list;
    
    ifstream f_config("fim_config.json");
    
    json j_data = json::parse(f_config);
    
    for (auto& elem : j_data["monitor-item"])
    {
        monitor_list.push_back(elem["path"]);
        item_count++;
    }

    thread f_monitor[item_count];

    for (auto& it : j_data["monitor-item"].items())
    {
        string monitor_path = it.value()["path"];
        string monitor_mask = it.value()["mask"];

        bool excluded_list_exist = false;
        for (auto& excluded_it : it.value()["excluded-item"].items())
        {
            struct excluded_item_struct f_excluded_item;

            string excluded_path = excluded_it.value()["excluded-path"];
            string excluded_mask = excluded_it.value()["excluded-mask"];
            f_excluded_item.path = excluded_path;
            f_excluded_item.mask = excluded_mask;

            excluded_item_map[excluded_path] = f_excluded_item;

            excluded_list_exist = true;
        }

        make_metadata_log(monitor_path);
        f_monitor[thread_count] = thread(file_integrity_monitoring, monitor_path, monitor_mask, excluded_list_exist);
        thread_count++;
    }

    for (int index = 0; index < item_count; index++)
    {
        f_monitor[index].join();
    }
}