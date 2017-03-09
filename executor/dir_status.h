#include <map>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/sha.h>

std::string format_time(struct stat& st) {
    // TODO (maybe not hash?)
    unsigned long atime, mtime, ctime;
    atime = (st.st_atim.tv_nsec > 0 ? st.st_atim.tv_nsec : st.st_atim.tv_sec);
    mtime = (st.st_mtim.tv_nsec > 0 ? st.st_mtim.tv_nsec : st.st_mtim.tv_sec);
    ctime = (st.st_ctim.tv_nsec > 0 ? st.st_ctim.tv_nsec : st.st_ctim.tv_sec);
    std::string tmp;
    if (atime >= mtime && atime >= ctime) {
        if (mtime >= ctime) {
            tmp = "amc";
        } else {
            tmp = "acm";
        }
    } else if (mtime >= ctime) {
        if (atime >= ctime) {
            tmp = "mac";
        } else {
            tmp = "mca";
        }
    } else {
        if (atime >= mtime) {
            tmp = "cam";
        } else {
            tmp = "cma";
        }
    }
    return tmp;
}

std::string get_status(struct stat& st) {
// TODO (get status)
    std::stringstream status_str;
    status_str << (unsigned long) st.st_mode << ","     // file type + permission
               << (long) st.st_nlink << ","             // link count
               << (long) st.st_uid << "," << (long) st.st_gid << "," // ownership
               << (long long) st.st_size << ","         // file size
              // << (long long) st.st_blocks << ","       // blocks allocated
               << format_time(st);                       // time (last status change, last file access, last file modification)
	return status_str.str();
}

void update_dir_status(const char* dir, std::map<std::string, std::string>& file_status)
{
    DIR *dp;
    struct dirent *ep;
	dp = opendir(dir);
	if (dp == NULL) {
		debug("update_dir_status: opendir(%s) failed", dir);
        return;
	}
	while ((ep = readdir(dp))) {
		if (strcmp(ep->d_name, ".") == 0 || strcmp(ep->d_name, "..") == 0)
			continue;
        std::string filename = "";
        filename += dir;
        filename += "/";
        filename += ep->d_name;
		struct stat st;
		if (lstat(filename.c_str(), &st))
			exitf("lstat(%s) failed", filename);
		if (S_ISDIR(st.st_mode)) {
            update_dir_status(filename.c_str(), file_status);
			continue;
		}
        file_status[filename] = get_status(st);
	}
	closedir(dp);
}

void hash_dir_status(const std::map<std::string, std::string>& file_status, unsigned char* hash) {
	std::stringstream ss;
	for (auto it = file_status.begin(); it != file_status.end(); it++) {
		ss << it->first << ":" << it->second << ";";
	}
	std::string status_str = ss.str();
    debug("[HashDirStatus], status_str: %s\n", status_str.c_str());
	SHA1((unsigned char*)status_str.c_str(), status_str.length(), hash);
}

