#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

std::string get_status(struct stat& st) {
// TODO (get status)
    std::string str_stats = "";
    return str_stats;
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

