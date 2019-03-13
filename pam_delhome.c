#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ftw.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

static int rmFiles(const char *pathname, const struct stat *sbuf, int type, struct FTW *ftwb) {
    if(remove(pathname) < 0) {
        return -1;
    }    
    return 0;
}


static int rm_dir(pam_handle_t *pamh, const char *dir_path) {
    if (nftw(dir_path, rmFiles,10, FTW_DEPTH|FTW_MOUNT|FTW_PHYS) < 0) {
	    pam_syslog(pamh, LOG_ERR, "Error in nftw");
    }
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
				    const char **argv)
{
	const char *username;
	char dir_path[512];

	/* Get the username from PAM */
	pam_get_item(pamh, PAM_USER, (const void **)&username);

	if(strcmp(username, "master") == 0) {
		/* We don't want to delete master home dir */
		pam_syslog(pamh, LOG_ERR, "root-expert: username is master");
		return PAM_SUCCESS;
	}

	/* Creating directory path string */
	sprintf(dir_path, "/home/%s", username);

	rm_dir(pamh, dir_path);

	return PAM_SUCCESS;
}
