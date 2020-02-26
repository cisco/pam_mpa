#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/wait.h>
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#define LOG(fmt, ...) do {                                              \
    char __prefix[256] = {0}, __msg[1024] = {0};                        \
    snprintf(__prefix, sizeof(__prefix), "%s@%d %s(): ",                \
            __FILE__, __LINE__,  __FUNCTION__);                         \
    snprintf(__msg, sizeof(__msg), "%s" fmt, __prefix, ## __VA_ARGS__); \
    pam_syslog(pamh, 4, __msg);                                         \
} while (0)
#define DBG(x...) if (cfg.debug) { LOG(x); }

#define CHKPWD_HELPER "/sbin/unix_chkpwd"

/* PAM module configuration */
struct cfg
{
    int debug;              /* boolean to enable debugging messages */
    char *usersfile;        /* path to the users file */
};

/* multi-person authentication configuration for a single account */
struct mpa_cfg
{
    int required;       /* number of authorizers required to authenticate */
    int authorizers;    /* number of authorizers in struct */
    char authorizer[][LOGIN_NAME_MAX + 1];     /* authorizer login name */
};

static void
parse_cfg(
    pam_handle_t *pamh,
    int flags,
    int argc,
    const char **argv,
    struct cfg *cfg)
{
    int i;

    cfg->debug = 0;
    cfg->usersfile = NULL;

    for (i = 0; i < argc; i++)
    {
        if (strncmp(argv[i], "debug", 5) == 0)
        {
            cfg->debug = 1;
        }
        else if (strncmp(argv[i], "usersfile=", 10) == 0)
        {
            cfg->usersfile = (char *)argv[i] + 10;
        }
        else
        {
            LOG("ERROR: unknown config argument: %s", argv[i]);
        }
    }
}

/* load_mpa_cfg()
 *
 * Load the multi-person authentication configuration for the given account
 *
 * Arguments:
 *  usersfile: path to the configuration file that contains MPA details
 *  account: account to look for in the users file
 *
 * Returns:
 *  NULL: account not found in users file
 *  != NULL: account found, config structure (caller must free)
 */
static struct mpa_cfg *
load_mpa_cfg(pam_handle_t *pamh, const char *usersfile, const char *account)
{
    FILE *file = NULL;
    char buf[1024] = {0}, *p = NULL, *authorized = NULL;
    struct mpa_cfg *out = NULL;
    long required = 0, count = 0;
    int len, i;
    size_t size;

    if (usersfile == NULL)
    {
        return NULL;
    }

    if (account == NULL)
    {
        return NULL;
    }

    len = strlen(account);
    if (len > LOGIN_NAME_MAX)
    {
        return NULL;
    }

    file = fopen(usersfile, "r");
    if (file == NULL)
    {
        LOG("fopen(%s) failed; %s (%d)", usersfile, strerror(errno),
                errno);
        return NULL;
    }

    while (fgets(buf, sizeof(buf), file) != NULL)
    {
        if (buf[0] == '#')
        {
            continue;
        }
        if (strncmp(buf, account, len) != 0)
        {
            continue;
        }
        if (buf[len] != ':')
        {
            continue;
        }

        required = strtol(buf + len + 1, &p, 0);
        if (required == LONG_MAX || required == LONG_MIN ||
                p == buf + len + 1)
        {
            LOG("strtol() failed for field 2 (required): '%s'", buf);
            continue;
        }
        if (*p != ':')
        {
            LOG("malformed line in userslist: '%s'", buf);
            continue;
        }

        /* count the number of authorized users for this account; assume 1 */
        count = 1;
        authorized = ++p;
        for (; *p != 0; p++)
        {
            if (*p == ',')
            {
                count++;
            }
        }

        /* allocate our output struct */
        size = sizeof(*out) + (count * (LOGIN_NAME_MAX + 1));
        out = malloc(size);
        if (out == NULL)
        {
            LOG("malloc(%lu) failed, %s (%d)", size, strerror(errno), errno);
            continue;
        }
        memset(out, 0, size);

        out->required = required;
        out->authorizers = count;

        for (p = authorized, i = 0; i < count; i++)
        {
            while (*p != 0 && *p != ',' && *p != '\n')
            {
                p++;
            }
            *p = 0;
            strncpy(out->authorizer[i], authorized, LOGIN_NAME_MAX);
            authorized = ++p;
        }

        return out;
    }

    return NULL;
}

#define authenticate(pamh, user, password) ({ \
    const char *__argv[] = { CHKPWD_HELPER, (user), "nonull", NULL }; \
    call_helper((pamh), __argv, (password)); \
})
#define check_expiry(pamh, user) ({ \
    const char *__argv[] = { CHKPWD_HELPER, (user), "chkexpiry", NULL }; \
    call_helper((pamh), __argv, NULL); \
})

static int
call_helper(
    pam_handle_t *pamh,
    const char *argv[],
    const char *in_buf)
{
    int rc, child, status;
    int helper_stdin[2] = {-1, -1}; /* pipe to the stdin for the helper */

    if (argv == NULL)
    {
        LOG("No argv");
        return PAM_AUTH_ERR;
    }

    if (in_buf != NULL)
    {
        rc = pipe(helper_stdin);
        if (rc != 0)
        {
            LOG("pipe() failed, %s", strerror(errno));
            return PAM_SERVICE_ERR;
        }
    }

    child = fork();
    if (child == -1)
    {
        LOG("fork() failed, %s", strerror(errno));
        close(helper_stdin[0]);
        close(helper_stdin[1]);
        return PAM_SERVICE_ERR;
    }

    /* parent process; write the password & wait on the status */
    else if (child > 0)
    {
        if (in_buf != NULL)
        {
            rc = write(helper_stdin[1], in_buf, strlen(in_buf) + 1);
            close(helper_stdin[1]);
            if (rc == -1)
            {
                LOG("write() failed, %s", strerror(errno));
                return PAM_SERVICE_ERR;
            }
        }

        rc = waitpid(child, &status, 0);
        if (rc == -1)
        {
            LOG("waitpid(%d) failed, %s", child, strerror(errno));
            return PAM_SERVICE_ERR;
        }

        return WIFEXITED(status) ? WEXITSTATUS(status) : PAM_SERVICE_ERR;
    }

    /* child process; will exec the helper */
    else
    {
        char *envp[] = { NULL };
        int fd, fd_max = sysconf(_SC_OPEN_MAX);

        /* redirect the pipe to stdin, or close it based on if there's no input
         * from the parent. */
        if (in_buf != NULL)
        {
            dup2(helper_stdin[0], 0);
        }
        else
        {
            close(0);
        }

        /* close all the other file descriptors */
        for (fd = 1; fd < fd_max; fd++)
        {
            close(fd);
        }

        /* the real uid must be root otherwise the helper gets mad */
        if (geteuid() == 0)
        {
            setuid(0);
        }

        execve(CHKPWD_HELPER, (char * const *)argv, envp);

        LOG("failed to execve(%s); %s (%d)", CHKPWD_HELPER, strerror(errno),
                errno);
        exit(PAM_AUTHINFO_UNAVAIL);
    }
}

PAM_EXTERN int
pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct cfg cfg;

    /* parse the options for this module */
    parse_cfg(pamh, flags, argc, argv, &cfg);
    DBG("flags: %d", flags);

    /* there's really nothing for us to do here; the application is supposed to
     * handle all uid/guid work */
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct cfg cfg;
    struct mpa_cfg *mpa_cfg;
    int retval, i, j, count, authorized;
    const char *account;
    char *authorizer = NULL, *password = NULL;
    char prompt[64] = {0};

    /* parse the options for this module */
    parse_cfg(pamh, flags, argc, argv, &cfg);

    /* if there is no users file configured, fail early */
    if (cfg.usersfile == NULL)
    {
        LOG("no usersfile configured\n");
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* fail if the user that is trying to authenticate doesn't exist in the
     * users file. */
    retval = pam_get_user(pamh, &account, "Username: ");
    if (retval != PAM_SUCCESS)
    {
        LOG("failed to get username\n");
        return PAM_USER_UNKNOWN;
    }

    mpa_cfg = load_mpa_cfg(pamh, cfg.usersfile, account);
    if (mpa_cfg == NULL)
    {
        DBG("account not present in %s; ignoring", cfg.usersfile);
        return PAM_IGNORE;
    }

    /* At this point, it is safe to log the account name; it cannot be a
     * password and exist in the usersfile. */
    if (cfg.debug)
    {
        LOG("Authorizing account '%s'; requires %d authorizers", account,
                mpa_cfg->required);
        for (i = 0; i < mpa_cfg->authorizers; i++)
        {
            LOG("mpa_cfg->authorizer[%d]: '%s'", i, mpa_cfg->authorizer[i]);
        }
    }

    if (mpa_cfg->required < 1)
    {
        LOG("rejecting authentication of account '%s'; required %d < 1",
                account, mpa_cfg->required);
        return PAM_AUTH_ERR;
    }

    /* query creds, and count the number of successful authentications */
    count = 0;
    for (i = 1; i <= mpa_cfg->required; i++)
    {
        /* prompt for the authorizer's username */
        snprintf(prompt, sizeof(prompt),
                "authorizer [%d of %d]: ", i, mpa_cfg->required);
        pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &authorizer, prompt);
        if (authorizer == NULL)
        {
            DBG("No authorizer %d username provided; aborting", i);
            return PAM_AUTH_ERR;
        }

        /* prompt for the password */
        snprintf(prompt, sizeof(prompt),
                "  password [%d of %d]: ", i, mpa_cfg->required);
        pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &password, prompt);
        if (password == NULL)
        {
            DBG("No authorizer %d password provided; aborting", i);
            free(authorizer);
            return PAM_AUTH_ERR;
        }

        retval = authenticate(pamh, authorizer, password);
        memset(password, 0, strlen(password));
        free(password);
        password = NULL;
        if (retval != PAM_SUCCESS)
        {
            /* username may have been a password; don't log it */
            LOG("Authentication of authorizer for account '%s' failed;"
                    " rc=%d", account, retval);
            goto next;
        }

        retval = check_expiry(pamh, authorizer);
        if (retval == PAM_NEW_AUTHTOK_REQD)
        {
            /* If this error is returned, I believe login will attempt to force
             * the user to change their password.  The problem is that it will
             * try to change root's password, not this user's.  So we're going
             * to roll this into a PAM_CRED_EXPIRED error, so they know they
             * need to log in as themselves and change it */
            LOG("authorizer '%s' needs to change their password; rejecting",
                    authorizer);
            free(authorizer);
            return PAM_CRED_EXPIRED;
        }

        /* PAM_AUTHTOK_ERR happens when the password has been changed too
         * recently.  For our purposes of authenticating an authorizer, this is
         * error code would not be a failure */
        if (retval != PAM_SUCCESS && retval != PAM_AUTHTOK_ERR)
        {
            LOG("authorizer '%s' for account '%s' has expired; %d",
                    authorizer, account, retval);
            free(authorizer);
            return retval;
        }

        /* check to see if the user is in the authorizers list */
        authorized = 0;
        for (j = 0; j < mpa_cfg->authorizers; j++)
        {
            if (strcmp(authorizer, mpa_cfg->authorizer[j]) == 0)
            {
                /* authenticated user is a valid authorizer for this account */

                if (!authorized)
                {
                    LOG("authorizer '%s' (%d of %d), accepted for account '%s'",
                            authorizer, i, mpa_cfg->required, account);
                    authorized = 1;
                    count++;
                }

                /* prevent re-use of an authorizer by clearing it */
                mpa_cfg->authorizer[j][0] = 0;

                /* and we continue in case this user is listed multiple times
                 * in the authorizers list */
            }
        }

        if (!authorized)
        {
            /* authorizer not found in mpa cfg for the account.  Note it
             * internally, and log the attempt, but do not short-circuit
             * authentication */
            LOG("authenticated user '%s' is not a valid authorizer"
                    " for account '%s'", authorizer, account);
        }

next:
        free(authorizer);
        authorizer = NULL;
    }

    if (count < mpa_cfg->required)
    {
        LOG("insufficient authorizers for account '%s'; required %d, got %d",
                account, mpa_cfg->required, count);
        retval = PAM_AUTH_ERR;
    }
    else
    {
        LOG("Access to account '%s' authorized by %d users", account, count);
        retval = PAM_SUCCESS;
    }

    if (mpa_cfg != NULL)
    {
        free(mpa_cfg);
    }

    return retval;
}
