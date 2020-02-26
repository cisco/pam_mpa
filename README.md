# PAM Multi-Party Authentication Module

The PAM Multi-Party Authentication Module (pam-mpa) can be used to require
multiple local users to authenticate to authorize access to a single account.

For example, in an environment where root access must be authorized by two
people, pam-mpa can be configured to require two users (Alice & Bob) to
authenticate to authorize root to log in.
```
$ ssh root@mpa-system.lan
authorizer [1 of 2]: alice
  password [1 of 2]:
authorizer [2 of 2]: bob
  password [2 of 2]:
Last login: Fri Jan 1 00:00:00 1970 from other-host
```

## License
pam-mpa is licensed under the MIT license.  See the LICENSE file for details.

## Limitations
* pam-mpa can only authorize using local users
  * authorizer accounts must exist in /etc/passwd & /etc/shadow

# Installation & Configuration

## Installation
For now, pam-mpa must be built from sources, and manually instatlled.

### Build Requirements
The following packages are required to build pam-mpa on rhel-7:
* gcc
* make
* pam-devel

### Build instruction
```sh
cd src/
make
```

### Installing the pam-mpa module
To install the pam-mpa copy `pam_mpa.so` from the src/ directory into the pam
module directory.

```sh
# on RHEL-7
sudo install -o root -g root -m 755 pam_mpa.so /lib64/security/pam_mpa.so
```

## Configuration

### Module Configuration Options
The following options are supported for the pam-mpa module:

* `usersfile=<path>` Users file to use for authorization
    * See Users File Format below
* `debug` Enable debugging output to syslog

### Users File Format

The users file specifies the authorizers, and how many authorizers are
required to log in as a given user.  Each `login` may only be listed once.

```txt
<login>:<required>:<authorizer_0>,<authorizer_1>[,...,<authorizer_n>]
```
* `login` is the account that requires multiple authorizers
* `required` is the number of authorizers required to authenticate
* `authorizer_*` is a list of possible authorizers

**NOTE** Authorizors must have valid local accounts, with passwords in
`/etc/shadow`.

### Example configuration for RHEL-7
The following section describe a full configuration for pam-mpa on a RHEL-7
system.  The directions should be the same for Centos-7.

#### Update pam configuration to use pam_mpa for authentication.

Update `auth` blocks in `/etc/pam.d/password-auth` and `/etc/pam.d/system-auth`
to try `pam_mpa.so` before `pam_unix.so`.

```txt
auth        required      pam_env.so
auth        required      pam_faildelay.so delay=2000000
auth        [success=done ignore=ignore default=die] pam_mpa.so usersfile=/etc/pam_mpa.usersfile debug
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so
```

#### Edit the pam_mpa users file
Add to the `usersfile` specified in the pam configuration any users that should
require multiple authorizers.  Format of the usersfile is:

#### Example usersfile

```
# /etc/pam_mpa.usersfile
root:2:alice,bob,charlie
```

# Contributing to pam-mpa
Contributions are welcome in the form of a pull-request.

Before sumitting changes, ensure all of the existing tests pass, and add
additional tests for new functionality.

## Testing
**WARNING**: The tests should **ONLY** be run on a non-production system, on a
private network, that is not already configured to use pam-mpa.  The tests
temporarily add users to /etc/passwd & /etc/shadow, and will modify the local pam
configuration.

**Do not run the tests on a production system.**

### Requirements
To run the tests, you need:
* root access on a non-production system
   * system must not be configured for pam-mpa
* the `pamtester` utility installed

### Running tests
To run the tests:
```sh
cd tests/
./test-pam_mpa.sh
```
