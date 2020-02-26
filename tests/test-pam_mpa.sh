#!/bin/bash -ue

BASEDIR=$(cd "$(dirname $(readlink -f "${BASH_SOURCE[0]}"))/.." && pwd)
TESTDIR="${BASEDIR}/tests"
SAFETY_FILE="${TESTDIR}/.tests_permitted"
MODULE_FILENAME="pam_mpa.so"
MODULE_SRC="${BASEDIR}/src/${MODULE_FILENAME}"
MODULE_LIVE="/lib64/security/${MODULE_FILENAME}"
USERSLIST="/etc/pam_mpa.userslist"

YESTERDAY=$(($(date +%s)/(60*60*24) - 1))
TODAY=$(($(date +%s)/(60*60*24)))

# Test account info
TPA_ACCOUNT="test-pam_mpa-acct"
AUTH1="test-pam_mpa-auth1"
AUTH1_PW="BLNorVmzE5RwTe0IzPuoa"
AUTH1_PW_HASH='$6$t1gSXMo$v/gg01Zj7n96vYqMygQv0da7fafUqaWROy8WoK8TBHv1Wd15nKsm.2B1atc1oSbbbZcRmOsHpDib3jig.YqX.1'
AUTH2="test-pam_mpa-auth2"
AUTH2_PW="S44jR9mD0sgjqee58PcVN"
AUTH2_PW_HASH='$6$9M9QZGz$litiYWOQ2m/G8BwWSUwQFLCrlhkCoPXNPGlIt12Rt9QrzWYJbs.4KUERysbGieHTFI30omU5NGXS6Q1haNx3S/'
NOAUTH="test-pam_mpa-noauth"
NOAUTH_PW="GiPBgsJRgQKw1iAV4h1VYefg"
NOAUTH_PW_HASH='$6$PXKclBW+eNc=$waYkxaGZ2.W8eV58Jo9zRYmJ4YNKJpun2VwoJWIhijXVQKxwlJBXwpzp/n9aXRvFrNigQQg8j.7DzTYqYo1Xt1'

# simplify useradd with some defaults
USERADD="/usr/sbin/useradd -c test-pam_mpa --no-create-home --home /tmp"
USERDEL="/usr/sbin/userdel -f -r"

# setup:
#   * test-pam_mpa service with nothing else
#   * locked TPA account, tpa_acct
#   * TPA Authorizer for tpa_acct: tpa_auth1
#   * TPA Authorizer for tpa_acct: tpa_auth2
#   * Expired TPA Authorizer for tpa_acct: tpa_auth_expired
#   * Account not in MPA list
function setup() {
  # create our accounts
  $USERADD $TPA_ACCOUNT
  $USERADD -p $AUTH1_PW_HASH $AUTH1
  $USERADD -p $AUTH2_PW_HASH $AUTH2
  $USERADD -p $NOAUTH_PW_HASH $NOAUTH

  # install the pam module
  install -o root -g root -m 755 $MODULE_SRC $MODULE_LIVE

  # install the required pam configurations
  install -o root -g root -m 644 $TESTDIR/test-pam_mpa.pamd \
      /etc/pam.d/test-pam_mpa
}

function cleanup() {
  set +ue   # disable these abort conditions, best effort
  $USERDEL $TPA_ACCOUNT 2>/dev/null
  $USERDEL $AUTH1 2>/dev/null
  $USERDEL $AUTH2 2>/dev/null
  $USERDEL $NOAUTH 2>/dev/null

  rm -f $MODULE_LIVE /etc/pam.d/test-pam_mpa $USERSLIST
}

function auth() {
  local service="$1"
  local account="$2"
  local input="$3"

  echo -e "$input" |
      pamtester -v $service $account authenticate 2>&1
}

function run_test() {
  local desc="$1"
  shift
  local user input
  local service="test-pam_mpa" result="pamtester: successfully authenticated"

  for arg in "$@"; do
    case "$arg" in
      userslist=*)
        echo "${arg/userslist=}" > $USERSLIST
        shift
        ;;
      user=*|input=*|service=*|result=*)
        eval "$arg"
        shift
        ;;
      *)
        echo "Error: unsupported argument to run_test(): '$arg'"
        return 1;
    esac
  done

  echo -en "\e[33m${desc}\e[0m: "
  local buf=$(auth ${service} ${user} ${input})

  if [[ -z ${buf##*${result}*} ]]; then
    echo -e "\e[32mpassed\e[0m"
  else
    echo -e "\e[31mFAILED\e[0m"
    echo -e "  \e[37;1mcommand:\e[0m auth ${service} ${user}"
    echo -e "  \e[37;1minput:\e[0m\n${input}"
    echo -e "  \e[37;1moutput:\e[0m\n${buf}"
    echo ""
  fi
}

# Must be run as root
if [[ $(id -u) -ne 0 ]]; then
  echo "This script must be run as root!"
  exit 1
fi

# Make sure the runner of this script is ok with us stomping the heck out of
# pam, the shadow file, etc...
if [[ ! -f $SAFETY_FILE || $(cat $SAFETY_FILE) != $(hostname -f) ]]; then
  cat <<EOF

          *** WARNING   WARNING   WARNING   WARNING   WARNING ***

This script should **ONLY** be run on a non-production system, on a private
network, that is not already configured to use PAM-MPA.

If this is not the case, hit CTRL-C now.

  *** THIS SCRIPT (temporarily) ADDS USERS TO /etc/passwd & /etc/shadow ***
  ***     THIS SCRIPT (temporarily) MODIFIES YOUR PAM CONFIGURATION     ***

The script will make a best effort attempt to clean up everything it adds,
but there are NO GUARANTEES that the code works correctly.

          *** WARNING   WARNING   WARNING   WARNING   WARNING ***

(You can hit F below to silence this warning forever in this directory on this
host.)
EOF

  while true; do
    echo -n "Continue ([N]/Y/F)? "
    read answer

    case "$answer" in
    y|Y)
      echo "Continuing"
      break
      ;;
    f|F)
      echo "Continuing, and disabling this warning for future runs"
      echo "  To re-enable this warning, remove $SAFETY_FILE"
      hostname -f > $SAFETY_FILE
      break
      ;;
    ""|n|N)
      echo "Aborting"
      exit
      ;;
    *)
      echo "Unknown response, $answer"
      ;;
    esac
  done
fi

# double check they're not hurting themselves
if [[ -f $MODULE_LIVE ]]; then
  cat <<END
ERROR!!! The module to be tested already exists on the system!  Refusing to
continue.

If you're CERTAIN that this system is not configured to use pam_mpa, you can
remove $MODULE_LIVE to get past this error.
END

  exit 1
fi

# setup the system for testing, and ensure we clean it up during exit
trap 'cleanup' EXIT
setup

run_test "authentication requires two authenticated authorizers" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2,fake-user" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: successfully authenticated'"

run_test "authentication fails if first user has bad password" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\nBAD_PASSWORD\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: Authentication failure'"

run_test "authentication fails if second user has bad password" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\n$AUTH2\nBAD_PASSWORD\n\"" \
    "result='pamtester: Authentication failure'"

run_test "authentication fails if first user is invalid" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"BAD_USER\nBAD_PASSWORD\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: Authentication failure'"

run_test "authentication fails if second user is invalid" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\nBAD_USER\nBAD_PASSWORD\n\"" \
    "result='pamtester: Authentication failure'"

run_test "authentication fails if first user is not a valid authorizer" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$NOAUTH\n$NOAUTH_PW\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: Authentication failure'"

run_test "authentication fails if second user is not a valid authorizer" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\n$NOAUTH\n$NOAUTH_PW\n\"" \
    "result='pamtester: Authentication failure'"

chage --lastday 0 --maxdays 10 --inactive 10 $AUTH1
run_test "authentication fails if first user password has expired" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: User credentials expired'"
chage --lastday $TODAY --maxdays 99999 --inactive -1 $AUTH1

chage --lastday 0 --maxdays 10 --inactive 10 $AUTH2
run_test "authentication fails if second user password has expired" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: User credentials expired'"
chage --lastday $TODAY --maxdays 99999 --inactive -1 $AUTH2

chage --lastday $TODAY --mindays 7 $AUTH1
run_test 'authentication does not fail if authorizer just change password' \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: successfully authenticated'"
chage --lastday $TODAY --mindays -1 $AUTH1

chage -E $YESTERDAY $AUTH1
run_test "authentication fails if first user account has expired" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: User account has expired'"
chage -E -1 $AUTH1

chage -E $YESTERDAY $AUTH2
run_test "authentication fails if second user account has expired" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: User account has expired'"
chage -E -1 $AUTH2

usermod --lock $AUTH1
run_test "authentication fails if first user account is locked" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: Authentication failure'"
usermod --unlock $AUTH1

usermod --lock $AUTH2
run_test "authentication fails if second user account is locked" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input=\"$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n\"" \
    "result='pamtester: Authentication failure'"
usermod --unlock $AUTH2

run_test "authentication fails if both authorizers are the same user" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input='$AUTH1\n$AUTH1_PW\n$AUTH1\n$AUTH1_PW\n'" \
    "result='pamtester: Authentication failure'"

run_test "authentication fails if both authorizers are the same user and that \
user is listed twice in the userslist" \
    "userslist=$TPA_ACCOUNT:2:$AUTH1,$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input='$AUTH1\n$AUTH1_PW\n$AUTH1\n$AUTH1_PW\n'" \
    "result='pamtester: Authentication failure'"

run_test "will not attempt to authenticate unless account is in userslist" \
    "userslist=''" \
    "user=$TPA_ACCOUNT" \
    "input='$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n'" \
    "result='pamtester: Permission denied'"

run_test "authentication fails if required authorizers is zero" \
    "userslist=$TPA_ACCOUNT:0:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input='$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n'" \
    "result='pamtester: Authentication failure'"

run_test "authentication fails if required authorizers is negative" \
    "userslist=$TPA_ACCOUNT:-1:$AUTH1,$AUTH2" \
    "user=$TPA_ACCOUNT" \
    "input='$AUTH1\n$AUTH1_PW\n$AUTH2\n$AUTH2_PW\n'" \
    "result='pamtester: Authentication failure'"
