#!/bin/sh
require_clean_work_tree () {
	git rev-parse --verify HEAD >/dev/null || exit 1
	git update-index -q --refresh
	err=0

	if ! git diff-files --quiet
	then
		echo >&2 "Cannot $1: You have unstaged changes."
		err=1
	fi

	if ! git diff-index --cached --quiet HEAD --
	then
		if [ $err = 0 ]
		then
		    echo >&2 "Cannot $1: Your index contains uncommitted changes."
		else
		    echo >&2 "Additionally, your index contains uncommitted changes."
		fi
		err=1
	fi

	if [ $err = 1 ]
	then
		test -n "$2" && echo >&2 "$2"
		exit 1
	fi
}

if [ "$1" = "ci" ]; then
    require_clean_work_tree rebuild-binaries "Please commit or stash them"
fi


GOARCH=386 go build && mv thinssh bin/thinssh.i686
GOARCH=amd64 go build && mv thinssh bin/thinssh.x86_64

if [ "$1" = "ci" ]; then
    AUTHOR="Marvin the Paranoid Android <marvin@example.com>" 
    MSG="Rebuilded on $(git rev-parse HEAD)"
    git add bin/
    git ci --author "$AUTHOR" -s -m "$MSG"
fi
