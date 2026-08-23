#!/bin/sh
# Render the small, detached-signature update manifest consumed by
# packaging/update.sh. Values are arguments rather than discovered here so
# the release job has one explicit record of the exact artifacts it signed.
set -eu

[ $# -eq 8 ] || [ $# -eq 12 ] || {
	echo "usage: $0 CHANNEL VERSION BUILD_ID TARGET ARCHIVE_URL ARCHIVE_SHA256 APP_URL APP_SHA256 [LINUX_X86_URL LINUX_X86_SHA LINUX_ARM_URL LINUX_ARM_SHA]" >&2
	exit 2
}

channel=$1 version=$2 build=$3 target=$4 archive_url=$5 archive_sha=$6 app_url=$7 app_sha=$8
linux_x86_url="" linux_x86_sha="" linux_arm_url="" linux_arm_sha=""
if [ $# -eq 12 ]; then
	linux_x86_url=$9 linux_x86_sha=${10} linux_arm_url=${11} linux_arm_sha=${12}
fi
case "$channel" in stable | beta | nightly) ;; *) echo "bad channel: $channel" >&2; exit 2 ;; esac
case "${version#v}" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "bad version: $version" >&2; exit 2 ;; esac
case "$archive_sha$app_sha$linux_x86_sha$linux_arm_sha" in *[!0-9a-f]*) echo "digests must be lowercase hex" >&2; exit 2 ;; esac
[ ${#archive_sha} -eq 64 ] || { echo "archive sha256 is not 64 hex characters" >&2; exit 2; }
if [ -n "$app_url" ]; then
	[ ${#app_sha} -eq 64 ] || { echo "app sha256 is not 64 hex characters" >&2; exit 2; }
fi
if [ -n "$linux_x86_url" ]; then
	[ ${#linux_x86_sha} -eq 64 ] || { echo "linux-x86_64 sha256 is not 64 hex characters" >&2; exit 2; }
	[ ${#linux_arm_sha} -eq 64 ] || { echo "linux-arm64 sha256 is not 64 hex characters" >&2; exit 2; }
fi

# One line is deliberate: the installed POSIX-sh reader extracts uniquely
# named scalar fields without needing jq or Python on the host. Extra Linux
# archive fields are optional; Darwin readers ignore unknown keys.
if [ -n "$linux_x86_url" ]; then
	printf '{"schema":"1","channel":"%s","version":"%s","build_id":"%s","target":"%s","minimum_updater_version":"0.0.1","archive_url":"%s","archive_sha256":"%s","app_url":"%s","app_sha256":"%s","linux_x86_64_archive_url":"%s","linux_x86_64_archive_sha256":"%s","linux_arm64_archive_url":"%s","linux_arm64_archive_sha256":"%s"}\n' \
		"$channel" "$version" "$build" "$target" "$archive_url" "$archive_sha" "$app_url" "$app_sha" \
		"$linux_x86_url" "$linux_x86_sha" "$linux_arm_url" "$linux_arm_sha"
else
	printf '{"schema":"1","channel":"%s","version":"%s","build_id":"%s","target":"%s","minimum_updater_version":"0.0.1","archive_url":"%s","archive_sha256":"%s","app_url":"%s","app_sha256":"%s"}\n' \
		"$channel" "$version" "$build" "$target" "$archive_url" "$archive_sha" "$app_url" "$app_sha"
fi
