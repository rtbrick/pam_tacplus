#!/bin/bash

set -ue;

# We always run a ldconfig , just in case the package installed any
# shared libraries.
ldconfig;

# Find out the codename of the Debian/Ubuntu distribution currently
# running on. This might have already been set.
_codename="${_codename:-$(/usr/bin/lsb_release -s -c || echo 'unknown')}";

# Find out how this script is being called. See man 5 deb-postinst.
# If action == "configure" and param1 is empty then this is the initial
# installation of a package, if param1 is not empty then it should contain
# old-version meaning it's an upgrade of an already installed package.
_deb_script_name="$0";
_deb_action="${1:-}";
_deb_param1="${2:-}";

# Enable and start package service if needed.
# shellcheck disable=SC2050
if [ "__{{ .ServiceName }}" != "__" ] && [ "__{{ .ServiceName }}" != "__ " ]; then
	srv_name="{{ .ServiceName }}";
	>&2 echo "Running enable and start for package service '$srv_name' ...";
	case $_codename in
		bionic|focal|jammy)
			_systemctl="$(which systemctl)"	\
				|| _systemctl="echo [systemctl not found]: would have run: systemctl";

			# Any of the systemctl commands might fail if the
			# package is installed inside a docker container where
			# systemd is not running.
			$_systemctl daemon-reload || true;
			$_systemctl enable "$srv_name" || true;
			$_systemctl start "$srv_name" || true;

			# Let's also try to create the required symlinks
			# manually, just in-case any of above commands failed
			# but we do need the service to start at system boot.
			target="/lib/systemd/system/${srv_name}.service";
			[ -f "$target" ] && {
				mkdir -p "/etc/systemd/system/multi-user.target.wants/";

				link="/etc/systemd/system/${srv_name}.service";
				[ -L "$link" ] || {
					ln -v -s "$target" "$link";
				}

				link="/etc/systemd/system/multi-user.target.wants/${srv_name}.service";
				[ -L "$link" ] || {
					ln -v -s "$target" "$link";
				}
			}
			;;
		# We use the Debian release code-names to detect when a package
		# is being installed in ONL. Newer Debian versions actually use
		# systemd just like Ubuntu but the ONL build even if it's based
		# on newer Debian versions still uses SysVinit . 
		stretch|buster|bullseye)
			update-rc.d "$srv_name" defaults;
			# Starting the service will probably fail if the package
			# is installed during an image build.
			service "$srv_name" start || true;
			;;
		*)
			echo "Don't know how to correctly install service on distribution '$_codename'";
			exit 1;
			;;
	esac
fi

# Ensure the script doesn't finish with a non-zero exit code in case the
# previous statement was false.
true;

# Add more commands after this line.

cp /usr/share/rtbrick/tacplus/etc/pam.d/* /etc/pam.d/;
cp /usr/share/rtbrick/tacplus/etc/security/group.conf /etc/security/group.conf;
[ ! -f "/etc/tacplus_servers" ] && cp /usr/local/etc/tacplus_servers /etc/tacplus_servers;

if [ ! -e /lib/x86_64-linux-gnu/security/pam_tacplus.so ]; then
        ln -s /usr/local/lib/security/pam_tacplus.so /lib/x86_64-linux-gnu/security/pam_tacplus.so;
fi

# Ensure the script doesn't finish with a non-zero exit code in case the
# previous statement was false.
true;
