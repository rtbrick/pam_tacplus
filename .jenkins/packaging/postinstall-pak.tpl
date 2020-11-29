#!/bin/bash

set -ue;

# We always run a ldconfig , just in case the package installed any
# shared libraries.
ldconfig;

# Find out the codename of the Debian/Ubuntu distribution currently
# running on. This might have already been set.
_codename="${_codename:-$(/usr/bin/lsb_release -s -c || echo 'unknown')}";

# Enable and start package service if needed.
if [ "__{{ .ServiceName }}" != "__" ] && [ "__{{ .ServiceName }}" != "__ " ]; then
	>&2 echo "Running enable and start for package service '{{ .ServiceName }}' ...";
	case $_codename in
		bionic)
			_systemctl="$(which systemctl)"	\
				|| _systemctl="echo [systemctl not found]: would have run: systemctl";
	
			$_systemctl daemon-reload;
			$_systemctl enable "{{ .ServiceName }}";
			$_systemctl start "{{ .ServiceName }}";
			;;
		stretch)
			update-rc.d "{{ .ServiceName }}" defaults;
			service "{{ .ServiceName }}" start;
  			;;
		*)
			echo "Don't know how to correctly install service on distribution '$_codename'";
			exit 1;
  			;;
	esac
fi

# Add more commands after this line.

cp /usr/share/rtbrick/tacplus/etc/pam.d/* /etc/pam.d/;
cp /usr/share/rtbrick/tacplus/etc/security/group.conf /etc/security/group.conf;
[ ! -f "/etc/tacplus_servers" ] && cp /usr/local/etc/tacplus_servers /etc/tacplus_servers;

if [ ! -e /lib/x86_64-linux-gnu/security/pam_tacplus.so ]; then
        ln -s /usr/local/lib/security/pam_tacplus.so /lib/x86_64-linux-gnu/security/pam_tacplus.so;
fi
