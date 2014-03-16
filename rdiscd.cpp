/*
 * Copyright 2014 Andrew Ayer
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "rdisc.hpp"
#include "hmac.hpp"
#include "sha2.hpp"
#include "util.hpp"
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <arpa/inet.h>

namespace {
	typedef crypto::Hmac<crypto::Sha256> Stable_privacy_hmac;

	enum Interface_id_type {
		INTERFACE_ID_FIXED,		// fixed interface ID
		INTERFACE_ID_STABLE_PRIVACY	// derive interface ID as per draft-ietf-6man-stable-privacy-addresses-17
	};

	sig_atomic_t			is_running = 1;
	//pid_t				child_pid = -1;
	const char*			interface_name;
	int				interface_index = -1;
	Interface_id_type		interface_id_type;
	// Next 2 lines: only if interface_id_type==INTERFACE_ID_FIXED
	struct in6_addr			interface_id;
	unsigned int			interface_id_len;	// in bits
	// Next 2 lines: only if interface_id_type==INTERFACE_ID_STABLE_PRIVACY
	unsigned char			stable_privacy_key[Stable_privacy_hmac::KEY_LENGTH];
	std::vector<unsigned char>	stable_privacy_net_iface;


	void print_usage (const char* arg0)
	{
		std::clog << "Usage: " << arg0 << " [OPTIONS] INTERFACE" << std::endl;
		std::clog << "Options:" << std::endl;
		std::clog << " -f                     (don't daemonize)" << std::endl;
		std::clog << " -p PIDFILE" << std::endl;
		std::clog << " -i INTERFACE_ID        (an address suffix, or 'macaddr' or 'stable-privacy')" << std::endl;
		std::clog << " -l INTERFACE_ID_LEN    (number of bits in the interface ID)" << std::endl;
		std::clog << " -m MACADDRESS" << std::endl;
		std::clog << "Options specific to '-i stable-privacy' mode:" << std::endl;
		std::clog << " -I index|name|macaddr  (choice of stable-privacy interface parameter)" << std::endl;
		std::clog << " -k KEYFILE" << std::endl;
	}

	void graceful_termination_handler (int signum)
	{
		is_running = 0;
	}

	void init_signals ()
	{
		signal(SIGPIPE, SIG_IGN);
		signal(SIGCHLD, SIG_DFL);

		// SIGTERM, SIGINT
		struct sigaction	siginfo;
		sigemptyset(&siginfo.sa_mask);
		sigaddset(&siginfo.sa_mask, SIGTERM);
		sigaddset(&siginfo.sa_mask, SIGINT);
		siginfo.sa_flags = 0;
		siginfo.sa_handler = graceful_termination_handler;
		sigaction(SIGTERM, &siginfo, NULL);
		sigaction(SIGINT, &siginfo, NULL);
		sigprocmask(SIG_BLOCK, &siginfo.sa_mask, NULL);
	}


	// As per http://tools.ietf.org/html/draft-ietf-6man-stable-privacy-addresses-17#section-5
	// Note: we don't follow the algorithm exactly (e.g. we omit the DAD counter, we take bits
	// from the PRF output in a different order), but since the draft standard lets implementations
	// choose their own PRFs anyways, it doesn't really matter what the inputs to the PRF are, or
	// how we use the output.
	void	generate_stable_privacy_interface_id (struct in6_addr* out, unsigned int len, const in6_addr& prefix)
	{
		std::vector<unsigned char>	hmac_input(16 + stable_privacy_net_iface.size());
		std::copy(&prefix.s6_addr[0], &prefix.s6_addr[16], hmac_input.begin());
		std::copy(stable_privacy_net_iface.begin(), stable_privacy_net_iface.end(), hmac_input.begin() + 16);

		unsigned char	hmac_out[Stable_privacy_hmac::LENGTH];
		Stable_privacy_hmac::compute(hmac_out, sizeof(hmac_out),
					     stable_privacy_key, sizeof(stable_privacy_key),
					     &hmac_input[0], hmac_input.size());
		if (len > 128) {
			len = 128;
		}
		if (len > sizeof(hmac_out)*8) {
			// shouldn't happen because we use SHA256, which has a 256 bit long output
			len = sizeof(hmac_out)*8;
		}
		unsigned int	nbytes = len / 8;
		unsigned int	nbits = len % 8;

		std::memcpy(&out->s6_addr[16 - nbytes], hmac_out, nbytes);
		if (nbits) {
			out->s6_addr[16 - nbytes - 1] = (hmac_out[nbytes] & ((1 << nbits) - 1));
		}
	}


	class Rdisc_consumer : public Rdisc::Consumer {
	public:
		virtual void	dhcp_level_changed (Rdisc::Dhcp_level dhcp_level)
		{
		}
		virtual void	mtu_changed (int mtu)
		{
			// ip link set IFNAME mtu MTU
		}
		virtual void	gateway_changed (const Rdisc::Gateway& gateway)
		{
			// ip -6 route add|del default via GATEWAY dev IFNAME
			std::string	address_string(format_ipv6_address(gateway.address));
			const char*	args[] = { "ip", "-6", "route", gateway.is_valid() ? "add" : "del", "default", "via", address_string.c_str(), "dev", interface_name, NULL };
			systemv("/bin/ip", args);

		}
		virtual void	onlink_prefix_changed (const Rdisc::Onlink_prefix& prefix)
		{
			// ip -6 route add|del PREFIX/PREFIXLEN dev IFNAME
			std::string	address_string(format_ipv6_address(prefix.prefix, prefix.prefix_len));
			const char*	args[] = { "ip", "-6", "route", prefix.is_valid() ? "add" : "del", address_string.c_str(), "dev", interface_name, NULL };
			systemv("/bin/ip", args);
		}
		virtual void	autoconf_prefix_changed (const Rdisc::Autoconf_prefix& prefix)
		{
			struct in6_addr		address(prefix.prefix);
			if (interface_id_type == INTERFACE_ID_FIXED) {
				if (prefix.prefix_len + interface_id_len > 128) {
					std::clog << "Warning: cannot assign address because prefix length (" << prefix.prefix_len << ") + interface ID length (" << interface_id_len << ") exceeds 128 bits" << std::endl;
					return;
				}
				set_address_suffix(&address, interface_id, interface_id_len);
			} else if (interface_id_type == INTERFACE_ID_STABLE_PRIVACY) {
				unsigned int	stable_interface_id_len = 128 - prefix.prefix_len;
				struct in6_addr	stable_interface_id;
				generate_stable_privacy_interface_id(&stable_interface_id, stable_interface_id_len, prefix.prefix);
				set_address_suffix(&address, stable_interface_id, stable_interface_id_len);
			}

			if (prefix.is_valid()) {
				// ip -6 addr replace ADDRESS/128 preferred_lft forever|0 dev IFNAME
				std::string	address_string(format_ipv6_address(address, 128));
				const char*	args[] = { "ip", "-6", "addr", "replace", address_string.c_str(), "preferred_lft", prefix.is_preferred() ? "forever" : "0", "dev", interface_name, NULL };
				systemv("/bin/ip", args);
			} else {
				// ip -6 addr del ADDRESS/128 dev IFNAME
				std::string	address_string(format_ipv6_address(address, 128));
				const char*	args[] = { "ip", "-6", "addr", "del", address_string.c_str(), "dev", interface_name, NULL };
				systemv("/bin/ip", args);
			}
		}
	};

	/*
	// receive rdisc events and proxy them via IPC to another process (for privilege separation purposes)
	class Rdisc_consumer_proxy : public Rdisc::Consumer {
	public:
		virtual void	dhcp_level_changed (Rdisc::Dhcp_level dhcp_level)
		{
		}
		virtual void	mtu_changed (int mtu)
		{
		}
		virtual void	gateway_changed (const Rdisc::Gateway& gateway)
		{
		}
		virtual void	onlink_prefix_changed (const Rdisc::Onlink_prefix& prefix)
		{
		}
		virtual void	autoconf_prefix_changed (const Rdisc::Autoconf_prefix& prefix)
		{
		}
	};
	*/
}

int main (int argc, char** argv)
{
	bool		want_daemonize = true;
	const char*	pid_file = NULL;
	const char*	interface_id_string = "macaddr";
	const char*	macaddr_string = NULL;
	const char*	stable_privacy_net_iface_type = "macaddr";
	const char*	stable_privacy_key_file = NULL;

	int		flag;
	while ((flag = getopt(argc, argv, "l:fi:I:k:m:p:")) != -1) {
		switch (flag) {
		case 'f':
			want_daemonize = false;
			break;
		case 'i':
			interface_id_string = optarg;
			break;
		case 'I':
			stable_privacy_net_iface_type = optarg;
			break;
		case 'k':
			stable_privacy_key_file = optarg;
			break;
		case 'l':
			interface_id_len = std::atoi(optarg);
			if (interface_id_len < 1 || interface_id_len > 127) {
				std::clog << argv[0] << ": Interface ID bit length (-l) must be between 1 and 127, inclusive" << std::endl;
				return 1;
			}
			break;
		case 'm':
			macaddr_string = optarg;
			break;
		case 'p':
			pid_file = optarg;
			break;
		case ':':
		case '?':
			print_usage(argv[0]);
			return 2;
		}
	}

	if (argc - optind != 1) {
		std::clog << argv[0] << ": No interface specified" << std::endl;
		print_usage(argv[0]);
		return 2;
	}
	if (pid_file && !want_daemonize) {
		std::clog << argv[0] << ": -p (pid file) and -f (don't daemonize) are mutually exclusive" << std::endl;
		return 2;
	}

	interface_name = argv[optind];
	if ((interface_index = get_ifindex(interface_name)) == -1) {
		std::clog << argv[0] << ": " << interface_name << ": Unrecognized interface name" << std::endl;
		return 1;
	}

	/*
	 * Derive the interface ID
	 */
	if (std::strcmp(interface_id_string, "macaddr") == 0) {
		if (interface_id_len && interface_id_len != 64) {
			std::clog << argv[0] << ": Interface ID bit length (-l) must be 64 when using a MAC address interface ID (-i macaddr)" << std::endl;
			return 1;
		}

		unsigned char	macaddr[6];
		if (macaddr_string) {
			if (!parse_macaddr_string(macaddr, macaddr_string)) {
				std::clog << argv[0] << ": " << macaddr_string << ": Invalid MAC address" << std::endl;
				return 1;
			}
		} else {
			if (!get_if_macaddr(macaddr, interface_name)) {
				std::clog << argv[0] << ": " << interface_name << ": Interface does not have MAC address" << std::endl;
				return 1;
			}
		}
		interface_id_type = INTERFACE_ID_FIXED;
		fill_address_from_mac(&interface_id, macaddr);
		interface_id_len = 64;
	} else if (std::strcmp(interface_id_string, "stable-privacy") == 0) {
		interface_id_type = INTERFACE_ID_STABLE_PRIVACY;
		if (std::strcmp(stable_privacy_net_iface_type, "macaddr") == 0) {
			stable_privacy_net_iface.resize(6);
			if (macaddr_string) {
				if (!parse_macaddr_string(&stable_privacy_net_iface[0], macaddr_string)) {
					std::clog << argv[0] << ": " << macaddr_string << ": Invalid MAC address" << std::endl;
					return 1;
				}
			} else {
				if (!get_if_macaddr(&stable_privacy_net_iface[0], interface_name)) {
					std::clog << argv[0] << ": " << interface_name << ": Interface does not have MAC address" << std::endl;
					return 1;
				}
			}
		} else if (std::strcmp(stable_privacy_net_iface_type, "index") == 0) {
			uint32_t	index = htonl(interface_index);
			stable_privacy_net_iface.resize(sizeof(index));
			std::memcpy(&stable_privacy_net_iface[0], &index, sizeof(index));
		} else if (std::strcmp(stable_privacy_net_iface_type, "name") == 0) {
			stable_privacy_net_iface.resize(std::strlen(interface_name));
			std::memcpy(&stable_privacy_net_iface[0], interface_name, stable_privacy_net_iface.size());
		} else {
			std::clog << argv[0] << ": -I must be macaddr, index, or name" << std::endl;
			return 2;
		}

		std::ifstream	key_in;

		// Disable buffering so we don't waste system entropy by reading more than necessary, in case
		// key file is specified as a random device (e.g. /dev/urandom)
		key_in.rdbuf()->pubsetbuf(NULL, 0);

		if (stable_privacy_key_file) {
			key_in.open(stable_privacy_key_file, std::ios::binary);
			if (!key_in) {
				std::clog << argv[0] << ": " << stable_privacy_key_file << ": Unable to open key file" << std::endl;
				return 1;
			}
		} else {
			// Randomly generate key (by opening /dev/[u]random)
			key_in.open("/dev/urandom", std::ios::binary);
			if (!key_in) {
				key_in.open("/dev/random", std::ios::binary);
				if (!key_in) {
					std::clog << argv[0] << ": Unable to open random device to generate a stable privacy key; please specify a key file using the -k option" << std::endl;
					return 1;
				}
			}
		}

		key_in.read(reinterpret_cast<char*>(stable_privacy_key), sizeof(stable_privacy_key)); // cast from unsigned char* to char* is safe
		if (static_cast<size_t>(key_in.gcount()) != sizeof(stable_privacy_key)) {
			if (stable_privacy_key_file) {
				std::clog << argv[0] << ": " << stable_privacy_key_file << ": Key file too short (must be " << sizeof(stable_privacy_key) << " bytes long)" << std::endl;
			} else {
				std::clog << argv[0] << ": Insufficient number of bytes returned from random device" << std::endl;
			}
			return 1;
		}
	} else {
		interface_id_type = INTERFACE_ID_FIXED;
		if (inet_pton(AF_INET6, interface_id_string, &interface_id) != 1) {
			std::clog << argv[0] << ": " << interface_id_string << ": Invalid IPv6 address" << std::endl;
			return 1;
		}
		unsigned int	slen = count_suffix_length(interface_id);
		if (!interface_id_len) {
			interface_id_len = slen;
		} else if (slen > interface_id_len) {
			std::clog << argv[0] << ": " << interface_id_string << ": Longer than specified interface ID bit length (-l " << interface_id_len << ")" << std::endl;
			return 1;
		}
	}


	/* DEBUG
	char		addrstr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &interface_id, addrstr, sizeof(addrstr));
	std::clog << "Interface ID = " << addrstr << "; length = " << interface_id_len << std::endl;
	*/

	int			exit_status = 0;

	try {
		Rdisc_consumer	consumer;
		Rdisc		rdisc(interface_index, interface_name, &consumer);

		/*
		 * Daemonize, if applicable
		 */
		if (want_daemonize) {
			// Open the PID file (open before forking so we can report errors)
			std::ofstream	pid_out;
			if (pid_file) {
				pid_out.open(pid_file, std::ofstream::out | std::ofstream::trunc);
				if (!pid_out) {
					std::clog << argv[0] << ": " << pid_file << ": Unable to open PID file for writing" << std::endl;
					return 1;
				}
			}

			pid_t		pid = fork();
			if (pid == -1) {
				std::perror("fork");
				unlink(pid_file);
				return 1;
			}
			if (pid != 0) {
				// exit the parent process
				return 0;
			}
			setsid();

			// Write the PID file now that we've forked
			if (pid_out) {
				pid_out << getpid() << '\n';
				pid_out.close();
			}

			// dup stdin, stdout, stderr to /dev/null
			close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDONLY);
			open("/dev/null", O_WRONLY);
			open("/dev/null", O_WRONLY);
		}

		init_signals();

		rdisc.run(is_running);

	} catch (const Rdisc::libndp_error& e) {
		std::clog << "rdiscd[" << e.ifname << "]: " << e.where << ": libndp error " << e.error << std::endl;
		exit_status = 1;
	} catch (const Rdisc::system_error& e) {
		std::clog << "rdiscd[" << e.ifname << "]: " << e.where << ": " << strerror(e.error) << std::endl;
		exit_status = 1;
	}

	if (pid_file) {
		unlink(pid_file);
	}

	return exit_status;
}
