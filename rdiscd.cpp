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
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <arpa/inet.h>

static volatile sig_atomic_t		is_running = 1;

namespace {
	typedef crypto::Hmac<crypto::Sha256> Stable_privacy_hmac;

	enum Interface_id_type {
		INTERFACE_ID_FIXED,		// fixed interface ID
		INTERFACE_ID_STABLE_PRIVACY	// derive interface ID as per RFC 7217
	};

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
		std::clog << "Options to enable privilege separation:" << std::endl;
		std::clog << " -u USER_NAME" << std::endl;
		std::clog << " -g GROUP_NAME" << std::endl;
		std::clog << " -r CHROOT_DIRECTORY" << std::endl;
	}

	void graceful_termination_handler (int signum)
	{
		is_running = 0;
	}

	void init_signals ()
	{
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


	// Generate a "stable privacy" interface ID as per RFC 7217 (http://tools.ietf.org/html/rfc7217).
	// Note: we don't follow the algorithm exactly (e.g. we omit the DAD counter, we take bits
	// from the PRF output in a different order), but since the draft standard lets implementations
	// choose their own PRFs anyways, it doesn't matter for standards compliance what the inputs to
	// the PRF are, or how we use the output.
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

	template<class T> void write_object (int fd, const T& obj)
	{
		const unsigned char*	p = reinterpret_cast<const unsigned char*>(&obj);
		size_t			len = sizeof(obj);
		while (len > 0) {
			ssize_t		bytes_written = write(fd, p, len);
			if (bytes_written < 0) {
				throw Rdisc::system_error(interface_name, "write", errno); // TODO: use a better exception
			}
			len -= bytes_written;
			p += bytes_written;
		}
	}
	template<class T> bool read_object (int fd, T& obj)
	{
		unsigned char*		p = reinterpret_cast<unsigned char*>(&obj);
		size_t			len = sizeof(obj);
		while (len > 0) {
			ssize_t		bytes_read = read(fd, p, len);
			if (bytes_read == 0) {
				return false;
			}
			if (bytes_read < 0) {
				throw Rdisc::system_error(interface_name, "read", errno); // TODO: use a better exception
			}
			len -= bytes_read;
			p += bytes_read;
		}
		return true;
	}

	// receive rdisc events and proxy them via a file descriptor to another process (for privilege separation purposes)
	class Rdisc_consumer_proxy : public Rdisc::Consumer {
		int		fd;

	public:
		explicit Rdisc_consumer_proxy (int arg_fd) : fd(arg_fd) { }

		virtual void	dhcp_level_changed (Rdisc::Dhcp_level dhcp_level)
		{
			write_object<uint8_t>(fd, 0);
			write_object(fd, dhcp_level);
		}
		virtual void	mtu_changed (int mtu)
		{
			write_object<uint8_t>(fd, 1);
			write_object(fd, mtu);
		}
		virtual void	gateway_changed (const Rdisc::Gateway& gateway)
		{
			write_object<uint8_t>(fd, 2);
			write_object(fd, gateway);
		}
		virtual void	onlink_prefix_changed (const Rdisc::Onlink_prefix& prefix)
		{
			write_object<uint8_t>(fd, 3);
			write_object(fd, prefix);
		}
		virtual void	autoconf_prefix_changed (const Rdisc::Autoconf_prefix& prefix)
		{
			write_object<uint8_t>(fd, 4);
			write_object(fd, prefix);
		}
	};

	// receive rdisc events from a file descriptor and proxy them to an rdisc consumer (for privilege separation purposes)
	void run_proxy_receiver (int fd, Rdisc::Consumer& consumer, const char* pid_file)
	{
		uint8_t		command;
		while (read_object(fd, command)) {
			// TODO: use enum for commands
			if (command == 0) {
				Rdisc::Dhcp_level dhcp_level;
				read_object(fd, dhcp_level);
				consumer.dhcp_level_changed(dhcp_level);
			} else if (command == 1) {
				int mtu;
				read_object(fd, mtu);
				consumer.mtu_changed(mtu);
			} else if (command == 2) {
				Rdisc::Gateway gateway;
				read_object(fd, gateway);
				consumer.gateway_changed(gateway);
			} else if (command == 3) {
				Rdisc::Onlink_prefix prefix;
				read_object(fd, prefix);
				consumer.onlink_prefix_changed(prefix);
			} else if (command == 4) {
				Rdisc::Autoconf_prefix prefix;
				read_object(fd, prefix);
				consumer.autoconf_prefix_changed(prefix);
			} else if (command == 255) {
				// TODO: Think of a nicer way to handle PID removal?
				// This is a pretty ugly violation of encapsulation.
				if (pid_file) {
					unlink(pid_file);
					pid_file = NULL;
				}
			} else {
				throw Rdisc::system_error(interface_name, "run_proxy_receiver", EPROTO); // TODO: use a better exception
			}
		}
	}

	bool drop_privileges (const char* user_name, const char* group_name, const char* chroot_directory)
	{
		// Resolve user and group names
		errno = 0;
		struct passwd*		usr = getpwnam(user_name);
		if (!usr) {
			if (errno) {
				std::perror("getpwnam");
			} else {
				std::clog << user_name << ": No such user" << std::endl;
			}
			return false;
		}
		struct group*		grp = NULL;
		if (group_name) {
			errno = 0;
			grp = getgrnam(group_name);
			if (!grp) {
				if (errno) {
					std::perror("getgrnam");
				} else {
					std::clog << group_name << ": No such group" << std::endl;
				}
				return false;
			}
		}

		// chroot (while we're still root)
		if (chroot_directory) {
			if (chroot(chroot_directory) == -1) {
				std::perror(chroot_directory);
				return false;
			}
			if (chdir("/") == -1) {
				std::perror("chdir(/)");
				return false;
			}
		}

		// Change GID and UID
		// If no group is specified, use primary GID of user
		if (setgid(grp ? grp->gr_gid : usr->pw_gid) == -1) {
			std::perror("setgid");
			return false;
		}
		if (initgroups(usr->pw_name, usr->pw_gid) == -1) {
			std::perror("initgroups");
			return false;
		}
		if (setuid(usr->pw_uid) == -1) {
			std::perror("setuid");
			return false;
		}
		return true;
	}
}

int main (int argc, char** argv)
{
	bool		want_daemonize = true;
	const char*	pid_file = NULL;
	const char*	interface_id_string = "macaddr";
	const char*	macaddr_string = NULL;
	const char*	stable_privacy_net_iface_type = "macaddr";
	const char*	stable_privacy_key_file = NULL;
	const char*	user_name = NULL;
	const char*	group_name = NULL;
	const char*	chroot_directory = NULL;

	int		flag;
	while ((flag = getopt(argc, argv, "l:fi:I:k:m:p:u:g:r:")) != -1) {
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
		case 'u':
			user_name = optarg;
			break;
		case 'g':
			group_name = optarg;
			break;
		case 'r':
			chroot_directory = optarg;
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
	if (!user_name && (group_name || chroot_directory)) {
		std::clog << argv[0] << ": -g (group name) and -r (chroot directory) cannot be specified unless -u (user name) is also specified" << std::endl;
		return 2;
	}

	interface_name = argv[optind];
	if (*interface_name == '\0') {
		std::clog << argv[0] << ": Interface name can't be empty" << std::endl;
		return 1;
	}
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

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_DFL);

	int				init_pipe[2];
	if (want_daemonize) {
		// Create a pipe that the daemon can use to tell its parent when it has successfully initialized.
		if (pipe(init_pipe) == -1) {
			std::perror("pipe");
			return 1;
		}
		pid_t		child_pid = fork();
		if (child_pid == -1) {
			std::perror("fork");
			return 1;
		}
		if (child_pid != 0) {
			// Parent process: don't exit until daemon has successfully initialized.
			close(init_pipe[1]);
			char	success = 0;
			if (read(init_pipe[0], &success, 1) == -1) {
				std::perror("read");
				_exit(1);
			}
			if (success) {
				// Daemon has successfully initialized, so we can exit.
				_exit(0);
			}
			// Daemon failed to successfully initialize.  Wait for our child and then exit with same exit code.
			int	status;
			if (waitpid(child_pid, &status, 0) == -1) {
				std::perror("waitpid");
				_exit(1);
			}
			if (!WIFEXITED(status)) {
				std::clog << argv[0] << ": Process terminated uncleanly while initializing" << std::endl;
				_exit(1);
			}
			_exit(WEXITSTATUS(status));
		}
		close(init_pipe[0]);
		setsid();
	}

	std::auto_ptr<Rdisc::Consumer>	consumer;
	int				proxy_pipe[2];
	pid_t				proxy_receiver_pid = -1;
	if (user_name) { // Privilege separation enabled
		// Create a pipe for communicating between the unprivileged and privileged processes.
		if (pipe(proxy_pipe) == -1) {
			std::perror("pipe");
			return 1;
		}
		consumer.reset(new Rdisc_consumer_proxy(proxy_pipe[1]));

		// Fork our privileged child process.  Do this before initializing rdisc
		// so it doesn't inherit any file descriptors or rdisc state.
		proxy_receiver_pid = fork();
		if (proxy_receiver_pid == -1) {
			std::perror("fork");
			return 1;
		}
		if (proxy_receiver_pid == 0) {
			// Privileged child process
			if (want_daemonize) {
				close(init_pipe[1]);
				close_standard_streams();
			}
			set_cloexec(proxy_pipe[0]);
			close(proxy_pipe[1]);
			// We should be terminated via our parent process, not directly:
			signal(SIGINT, SIG_IGN);
			signal(SIGTERM, SIG_IGN);
			try {
				Rdisc_consumer		consumer;
				run_proxy_receiver(proxy_pipe[0], consumer, pid_file);
			} catch (const Rdisc::system_error& e) {
				std::clog << "rdiscd[" << e.ifname << "]: " << e.where << ": " << strerror(e.error) << std::endl;
				_exit(1);
			} catch (...) {
				std::terminate();
			}
			close(proxy_pipe[0]);
			_exit(0);
		}
		close(proxy_pipe[0]);
	} else {
		consumer.reset(new Rdisc_consumer);
	}

	int			exit_status = 0;
	bool			written_pid_file = false;

	try {
		Rdisc		rdisc(interface_index, interface_name, consumer.get());

		if (pid_file) {
			// Write the PID file:
			std::ofstream	pid_out(pid_file);
			if (!pid_out) {
				std::clog << argv[0] << ": " << pid_file << ": Unable to open PID file for writing" << std::endl;
				return 1;
			}
			pid_out << getpid() << '\n';
			written_pid_file = true;
		}

		if (user_name) {
			// TODO: use an exception to bail out here
			if (!drop_privileges(user_name, group_name, chroot_directory)) {
				if (written_pid_file) {
					unlink(pid_file);
				}
				return 1;
			}
		}

		if (want_daemonize) {
			// We've successfully initialized, so tell our parent it can stop waiting for us.
			char	success = 1;
			if (write(init_pipe[1], &success, 1) == -1) {
				std::perror("write");
			}
			close(init_pipe[1]);

			close_standard_streams();
		}

		init_signals();

		rdisc.run(&is_running);

	} catch (const Rdisc::libndp_error& e) {
		std::clog << "rdiscd[" << e.ifname << "]: " << e.where << ": libndp error " << e.error << std::endl;
		exit_status = 1;
	} catch (const Rdisc::system_error& e) {
		std::clog << "rdiscd[" << e.ifname << "]: " << e.where << ": " << strerror(e.error) << std::endl;
		exit_status = 1;
	}

	if (written_pid_file) {
		if (user_name) {
			// Tell our privileged child to unlink the PID file (since we probably don't have permission):
			write_object<uint8_t>(proxy_pipe[1], 255);
		} else {
			unlink(pid_file);
		}
	}

	if (user_name) {
		// Wait for our privileged child process to exit:
		close(proxy_pipe[1]);
		waitpid(proxy_receiver_pid, NULL, 0);
	}

	return exit_status;
}
