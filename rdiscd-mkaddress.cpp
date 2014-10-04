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
#include "rfc7217.hpp"
#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>

namespace {
	void print_usage (const char* arg0)
	{
		std::clog << "Usage: " << arg0 << " [OPTIONS] PREFIX/LEN INTERFACE_ID" << std::endl;
		std::clog << "INTERFACE_ID is one of:" << std::endl;
		std::clog << "  * a literal address suffix" << std::endl;
		std::clog << "  * 'macaddr'" << std::endl;
		std::clog << "  * 'stable-privacy'" << std::endl;
		std::clog << "Options:" << std::endl;
		std::clog << " -l INTERFACE_ID_LEN    (number of bits in the literal interface ID)" << std::endl;
		std::clog << " -m MACADDRESS" << std::endl;
		std::clog << " -d DEVICE" << std::endl;
		std::clog << "Options specific to 'stable-privacy' interface IDs:" << std::endl;
		std::clog << " -I index|name|macaddr  (choice of stable-privacy interface parameter)" << std::endl;
		std::clog << " -k KEYFILE" << std::endl;
	}

	bool parse_prefix (struct in6_addr* address, unsigned int* prefix_len, const char* prefix_string)
	{
		const char*		slash = std::strchr(prefix_string, '/');
		if (!slash) {
			return false;
		}
		const std::string	address_part(prefix_string, slash);
		if (inet_pton(AF_INET6, address_part.c_str(), address) != 1) {
			return false;
		}
		const int		prefix_len_signed = std::atoi(slash + 1);
		if (prefix_len_signed < 0 || prefix_len_signed > 128) {
			return false;
		}
		*prefix_len = prefix_len_signed;
		return true;
	}
}

int main (int argc, char** argv)
{
	unsigned int	interface_id_len = 0;	// in bits		// -l
	const char*	macaddr_string = NULL;				// -m
	const char*	interface_name = NULL;				// -d
	const char*	stable_privacy_net_iface_type = "macaddr";	// -I
	const char*	stable_privacy_key_file = NULL;			// -k

	int		flag;
	while ((flag = getopt(argc, argv, "l:m:d:I:k:")) != -1) {
		switch (flag) {
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
		case 'd':
			interface_name = optarg;
			if (*interface_name == '\0') {
				std::clog << argv[0] << ": device name can't be empty" << std::endl;
				return 1;
			}
			break;
		case 'I':
			stable_privacy_net_iface_type = optarg;
			break;
		case 'k':
			stable_privacy_key_file = optarg;
			break;
		case ':':
		case '?':
			print_usage(argv[0]);
			return 2;
		}
	}

	if (argc - optind != 2) {
		print_usage(argv[0]);
		return 2;
	}

	int			interface_index = -1;
	if (interface_name && (interface_index = get_ifindex(interface_name)) == -1) {
		std::clog << argv[0] << ": " << interface_name << ": Unrecognized interface name" << std::endl;
		return 1;
	}

	/*
	 * Parse the prefix
	 */
	const char*		prefix_string = argv[optind];
	struct in6_addr		address;
	unsigned int		prefix_len;

	if (!parse_prefix(&address, &prefix_len, prefix_string)) {
		std::clog << argv[0] << ": " << prefix_string << ": Invalid prefix string (must be of form ADDRESS/LEN; e.g. 2001:db8:92e:b51f::/64)" << std::endl;
		return 1;
	}

	/*
	 * Derive the interface ID
	 */
	const char*		interface_id_string = argv[optind + 1];
	if (std::strcmp(interface_id_string, "macaddr") == 0) {
		if (interface_id_len && interface_id_len != 64) {
			std::clog << argv[0] << ": Interface ID bit length (-l) must be 64 when using a MAC address interface ID" << std::endl;
			return 1;
		}
		if (prefix_len != 64) {
			std::clog << argv[0] << ": Prefix bit length must be 64 when using a MAC address interface ID" << std::endl;
			return 1;
		}

		unsigned char	macaddr[6];
		if (macaddr_string) {
			// Get MAC address from command line option -m
			if (!parse_macaddr_string(macaddr, macaddr_string)) {
				std::clog << argv[0] << ": " << macaddr_string << ": Invalid MAC address" << std::endl;
				return 1;
			}
		} else if (interface_name) {
			// Get MAC address by looking at the interface (specified with -d option)
			if (!get_if_macaddr(macaddr, interface_name)) {
				std::clog << argv[0] << ": " << interface_name << ": Interface does not have MAC address" << std::endl;
				return 1;
			}
		} else {
			std::clog << argv[0] << ": need to specify either the MAC address (-m) or device (-d) option with 'macaddr' interface ID type" << std::endl;
			return 1;
		}

		fill_address_from_mac(&address, macaddr);

	} else if (std::strcmp(interface_id_string, "stable-privacy") == 0) {
		std::vector<unsigned char>	stable_privacy_net_iface;
		if (std::strcmp(stable_privacy_net_iface_type, "macaddr") == 0) {
			// Use MAC address for stable privacy network interface
			stable_privacy_net_iface.resize(6);
			if (macaddr_string) {
				// Get MAC address from command line option -m
				if (!parse_macaddr_string(&stable_privacy_net_iface[0], macaddr_string)) {
					std::clog << argv[0] << ": " << macaddr_string << ": Invalid MAC address" << std::endl;
					return 1;
				}
			} else if (interface_name) {
				// Get MAC address by looking at the interface (specified with -d option)
				if (!get_if_macaddr(&stable_privacy_net_iface[0], interface_name)) {
					std::clog << argv[0] << ": " << interface_name << ": Interface does not have MAC address" << std::endl;
					return 1;
				}
			} else {
				std::clog << argv[0] << ": need to specify either the MAC address (-m) or device (-d) option with '-I macaddr'" << std::endl;
				return 1;
			}
		} else if (std::strcmp(stable_privacy_net_iface_type, "index") == 0) {
			// Use the interface index for stable privacy network interface
			if (interface_index == -1) {
				std::clog << argv[0] << ": need to specify device (-d) option with '-I index'" << std::endl;
				return 1;
			}
			uint32_t	index = htonl(interface_index);
			stable_privacy_net_iface.resize(sizeof(index));
			std::memcpy(&stable_privacy_net_iface[0], &index, sizeof(index));
		} else if (std::strcmp(stable_privacy_net_iface_type, "name") == 0) {
			// Use the interface name for stable privacy network interface
			if (!interface_name) {
				std::clog << argv[0] << ": need to specify device (-d) option with '-I name'" << std::endl;
				return 1;
			}
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

		unsigned char		stable_privacy_key[Stable_privacy_hmac::KEY_LENGTH];
		key_in.read(reinterpret_cast<char*>(stable_privacy_key), sizeof(stable_privacy_key)); // cast from unsigned char* to char* is safe
		if (static_cast<size_t>(key_in.gcount()) != sizeof(stable_privacy_key)) {
			if (stable_privacy_key_file) {
				std::clog << argv[0] << ": " << stable_privacy_key_file << ": Key file too short (must be " << sizeof(stable_privacy_key) << " bytes long)" << std::endl;
			} else {
				std::clog << argv[0] << ": Insufficient number of bytes returned from random device" << std::endl;
			}
			return 1;
		}

		unsigned int	stable_interface_id_len = 128 - prefix_len;
		struct in6_addr	stable_interface_id;
		generate_stable_privacy_interface_id(&stable_interface_id, stable_interface_id_len, address, stable_privacy_key, stable_privacy_net_iface);
		set_address_suffix(&address, stable_interface_id, stable_interface_id_len);
	} else {
		struct in6_addr		interface_id;
		if (inet_pton(AF_INET6, interface_id_string, &interface_id) != 1) {
			std::clog << argv[0] << ": " << interface_id_string << ": Invalid IPv6 address" << std::endl;
			return 1;
		}
		unsigned int		slen = count_suffix_length(interface_id);
		if (!interface_id_len) {
			interface_id_len = slen;
		} else if (slen > interface_id_len) {
			std::clog << argv[0] << ": " << interface_id_string << ": Longer than specified interface ID bit length (-l " << interface_id_len << ")" << std::endl;
			return 1;
		}

		if (prefix_len + interface_id_len > 128) {
			std::clog << argv[0] << ": cannot assign address because prefix length (" << prefix_len << ") + interface ID length (" << interface_id_len << ") exceeds 128 bits" << std::endl;
			return 1;
		}
		set_address_suffix(&address, interface_id, interface_id_len);
	}

	char	address_string[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &address, address_string, sizeof(address_string));
	std::cout << address_string << std::endl;

	return 0;
}
