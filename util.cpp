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
#include "util.hpp"
#include <string>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>

int get_ifindex (const char* ifname)
{
	std::string	path("/sys/class/net/");
	path += ifname;
	path += "/ifindex";

	std::ifstream	file(path.c_str());
	if (!file) {
		return -1;
	}

	int		ifindex = -1;
	file >> ifindex;
	return ifindex;
}

bool parse_macaddr_string (unsigned char* macaddr, const char* macaddr_string)
{
	return std::sscanf(macaddr_string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&macaddr[0], &macaddr[1], &macaddr[2], &macaddr[3], &macaddr[4], &macaddr[5]) == 6;
}

bool get_if_macaddr (unsigned char* macaddr, const char* ifname)
{
	std::string	path("/sys/class/net/");
	path += ifname;
	path += "/address";

	std::ifstream	file(path.c_str());
	if (!file) {
		return false;
	}

	std::string	macaddr_string;
	file >> macaddr_string;
	return parse_macaddr_string(macaddr, macaddr_string.c_str());
}

/* Translate 48-bit (6 byte) MAC address to a 64-bit modified interface identifier
 * and write it to the second half of the IPv6 address.
 *
 * See http://tools.ietf.org/html/rfc3513#page-21
 */
void fill_address_from_mac (struct in6_addr* address, const unsigned char* mac)
{
	unsigned char* identifier = address->s6_addr + 8;

	std::memcpy(identifier, mac, 3);
	identifier[0] ^= 0x02;
	identifier[3] = 0xff;
	identifier[4] = 0xfe;
	std::memcpy(identifier + 5, mac + 3, 3);
}

// assumes that the last slen bits of address and the first (128-slen) bits of suffix are zero
void set_address_suffix (struct in6_addr* address, const struct in6_addr& suffix, unsigned int slen)
{
	unsigned int nbytes = slen / 8;

	std::memcpy(address->s6_addr + (16 - nbytes), suffix.s6_addr + (16 - nbytes), nbytes);
	if (nbytes < 16) {
		address->s6_addr[16 - nbytes - 1] |= suffix.s6_addr[16 - nbytes - 1];
	}
}

unsigned int count_suffix_length (const struct in6_addr& address)
{
	// count the number of leading zero bits in address
	unsigned int	zeroes = 0;
	size_t		i = 0;
	while (i < 16 && address.s6_addr[i] == 0) {
		zeroes += 8;
		++i;
	}
	if (i < 16) {
		// 0000 000x => 7
		// 0000 00xx => 6
		// 0000 0xxx => 5
		// 0000 xxxx => 4
		// 000x xxxx => 3
		// 00xx xxxx => 2
		// 0xxx xxxx => 1
		// xxxx xxxx => 0
		if ((address.s6_addr[i] & 0xFE) == 0) {
			zeroes += 7;
		} else if ((address.s6_addr[i] & 0xFC) == 0) {
			zeroes += 6;
		} else if ((address.s6_addr[i] & 0xF8) == 0) {
			zeroes += 5;
		} else if ((address.s6_addr[i] & 0xF0) == 0) {
			zeroes += 4;
		} else if ((address.s6_addr[i] & 0xE0) == 0) {
			zeroes += 3;
		} else if ((address.s6_addr[i] & 0xC0) == 0) {
			zeroes += 2;
		} else if ((address.s6_addr[i] & 0x80) == 0) {
			zeroes += 1;
		}
	}

	return 128 - zeroes;
}

std::string		format_ipv6_address (const struct in6_addr& addr)
{
	char		addrstr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &addr, addrstr, sizeof(addrstr));
	return addrstr;
}

std::string		format_ipv6_address (const struct in6_addr& addr, int plen)
{
	std::ostringstream	out;
	out << format_ipv6_address(addr);
	out << "/" << plen;
	return out.str();
}

int			systemv (const char* command, const char* const* argv)
{
	pid_t		child = fork();
	if (child == -1) {
		return -1;
	}
	if (child == 0) {
		execvp(command, const_cast<char* const*>(argv));
		std::perror(command);
		_exit(127);
	}
	int		status;
	if (waitpid(child, &status, 0) == -1) {
		return -1;
	}
	return status;
}

void* explicit_memset (void* s, int c, size_t n)
{
	volatile unsigned char* p = reinterpret_cast<unsigned char*>(s);

	while (n--) {
		*p++ = c;
	}

	return s;
}

