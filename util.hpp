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
#pragma once

#include <string>
#include <stddef.h>
#include <arpa/inet.h>

int			get_ifindex (const char* ifname);
bool			parse_macaddr_string (unsigned char* macaddr, const char* macaddr_string);
bool			get_if_macaddr (unsigned char* macaddr, const char* ifname);
void			fill_address_from_mac (struct in6_addr* address, const unsigned char* mac);
void			set_address_suffix (struct in6_addr* address, const struct in6_addr& suffix, unsigned int slen);
unsigned int		count_suffix_length (const struct in6_addr& address);
std::string		format_ipv6_address (const struct in6_addr& addr);
std::string		format_ipv6_address (const struct in6_addr& addr, int plen);
int			systemv (const char* command, const char* const* argv);
void			explicit_memzero (void* s, size_t n); // zero memory that won't be optimized away
void			store_be64 (unsigned char* p, uint64_t i);
void			close_standard_streams ();
int			set_cloexec (int fd);
