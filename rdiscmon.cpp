/*
 * Copyright 2014 Andrew Ayer
 *
 * Based, in part, on code from NetworkManager, Copyright (C) 2013 Red Hat, Inc.
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
#include "util.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

class Rdisc_monitor : public Base_rdisc {
	static const char* dhcp_level_to_string (Dhcp_level dhcp_level)
	{
		switch (dhcp_level) {
		case DHCP_LEVEL_NONE:
			return "none";
		case DHCP_LEVEL_OTHERCONF:
			return "otherconf";
		case DHCP_LEVEL_MANAGED:
			return "managed";
		default:
			return "INVALID";
		}
	}

	virtual void		dhcp_level_changed (Dhcp_level dhcp_level)
	{
		std::clog << "DHCP level = " << dhcp_level_to_string(dhcp_level) << std::endl;
	}

	virtual void		mtu_changed (int mtu)
	{
		std::clog << "MTU = " << mtu << std::endl;
	}

	virtual void		gateway_changed (const Gateway& gateway)
	{
		char		addrstr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &gateway.address, addrstr, sizeof(addrstr));
		std::clog << "Gateway = " << addrstr << " (valid_lft ";
		if (gateway.lifetime == FOREVER) {
			std::clog << "forever";
		} else {
			std::clog << gateway.lifetime;
		}
		std::clog << ")" << std::endl;
	}

	virtual void		onlink_prefix_changed (const Onlink_prefix& prefix)
	{
		char		addrstr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &prefix.prefix, addrstr, sizeof(addrstr));
		std::clog << "Onlink prefix = " << addrstr << "/" << prefix.prefix_len << " (valid_lft ";
		if (prefix.lifetime == FOREVER) {
			std::clog << "forever";
		} else {
			std::clog << prefix.lifetime;
		}
		std::clog << ")" << std::endl;
	}

	virtual void		autoconf_prefix_changed (const Autoconf_prefix& prefix)
	{
		char		addrstr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &prefix.prefix, addrstr, sizeof(addrstr));
		std::clog << "Autoconf prefix = " << addrstr << "/" << prefix.prefix_len << " (valid_lft ";
		if (prefix.lifetime == FOREVER) {
			std::clog << "forever";
		} else {
			std::clog << prefix.lifetime;
		}
		std::clog << " preferred_lft ";
		if (prefix.preferred_lifetime == FOREVER) {
			std::clog << "forever";
		} else {
			std::clog << prefix.preferred_lifetime;
		}
		std::clog << ")" << std::endl;
	}


public:
	Rdisc_monitor (int arg_ifindex, const std::string& arg_ifname) : Base_rdisc(arg_ifindex, arg_ifname) { }
};

int main (int argc, char** argv)
{
	if (argc != 2) {
		std::clog << "Usage: " << argv[0] << " INTERFACE" << std::endl;
		return 2;
	}

	const char*		interface_name = argv[1];
	int			interface_index = get_ifindex(interface_name);
	if (interface_index == -1) {
		std::clog << argv[0] << ": " << interface_name << ": No such interface" << std::endl;
		return 1;
	}


	Rdisc_monitor		mon(interface_index, interface_name);
	mon.set_enable_debug(true);
	mon.run();
	return 0;
}

