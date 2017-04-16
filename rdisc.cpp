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
#include <cstdlib>
#include <iostream>
#include <errno.h>

static time_t get_time ()
{
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return tp.tv_sec;
}

const time_t Base_rdisc::FOREVER = std::numeric_limits<time_t>::max();

time_t	Base_rdisc::get_next_event_time () const
{
	time_t	next_event = FOREVER;
	if (next_rs_time < next_event) {
		next_event = next_rs_time;
	}
	if (next_timeout_time < next_event) {
		next_event = next_timeout_time;
	}
	return next_event;
}

bool Base_rdisc::Base_item::clean (time_t now, time_t* nextevent)
{
	bool		changed = false;
	if (lifetime != FOREVER) {
		time_t	expiry = timestamp + lifetime;
		if (now >= expiry) {
			lifetime = 0;
			changed = true;
		} else if (*nextevent > expiry) {
			*nextevent = expiry;
		}
	}
	return changed;
}

bool Base_rdisc::Autoconf_prefix::clean (time_t now, time_t* nextevent)
{
	bool		changed = false;
	if (preferred_lifetime != 0 && preferred_lifetime != FOREVER) {
		time_t	preferred_expiry = timestamp + preferred_lifetime;
		if (now >= preferred_expiry) {
			preferred_lifetime = 0;
			changed = true;
		} else if (*nextevent > preferred_expiry) {
			*nextevent = preferred_expiry;
		}
	}

	return Base_item::clean(now, nextevent) || changed;
}

template<class T> bool Base_rdisc::clean (std::vector<T>& items, time_t now, time_t* nextevent)
{
	bool changed = false;
	size_t i = 0;
	while (i < items.size()) {
		T&		item(items[i]);
		if (item.clean(now, nextevent)) {
			changed = true;

			if (!item.is_valid()) {
				T	old_item(item);
				items.erase(items.begin() + i);
				item_changed(old_item);
				continue;
			} else {
				item_changed(item);
			}
		}

		++i;
	}

	return changed;
}

template<class T> void Base_rdisc::clear (std::vector<T>& old_items)
{
	std::vector<T>		items;
	items.swap(old_items);

	for (typename std::vector<T>::iterator item(items.begin()); item != items.end(); ++item) {
		item->lifetime = 0;
		item_changed(*item);
	}
}

bool Base_rdisc::process_dhcp_level (Dhcp_level new_dhcp_level)
{
	if (new_dhcp_level != dhcp_level) {
		dhcp_level = new_dhcp_level;
		dhcp_level_changed(dhcp_level);
		return true;
	}
	return false;
}

bool Base_rdisc::process_mtu (int new_mtu)
{
	if (new_mtu != mtu) {
		mtu = new_mtu;
		mtu_changed(mtu);
		return true;
	}
	return false;
}

bool Base_rdisc::process_gateway (const Base_rdisc::Gateway& new_gateway)
{
	// As per 6.3.4 of RFC 4861.

	for (size_t i = 0; i < gateways.size(); ++i) {
		Gateway&		gateway(gateways[i]);
		if (IN6_ARE_ADDR_EQUAL(&gateway.address, &new_gateway.address)) {
			gateway = new_gateway;

			if (gateway.lifetime == 0) {
				Gateway	old_gateway(gateway);
				gateways.erase(gateways.begin() + i);
				gateway_changed(old_gateway);
				return true;
			}

			return false;
		}
	}
	if (new_gateway.lifetime != 0) {
		gateways.push_back(new_gateway);
		gateway_changed(gateways.back());
		return true;
	}
	return false;
}

bool Base_rdisc::process_onlink_prefix (const Base_rdisc::Onlink_prefix& new_prefix)
{
	// As per 6.3.4 of RFC 4861.

	for (size_t i = 0; i < onlink_prefixes.size(); ++i) {
		Onlink_prefix&		prefix(onlink_prefixes[i]);

		if (IN6_ARE_ADDR_EQUAL(&prefix.prefix, &new_prefix.prefix) && prefix.prefix_len == new_prefix.prefix_len) {
			prefix = new_prefix;

			if (prefix.lifetime == 0) {
				Onlink_prefix	old_prefix(prefix);
				onlink_prefixes.erase(onlink_prefixes.begin() + i);
				onlink_prefix_changed(old_prefix);
				return true;
			}

			return false;
		}
	}
	if (new_prefix.lifetime != 0) {
		onlink_prefixes.push_back(new_prefix);
		onlink_prefix_changed(onlink_prefixes.back());
		return true;
	}
	return false;
}

bool Base_rdisc::process_autoconf_prefix (const Base_rdisc::Autoconf_prefix& new_prefix, time_t now, bool is_authenticated)
{
	// As per RFC 4862, Section 5.5.3:
	if (new_prefix.preferred_lifetime > new_prefix.lifetime) {
		// Future TODO: log this
		return false;
	}

	for (size_t i = 0; i < autoconf_prefixes.size(); ++i) {
		Autoconf_prefix&	prefix(autoconf_prefixes[i]);

		if (IN6_ARE_ADDR_EQUAL(&prefix.prefix, &new_prefix.prefix) && prefix.prefix_len == new_prefix.prefix_len) {
			prefix.timestamp = new_prefix.timestamp;

			// Attempt to stop a simple DoS as per RFC 4862, Section 5.5.3:
			time_t		remaining_lifetime = prefix.timestamp + prefix.lifetime - now;
			if (new_prefix.lifetime > 7200 || new_prefix.lifetime > remaining_lifetime) {
				prefix.lifetime = new_prefix.lifetime;
			} else if (remaining_lifetime <= 7200) {
				if (is_authenticated) {
					prefix.lifetime = new_prefix.lifetime;
				}
			} else {
				prefix.lifetime = 7200;
			}

			bool		was_preferred = prefix.is_preferred();
			prefix.preferred_lifetime = new_prefix.preferred_lifetime;


			if (prefix.lifetime == 0) {
				Autoconf_prefix	old_prefix(prefix);
				autoconf_prefixes.erase(autoconf_prefixes.begin() + i);
				autoconf_prefix_changed(old_prefix);
				return true;
			}

			if (prefix.is_preferred() != was_preferred) {
				autoconf_prefix_changed(prefix);
				return true;
			}

			return false;
		}
	}
	if (new_prefix.lifetime != 0) {
		autoconf_prefixes.push_back(new_prefix);
		autoconf_prefix_changed(autoconf_prefixes.back());
		return true;
	}
	return false;
}

bool Base_rdisc::clean_gateways (time_t now, time_t* nextevent)
{
	return clean(gateways, now, nextevent);
}
bool Base_rdisc::clean_onlink_prefixes (time_t now, time_t* nextevent)
{
	return clean(onlink_prefixes, now, nextevent);
}

bool Base_rdisc::clean_autoconf_prefixes (time_t now, time_t* nextevent)
{
	return clean(autoconf_prefixes, now, nextevent);
}

void Base_rdisc::check_timestamps (time_t now)
{
	if (enable_debug) { std::clog << "rdisc (" << ifname << "): checking timestamps" << std::endl; }

	next_timeout_time = FOREVER;

	time_t nextevent = FOREVER;
	clean_gateways(now, &nextevent);
	clean_onlink_prefixes(now, &nextevent);
	clean_autoconf_prefixes(now, &nextevent);

	if (nextevent != FOREVER) {
		if (enable_debug) { std::clog << "rdisc (" << ifname << "): scheduling next now/lifetime check: " << (nextevent - now) << " seconds from now" << std::endl; }
		next_timeout_time = nextevent;
	}
}

void Base_rdisc::process_events ()
{
	if (enable_debug) { std::clog << "rdisc (" << ifname << "): processing libndp events" << std::endl; }
	ndp_callall_eventfd_handler(ndp);
}

bool Base_rdisc::send_rs ()
{
	struct ndp_msg*		msg; // TODO: RAII
	if (int error = ndp_msg_new(&msg, NDP_MSG_RS)) {
		throw libndp_error(ifname, "ndp_msg_new", error);
	}
	ndp_msg_ifindex_set(msg, ifindex);

	if (enable_debug) { std::clog << "rdisc (" << ifname << "): sending router solicitation" << std::endl; }

	if (int error = ndp_msg_send(ndp, msg)) {
		if (enable_debug) { std::clog << "rdisc (" << ifname << "): error sending router solicitation: ndp_msg_send: " << error << std::endl; }
	}

	ndp_msg_destroy(msg);

	// schedule another router solicitation in TIMEOUT seconds
	if (enable_debug) { std::clog << "rdisc (" << ifname << "): scheduling router solicitation retry in " << RETRY << " seconds" << std::endl; }
	next_rs_time = get_time() + RETRY;

	return false;
}

void Base_rdisc::solicit ()
{
	if (next_rs_time == FOREVER) {
		// If no router solicitation is currently scheduled, schedule one for right now
		// (defer execution until we're back in the main loop)
		if (enable_debug) { std::clog << "rdisc (" << ifname << "): scheduling router solicitation" << std::endl; }
		next_rs_time = get_time();
	}
}

int Base_rdisc::receive_ra_cb (struct ndp* ndp, struct ndp_msg* msg, void* user_data)
{
	Base_rdisc*		rdisc = static_cast<Base_rdisc*>(user_data);
	struct ndp_msgra*	msgra = ndp_msgra(msg);
	time_t			now = get_time();

	/* Router discovery is subject to the following RFC documents:
	 *
	 * http://tools.ietf.org/html/rfc4861
	 * http://tools.ietf.org/html/rfc4862
	 *
	 * The biggest difference from good old DHCP is that all configuration
	 * items have their own lifetimes and they are merged from various
	 * sources. Router discovery is *not* contract-based, so there is *no*
	 * single time when the configuration is finished and updates can
	 * come at any time.
	 */
	if (rdisc->enable_debug) { std::clog << "rdisc (" << rdisc->ifname << "): received router advertisement at " << now << std::endl; }

	rdisc->next_rs_time = FOREVER;

	/* DHCP level:
	 *
	 * The problem with DHCP level is what to do if subsequent
	 * router advertisements carry different flags. Currently we just
	 * rewrite the flag with every inbound RA.
	 */
	{
		Dhcp_level	dhcp_level;

		if (ndp_msgra_flag_managed (msgra))
			dhcp_level = DHCP_LEVEL_MANAGED;
		else if (ndp_msgra_flag_other (msgra))
			dhcp_level = DHCP_LEVEL_OTHERCONF;
		else
			dhcp_level = DHCP_LEVEL_NONE;

		rdisc->process_dhcp_level(dhcp_level);
	}

	/* MTU */
	int			offset;
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_MTU) {
		rdisc->process_mtu(ndp_msg_opt_mtu(msg, offset));
	}

	/* Default gateway:
	 *
	 * Subsequent router advertisements can represent new default gateways
	 * on the network. We should present all of them in router preference
	 * order.
	 */
	Gateway			gateway;
	gateway.address = *ndp_msg_addrto(msg);
	gateway.timestamp = now;
	gateway.lifetime = ndp_msgra_router_lifetime(msgra); // implicit cast from uint16_t to time_t Does The Right Thing
	rdisc->process_gateway(gateway);

	/* Prefixes */
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_PREFIX) {
		size_t			prefix_len = ndp_msg_opt_prefix_len(msg, offset);
		struct in6_addr*	prefix = ndp_msg_opt_prefix(msg, offset);
		uint32_t		lifetime = ndp_msg_opt_prefix_valid_time(msg, offset);

		// Ignore the link-local prefix (fe80::/10)
		// TODO: should also check for shorter prefixes that encompass the link-local prefix
		if (prefix_len >= 10 && IN6_IS_ADDR_LINKLOCAL(prefix)) {
			// Future TODO: log this
			continue;
		}

		if (ndp_msg_opt_prefix_flag_on_link(msg, offset)) {
			Onlink_prefix	onlink_prefix;
			set_address_masked(&onlink_prefix.prefix, prefix, prefix_len);
			onlink_prefix.prefix_len = prefix_len;
			onlink_prefix.timestamp = now;
			onlink_prefix.lifetime = (lifetime == 0xFFFFFFFF ? FOREVER : lifetime);
			rdisc->process_onlink_prefix(onlink_prefix);
		}
		if (ndp_msg_opt_prefix_flag_auto_addr_conf(msg, offset)) {
			uint32_t	preferred_lifetime = ndp_msg_opt_prefix_preferred_time(msg, offset);
			Autoconf_prefix	autoconf_prefix;
			set_address_masked(&autoconf_prefix.prefix, prefix, prefix_len);
			autoconf_prefix.prefix_len = prefix_len;
			autoconf_prefix.timestamp = now;
			autoconf_prefix.lifetime = (lifetime == 0xFFFFFFFF ? FOREVER : lifetime);
			autoconf_prefix.preferred_lifetime = (preferred_lifetime == 0xFFFFFFFF ? FOREVER : preferred_lifetime);
			rdisc->process_autoconf_prefix(autoconf_prefix, now, false);
		}
	}

	rdisc->check_timestamps(now);

	return 0;
}

Base_rdisc::Base_rdisc (int arg_ifindex, const std::string& arg_ifname)
{
	ifindex = arg_ifindex;
	ifname = arg_ifname;
	enable_debug = false;

	dhcp_level = DHCP_LEVEL_UNKNOWN;
	mtu = 0;

	ndp = NULL;

	next_rs_time = FOREVER;
	next_timeout_time = FOREVER;

	if (int error = ndp_open(&ndp)) {
		throw libndp_error(ifname, "ndp_open", error);
	}
}

Base_rdisc::~Base_rdisc ()
{
	if (ndp) {
		ndp_close(ndp);
	}
}

void Base_rdisc::run (const volatile sig_atomic_t* is_running)
{
	// Flush any pending messages to avoid using obsolete information
	process_events();

	ndp_msgrcv_handler_register(ndp, &Base_rdisc::receive_ra_cb, NDP_MSG_RA, ifindex, this);
	solicit();

	int		ndp_fd = ndp_get_eventfd(ndp);
	fd_set		rfds;
	FD_ZERO(&rfds);

	sigset_t	empty_sigset;
	sigemptyset(&empty_sigset);

	while (*is_running) {
		time_t	now;
		time_t	next_event;

		while ((next_event = get_next_event_time()) <= (now = get_time())) {
			if (now >= next_rs_time) {
				send_rs();
			}
			if (now >= next_timeout_time) {
				check_timestamps(now);
			}
		}

		struct timespec timeout = { next_event - now, 0 };

		FD_SET(ndp_fd, &rfds);
		int	retval = pselect(ndp_fd + 1, &rfds, NULL, NULL, next_event != FOREVER ? &timeout : NULL, &empty_sigset);
		if (retval == -1 && errno != EINTR) {
			throw system_error(ifname, "select", errno);
		} else if (retval > 0) {
			process_events();
		}
	}

	clear(autoconf_prefixes);
	clear(onlink_prefixes);
	clear(gateways);
}

void Base_rdisc::run ()
{
	sig_atomic_t is_running = 1;
	run(&is_running);
}

/* Ensure the given address is masked with its prefix and that all host
 * bits are set to zero.  Some IPv6 router advertisement daemons (eg, radvd)
 * don't enforce this in their configuration.
 */
void Base_rdisc::set_address_masked (struct in6_addr* dst, const struct in6_addr* src, uint8_t plen)
{
	unsigned int nbytes = plen / 8;
	unsigned int nbits = plen % 8;

	if (plen >= 128) {
		*dst = *src;
	} else {
		std::memset(dst, '\0', sizeof(*dst));
		std::memcpy(dst->s6_addr, src->s6_addr, nbytes);
		dst->s6_addr[nbytes] = (src->s6_addr[nbytes] & (0xFF << (8 - nbits)));
	}
}

