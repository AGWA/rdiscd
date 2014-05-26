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
#ifndef _RDISC_RDISC_HPP
#define _RDISC_RDISC_HPP

#include <stdarg.h> // included because of a bug in ndp.h
#include <ndp.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <cstring>
#include <limits>
#include <signal.h>

class Base_rdisc {
	enum { RETRY = 10 };

public:
	static const time_t FOREVER;

	enum Config_type {
		CONFIG_DHCP_LEVEL,
		CONFIG_MTU,
		CONFIG_GATEWAY,
		CONFIG_ONLINK_PREFIX,
		CONFIG_AUTOCONF_PREFIX
	};

	enum Dhcp_level {
		DHCP_LEVEL_UNKNOWN,
		DHCP_LEVEL_NONE,
		DHCP_LEVEL_OTHERCONF,
		DHCP_LEVEL_MANAGED
	};

	struct Base_item {
		time_t			timestamp;
		time_t			lifetime;

		Base_item ()
		{
			timestamp = lifetime = 0;
		}

		bool			is_valid () const { return lifetime != 0; }
		bool			clean (time_t now, time_t* nextevent);
	};

	struct Gateway : Base_item {
		struct in6_addr		address;

		Gateway ()
		{
			std::memset(&address, '\0', sizeof(address));
		}
	};

	struct Onlink_prefix : Base_item {
		struct in6_addr		prefix;
		size_t			prefix_len;	// in bits

		Onlink_prefix ()
		{
			std::memset(&prefix, '\0', sizeof(prefix));
			prefix_len = 0;
		}
	};

	struct Autoconf_prefix : Base_item {
		struct in6_addr		prefix;
		size_t			prefix_len;	// in bits
		time_t			preferred_lifetime;

		Autoconf_prefix ()
		{
			std::memset(&prefix, '\0', sizeof(prefix));
			prefix_len = 0;
			preferred_lifetime = 0;
		}

		bool			is_preferred () const { return preferred_lifetime != 0; }
		bool			clean (time_t now, time_t* nextevent);
	};

private:
	int				ifindex;
	std::string			ifname;
	bool				enable_debug;

	Dhcp_level			dhcp_level;
	int				mtu;
	std::vector<Gateway>		gateways;
	std::vector<Onlink_prefix>	onlink_prefixes;
	std::vector<Autoconf_prefix>	autoconf_prefixes;

	struct ndp*			ndp;

	time_t			next_rs_time;		// absolute time at which next RS should be sent (FOREVER if none scheduled)
	time_t			next_timeout_time;	// absolute time at which next timeouts should occur (FOREVER if none scheduled)

	time_t			get_next_event_time () const;

	bool			process_dhcp_level (Dhcp_level);
	bool			process_mtu (int new_mtu);
	bool			process_gateway (const Gateway& new_gateway);
	bool			process_onlink_prefix (const Onlink_prefix& new_prefix);
	bool			process_autoconf_prefix (const Autoconf_prefix& new_prefix, time_t now, bool is_authenticated);

	template<class T> void	clear (std::vector<T>& old_items);

	template<class T> bool	clean (std::vector<T>& items, time_t now, time_t* nextevent);
	bool			clean_gateways (time_t now, time_t* nextevent);
	bool			clean_onlink_prefixes (time_t now, time_t* nextevent);
	bool			clean_autoconf_prefixes (time_t now, time_t* nextevent);
	void			check_timestamps (time_t now);

	void			process_events ();
	bool			send_rs ();
	void			solicit ();

	static int		receive_ra_cb (struct ndp* ndp, struct ndp_msg* msg, void* user_data);

	void			item_changed (const Gateway& item) { gateway_changed(item); }
	void			item_changed (const Onlink_prefix& item) { onlink_prefix_changed(item); }
	void			item_changed (const Autoconf_prefix& item) { autoconf_prefix_changed(item); }

protected:
	virtual void		dhcp_level_changed (Dhcp_level) { }
	virtual void		mtu_changed (int mtu) { }
	virtual void		gateway_changed (const Gateway&) { }
	virtual void		onlink_prefix_changed (const Onlink_prefix&) { }
	virtual void		autoconf_prefix_changed (const Autoconf_prefix&) { }

public:
	Base_rdisc (int ifindex, const std::string& ifname);
	virtual ~Base_rdisc ();

	void					set_enable_debug (bool x) { enable_debug = x; }

	const int				get_ifindex () const { return ifindex; }
	const char*				get_ifname () const { return ifname.c_str(); }
	Dhcp_level				get_dhcp_level () const { return dhcp_level; }
	int					get_mtu () const { return mtu; }
	const std::vector<Gateway>&		get_gateways () const { return gateways; }
	const std::vector<Onlink_prefix>&	get_onlink_prefixes () const { return onlink_prefixes; }
	const std::vector<Autoconf_prefix>&	get_autoconf_prefixes () const { return autoconf_prefixes; }

	void					run (const volatile sig_atomic_t* is_running);
	void					run ();

	static void				set_address_masked (struct in6_addr* dst, const struct in6_addr* src, uint8_t plen);

	struct libndp_error {
		std::string		ifname;
		std::string		where;
		int			error;

		libndp_error (std::string _ifname, std::string _where, int _error)
		: ifname(_ifname), where(_where), error(_error) { }
	};

	struct system_error {
		std::string		ifname;
		std::string		where;
		int			error;

		system_error (std::string _ifname, std::string _where, int _error)
		: ifname(_ifname), where(_where), error(_error) { }
	};
};

class Rdisc : public Base_rdisc {
public:
	struct Consumer {
		virtual void		dhcp_level_changed (Dhcp_level) { }
		virtual void		mtu_changed (int mtu) { }
		virtual void		gateway_changed (const Gateway&) { }
		virtual void		onlink_prefix_changed (const Onlink_prefix&) { }
		virtual void		autoconf_prefix_changed (const Autoconf_prefix&) { }

		virtual			~Consumer () { }
	};
private:
	Consumer*			consumer;

	virtual void			dhcp_level_changed (Dhcp_level l) { consumer->dhcp_level_changed(l); }
	virtual void			mtu_changed (int mtu) { consumer->mtu_changed(mtu); }
	virtual void			gateway_changed (const Gateway& gw) { consumer->gateway_changed(gw); }
	virtual void			onlink_prefix_changed (const Onlink_prefix& p) { consumer->onlink_prefix_changed(p); }
	virtual void			autoconf_prefix_changed (const Autoconf_prefix& p) { consumer->autoconf_prefix_changed(p); }
public:
	Rdisc (int ifindex, const std::string& ifname, Consumer* arg_consumer)
	: Base_rdisc(ifindex, ifname), consumer(arg_consumer)
	{
	}
};


#endif
