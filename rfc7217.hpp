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

#include "sha2.hpp"
#include "hmac.hpp"
#include <arpa/inet.h>
#include <vector>

typedef crypto::Hmac<crypto::Sha256> Stable_privacy_hmac;

void	generate_stable_privacy_interface_id (struct in6_addr* out, unsigned int len, const in6_addr& prefix, unsigned char stable_privacy_key[Stable_privacy_hmac::KEY_LENGTH], const std::vector<unsigned char>& stable_privacy_net_iface);
