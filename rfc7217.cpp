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
#include <algorithm>
#include <cstring>

// Generate a "stable privacy" interface ID as per RFC 7217 (http://tools.ietf.org/html/rfc7217).
// Note: we don't follow the algorithm exactly (e.g. we omit the DAD counter, we take bits
// from the PRF output in a different order), but since the RFC lets implementations
// choose their own PRFs anyways, it doesn't matter for standards compliance what the inputs to
// the PRF are, or how we use the output.
void	generate_stable_privacy_interface_id (struct in6_addr* out, unsigned int len, const in6_addr& prefix, unsigned char stable_privacy_key[Stable_privacy_hmac::KEY_LENGTH], const std::vector<unsigned char>& stable_privacy_net_iface)
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
