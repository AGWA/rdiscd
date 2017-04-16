/*
 * Copyright (C) 2014 Andrew Ayer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name(s) of the above copyright
 * holders shall not be used in advertising or otherwise to promote the
 * sale, use or other dealings in this Software without prior written
 * authorization.
 */

#pragma once

#include "blockhash.hpp"
#include "util.hpp"
#include <algorithm>
#include <stdint.h>
#include <stddef.h>

namespace crypto {
	class Sha256_state {
	public:
		enum {
			LENGTH = 32U,
			BLOCK_LENGTH = 64U
		};

		Sha256_state (const uint32_t* initial_state =sha256_initial_state);
		~Sha256_state ();
		void transform (const unsigned char*);
		void write (unsigned char* out, size_t out_len =LENGTH);

		template<class Hash> static void pad (Hash& hash)
		{
			unsigned char		length_pad[8];
			store_be64(length_pad, hash.get_count() << 3);
			hash.update("\200", 1);			// Append 0x80
			while (hash.get_count() % 64 != 56) {	// Append zeros until current block is 56 bytes long
				hash.update("\0", 1);
			}
			hash.update(length_pad, 8);		// Append 8 byte length, which should form complete block
		}

	private:
		uint32_t			state[8];
		static const uint32_t		sha256_initial_state[8];
	};

	typedef Block_hash<Sha256_state> Sha256;
}
