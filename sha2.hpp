/*
 * Copyright (C) 2013 Andrew Ayer
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

#include <stdint.h>
#include <cstddef>

namespace crypto {
	class Sha2_internals {
	public:
		struct CTX {
			union {
				uint32_t	st32[8];
				uint64_t	st64[8];
			} state;
			uint64_t		bitcount[2];
			uint8_t		buffer[128];
		};

	protected:
		CTX		ctx;
	};

	class Sha256 : private Sha2_internals {
	public:
		enum {
			LENGTH = 32,
			BLOCK_LENGTH = 64
		};

		Sha256 ();
		~Sha256 ();
		void update (const void* data, std::size_t len);
		void finish (unsigned char* out);
		void finish (unsigned char* out, std::size_t out_len);

		static void compute (unsigned char* out, std::size_t out_len, const void* data, std::size_t data_len)
		{
			Sha256 hash;
			hash.update(data, data_len);
			hash.finish(out, out_len);
		}

		static void compute (unsigned char* out, const void* data, std::size_t data_len)
		{
			Sha256 hash;
			hash.update(data, data_len);
			hash.finish(out);
		}
	};
}
