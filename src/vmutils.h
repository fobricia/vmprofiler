#pragma once
#include <vector>
#include <Zydis/Zydis.h>
#include <Zydis/Utils.h>
#include <xmmintrin.h>

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;
using u128 = __m128;

struct zydis_instr_t
{
	ZydisDecodedInstruction instr;
	std::vector<u8> raw;
	std::uintptr_t addr;
};

using zydis_routine_t = std::vector<zydis_instr_t>;

namespace vm
{
	namespace util
	{
		namespace reg
		{
			// converts say... AL to RAX...
			ZydisRegister to64(ZydisRegister reg);
			bool compare(ZydisRegister a, ZydisRegister b);
		}

		void print(zydis_routine_t& routine);
		void print(const ZydisDecodedInstruction& instr);
		bool is_jmp(const ZydisDecodedInstruction& instr);

		bool flatten(zydis_routine_t& routine, std::uintptr_t routine_addr, bool keep_jmps = false);
		void deobfuscate(zydis_routine_t& routine);
	}
}