#pragma once
#include <map>
#include <Zydis/Zydis.h>
#include <stdexcept>
#include <functional>
#include <vmutils.h>

namespace vm
{
	namespace transform
	{
		// taken from ida...
		template<class T> inline T __ROL__(T value, int count)
		{
			const unsigned int nbits = sizeof(T) * 8;

			if (count > 0)
			{
				count %= nbits;
				T high = value >> (nbits - count);
				if (T(-1) < 0) // signed value
					high &= ~((T(-1) << count));
				value <<= count;
				value |= high;
			}
			else
			{
				count = -count % nbits;
				T low = value << (nbits - count);
				value >>= count;
				value |= low;
			}
			return value;
		}

		// taken from ida...
		inline u8  __ROL1__(u8  value, int count) { return __ROL__((u8)value, count); }
		inline u16 __ROL2__(u16 value, int count) { return __ROL__((u16)value, count); }
		inline u32 __ROL4__(u32 value, int count) { return __ROL__((u32)value, count); }
		inline u64 __ROL8__(u64 value, int count) { return __ROL__((u64)value, count); }
		inline u8  __ROR1__(u8  value, int count) { return __ROL__((u8)value, -count); }
		inline u16 __ROR2__(u16 value, int count) { return __ROL__((u16)value, -count); }
		inline u32 __ROR4__(u32 value, int count) { return __ROL__((u32)value, -count); }
		inline u64 __ROR8__(u64 value, int count) { return __ROL__((u64)value, -count); }

		template <typename T>
		using transform_t = std::function<T(T, T)>;

		enum class type
		{
			rolling_key,
			generic1,
			generic2,
			generic3,
			update_key
		};

		using map_t = std::map<transform::type, ZydisDecodedInstruction>;

		template <class T>
		inline const auto _bswap = [](T a, T b) -> T
		{
			if constexpr (std::is_same_v<T, std::uint64_t>)
				return _byteswap_uint64(a);
			if constexpr (std::is_same_v<T, std::uint32_t>)
				return _byteswap_ulong(a);
			if constexpr (std::is_same_v<T, std::uint16_t>)
				return _byteswap_ushort(a);

			throw std::invalid_argument("invalid type size...");
		};

		template <class T>
		inline const auto _add = [](T a, T b) -> T
		{
			return a + b;
		};

		template <class T>
		inline const auto _xor = [](T a, T b) -> T
		{
			return a ^ b;
		};

		template <class T>
		inline const auto _sub = [](T a, T b) -> T
		{
			return a - b;
		};

		template <class T>
		inline const auto _neg = [](T a, T b) -> T
		{
			return a * -1;
		};

		template <class T>
		inline const auto _not = [](T a, T b) -> T
		{
			return ~a;
		};

		template <class T>
		inline const auto _ror = [](T a, T b) -> T
		{
			if constexpr (std::is_same_v<T, std::uint64_t>)
				return __ROR8__(a, b);
			if constexpr (std::is_same_v<T, std::uint32_t>)
				return __ROR4__(a, b);
			if constexpr (std::is_same_v<T, std::uint16_t>)
				return __ROR2__(a, b);
			if constexpr (std::is_same_v <T, std::uint8_t>)
				return __ROR1__(a, b);

			throw std::invalid_argument("invalid type size...");
		};

		template <class T>
		inline const auto _rol = [](T a, T b) -> T
		{
			if constexpr (std::is_same_v<T, std::uint64_t>)
				return __ROL8__(a, b);
			if constexpr (std::is_same_v<T, std::uint32_t>)
				return __ROL4__(a, b);
			if constexpr (std::is_same_v<T, std::uint16_t>)
				return __ROL2__(a, b);
			if constexpr (std::is_same_v <T, std::uint8_t>)
				return __ROL1__(a, b);

			throw std::invalid_argument("invalid type size...");
		};

		template <class T>
		inline const auto _inc = [](T a, T b) -> T
		{
			return a + 1;
		};

		template <class T>
		inline const auto _dec = [](T a, T b) -> T
		{
			return a - 1;
		};

		template <class T>
		inline std::map<ZydisMnemonic, transform_t<T>> transforms =
		{
			{ ZYDIS_MNEMONIC_ADD, _add<T> },
			{ ZYDIS_MNEMONIC_XOR, _xor<T> },
			{ ZYDIS_MNEMONIC_BSWAP, _bswap<T> },
			{ ZYDIS_MNEMONIC_SUB, _sub<T>},
			{ ZYDIS_MNEMONIC_NEG, _neg<T>},
			{ ZYDIS_MNEMONIC_NOT, _not<T>},
			{ ZYDIS_MNEMONIC_ROR, _ror<T>},
			{ ZYDIS_MNEMONIC_ROL, _rol<T>},
			{ ZYDIS_MNEMONIC_INC, _inc<T>},
			{ ZYDIS_MNEMONIC_DEC, _dec<T>}
		};

		inline std::map<ZydisMnemonic, ZydisMnemonic> inverse =
		{
			{ZYDIS_MNEMONIC_ADD, ZYDIS_MNEMONIC_SUB},
			{ZYDIS_MNEMONIC_XOR, ZYDIS_MNEMONIC_XOR},
			{ZYDIS_MNEMONIC_BSWAP, ZYDIS_MNEMONIC_BSWAP},
			{ZYDIS_MNEMONIC_SUB, ZYDIS_MNEMONIC_ADD},
			{ZYDIS_MNEMONIC_NEG, ZYDIS_MNEMONIC_NEG},
			{ZYDIS_MNEMONIC_NOT, ZYDIS_MNEMONIC_NOT},
			{ZYDIS_MNEMONIC_ROR, ZYDIS_MNEMONIC_ROL},
			{ZYDIS_MNEMONIC_ROL, ZYDIS_MNEMONIC_ROR},
			{ZYDIS_MNEMONIC_INC, ZYDIS_MNEMONIC_DEC},
			{ZYDIS_MNEMONIC_DEC, ZYDIS_MNEMONIC_INC}
		};

		// max size of a and b is 64 bits, a and b is then converted to 
		// the number of bits in bitsize, the transformation is applied,
		// finally the result is converted back to 64bits... zero extended...
		inline auto apply(std::uint8_t bitsize, ZydisMnemonic op,
			std::uint64_t a, std::uint64_t b) -> std::uint64_t
		{
			switch (bitsize)
			{
			case 8:
				return transforms<std::uint8_t>[op](a, b);
			case 16:
				return transforms<std::uint16_t>[op](a, b);
			case 32:
				return transforms<std::uint32_t>[op](a, b);
			case 64:
				return transforms<std::uint64_t>[op](a, b);
			default:
				throw std::invalid_argument("invalid bit size...");
			}
		}

		inline bool has_imm(ZydisDecodedInstruction* instr)
		{
			return instr->operand_count > 1 &&
				(instr->operands[1].type & ZYDIS_OPERAND_TYPE_IMMEDIATE);
		}
	}
}