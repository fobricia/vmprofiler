#pragma once
#include <transform.hpp>
#include <vmutils.h>
#include <vmprofiler.hpp>

namespace vm
{
	std::pair<std::uint64_t, std::uint64_t> decrypt_operand(transform::map_t& transforms, 
		std::uint64_t operand, std::uint64_t rolling_key);

	std::pair<std::uint64_t, std::uint64_t> encrypt_operand(transform::map_t& transforms,
		std::uint64_t operand, std::uint64_t rolling_key);

	void inverse_transforms(transform::map_t& transforms, transform::map_t& inverse);
	bool get_calc_jmp(const zydis_routine_t& vm_entry, zydis_routine_t& calc_jmp);
	bool get_vinstr_rva_transform(
		const zydis_routine_t& vm_entry, ZydisDecodedInstruction* transform_instr);

	struct handler_t
	{
		u8 imm_size; // size in bits...
		vm::transform::map_t transforms;
		vm::handler::profile_t* profile;
		zydis_routine_t instrs;
		std::uintptr_t address;
	};

	namespace handler
	{
		bool has_imm(const zydis_routine_t& vm_handler);
		std::uint8_t imm_size(const zydis_routine_t& vm_handler);
		bool get(zydis_routine_t& vm_entry, zydis_routine_t& vm_handler, std::uintptr_t handler_addr);

		// may throw an exception...
		bool get_all(std::uintptr_t module_base, std::uintptr_t image_base, 
			zydis_routine_t& vm_entry, std::uintptr_t* vm_handler_table, std::vector<vm::handler_t>& vm_handlers);

		// can be used on calc_jmp...
		bool get_operand_transforms(const zydis_routine_t& vm_handler, transform::map_t& transforms);
		vm::handler::profile_t* get_profile(vm::handler_t& vm_handler);

		namespace table
		{
			std::uintptr_t* get(const zydis_routine_t& vm_entry);
			bool get_transform(const zydis_routine_t& vm_entry, ZydisDecodedInstruction* transform_instr);

			std::uint64_t encrypt(ZydisDecodedInstruction& transform_instr, std::uint64_t val);
			std::uint64_t decrypt(ZydisDecodedInstruction& transform_instr, std::uint64_t val);
		}
	}
}