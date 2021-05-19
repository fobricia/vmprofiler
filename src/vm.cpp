#include "vm.h"

namespace vm
{
	std::pair<std::uint64_t, std::uint64_t> decrypt_operand(transform::map_t& transforms,
		std::uint64_t operand, std::uint64_t rolling_key)
	{
		const auto key_decrypt = &transforms[transform::type::rolling_key];
		const auto generic_decrypt_1 = &transforms[transform::type::generic1];
		const auto generic_decrypt_2 = &transforms[transform::type::generic2];
		const auto generic_decrypt_3 = &transforms[transform::type::generic3];
		const auto update_key = &transforms[transform::type::update_key];

		// apply transformation with rolling decrypt key...
		operand = transform::apply(key_decrypt->operands[0].size,
			key_decrypt->mnemonic, operand, rolling_key);

		// apply three generic transformations...
		{
			operand = transform::apply(
				generic_decrypt_1->operands[0].size,
				generic_decrypt_1->mnemonic, operand,
				// check to see if this instruction has an IMM...
				transform::has_imm(generic_decrypt_1) ?
				generic_decrypt_1->operands[1].imm.value.u : 0);

			operand = transform::apply(
				generic_decrypt_2->operands[0].size,
				generic_decrypt_2->mnemonic, operand,
				// check to see if this instruction has an IMM...
				transform::has_imm(generic_decrypt_2) ?
				generic_decrypt_2->operands[1].imm.value.u : 0);

			operand = transform::apply(
				generic_decrypt_3->operands[0].size,
				generic_decrypt_3->mnemonic, operand,
				// check to see if this instruction has an IMM...
				transform::has_imm(generic_decrypt_3) ?
				generic_decrypt_3->operands[1].imm.value.u : 0);
		}

		// update rolling key...
		auto result = transform::apply(update_key->operands[0].size,
			update_key->mnemonic, rolling_key, operand);

		// update decryption key correctly...
		switch (update_key->operands[0].size)
		{
		case 8:
			rolling_key = (rolling_key & ~0xFFull) + result;
			break;
		case 16:
			rolling_key = (rolling_key & ~0xFFFFull) + result;
			break;
		default:
			rolling_key = result;
			break;
		}

		return { operand, rolling_key };
	}

	void inverse_transforms(transform::map_t& transforms, transform::map_t& inverse)
	{
		inverse[transform::type::rolling_key] = transforms[transform::type::rolling_key];
		inverse[transform::type::rolling_key].mnemonic = 
			transform::inverse[transforms[transform::type::rolling_key].mnemonic];

		inverse[transform::type::generic1] = transforms[transform::type::generic1];
		inverse[transform::type::generic1].mnemonic = 
			transform::inverse[transforms[transform::type::generic1].mnemonic];

		inverse[transform::type::generic2] = transforms[transform::type::generic2];
		inverse[transform::type::generic2].mnemonic = 
			transform::inverse[transforms[transform::type::generic2].mnemonic];

		inverse[transform::type::generic3] = transforms[transform::type::generic3];
		inverse[transform::type::generic3].mnemonic = 
			transform::inverse[transforms[transform::type::generic3].mnemonic];

		inverse[transform::type::update_key] = transforms[transform::type::update_key];
		inverse[transform::type::update_key].mnemonic = 
			transform::inverse[transforms[transform::type::update_key].mnemonic];
	}

	std::pair<std::uint64_t, std::uint64_t> encrypt_operand(transform::map_t& transforms, 
		std::uint64_t operand, std::uint64_t rolling_key)
	{
		transform::map_t inverse;
		inverse_transforms(transforms, inverse);

		const auto key_decrypt = &inverse[transform::type::rolling_key];
		const auto generic_decrypt_1 = &inverse[transform::type::generic1];
		const auto generic_decrypt_2 = &inverse[transform::type::generic2];
		const auto generic_decrypt_3 = &inverse[transform::type::generic3];
		const auto update_key = &inverse[transform::type::update_key];

		auto result = transform::apply(update_key->operands[0].size,
			update_key->mnemonic, rolling_key, operand);

		// make sure we update the rolling decryption key correctly...
		switch (update_key->operands[0].size)
		{
		case 8:
			rolling_key = (rolling_key & ~0xFFull) + result;
			break;
		case 16:
			rolling_key = (rolling_key & ~0xFFFFull) + result;
			break;
		default:
			rolling_key = result;
			break;
		}

		{
			operand = transform::apply(
				generic_decrypt_3->operands[0].size,
				generic_decrypt_3->mnemonic, operand,
				// check to see if this instruction has an IMM...
				transform::has_imm(generic_decrypt_3) ?
				generic_decrypt_3->operands[1].imm.value.u : 0);

			operand = transform::apply(
				generic_decrypt_2->operands[0].size,
				generic_decrypt_2->mnemonic, operand,
				// check to see if this instruction has an IMM...
				transform::has_imm(generic_decrypt_2) ?
				generic_decrypt_2->operands[1].imm.value.u : 0);

			operand = transform::apply(
				generic_decrypt_1->operands[0].size,
				generic_decrypt_1->mnemonic, operand,
				// check to see if this instruction has an IMM...
				transform::has_imm(generic_decrypt_1) ?
				generic_decrypt_1->operands[1].imm.value.u : 0);
		}

		operand = transform::apply(key_decrypt->operands[0].size,
			key_decrypt->mnemonic, operand, rolling_key);

		return { operand, rolling_key };
	}

	bool get_calc_jmp(const zydis_routine_t& vm_entry, zydis_routine_t& calc_jmp)
	{
		auto result = std::find_if(vm_entry.begin(), vm_entry.end(), 
			[](const zydis_instr_t& instr_data) -> bool 
			{
				// mov/movsx/movzx rax/eax/ax/al, [rsi]
				if (instr_data.instr.operand_count > 1 &&
					(instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOV ||
						instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVSX ||
						instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVZX) &&
					instr_data.instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					util::reg::to64(instr_data.instr.operands[0].reg.value) == ZYDIS_REGISTER_RAX &&
					instr_data.instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
					instr_data.instr.operands[1].mem.base == ZYDIS_REGISTER_RSI)
					return true;
				return false;
			}
		);

		if (result == vm_entry.end())
			return false;

		calc_jmp.insert(calc_jmp.end(), result, vm_entry.end());
		return true;
	}

	bool get_vinstr_rva_transform(
		const zydis_routine_t& vm_entry, ZydisDecodedInstruction* transform_instr)
	{
		//
		// find mov esi, [rsp+0xA0]
		//

		auto result = std::find_if(vm_entry.begin(), vm_entry.end(), 
			[](const zydis_instr_t& instr_data) -> bool 
			{
				if (instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
					instr_data.instr.operand_count == 2 &&
					instr_data.instr.operands[0].reg.value == ZYDIS_REGISTER_ESI &&
					instr_data.instr.operands[1].mem.base == ZYDIS_REGISTER_RSP &&
					instr_data.instr.operands[1].mem.disp.has_displacement &&
					instr_data.instr.operands[1].mem.disp.value == 0xA0)
					return true;
				return false;
			}
		);

		if (result == vm_entry.end())
			return false;

		//
		// find the next instruction with ESI as the dest...
		//

		result = std::find_if(++result, vm_entry.end(),
			[](const zydis_instr_t& instr_data) -> bool
			{
				if (instr_data.instr.operands[0].reg.value == ZYDIS_REGISTER_ESI)
					return true;

				return false;
			}
		);

		if (result == vm_entry.end())
			return false;

		*transform_instr = result->instr;
		transform_instr->mnemonic = transform::inverse[result->instr.mnemonic];
		return true;
	}
	
	namespace handler
	{
		bool get(zydis_routine_t& calc_jmp, zydis_routine_t& vm_handler, std::uintptr_t handler_addr)
		{
			if (!vm::util::flatten(vm_handler, handler_addr))
				return false;

			vm::util::deobfuscate(vm_handler);

			static const auto calc_jmp_check = 
				[&](std::uintptr_t addr) -> bool
			{
				for (const auto& [instr, instr_raw, instr_addr] : calc_jmp)
					if (instr_addr == addr)
						return true;

				return false;
			};

			auto result = std::find_if(
				vm_handler.begin(), vm_handler.end(), 
				[](const zydis_instr_t& instr) -> bool 
				{
					if (instr.instr.mnemonic == ZYDIS_MNEMONIC_LEA &&
						instr.instr.operands[0].reg.value == ZYDIS_REGISTER_RAX &&
						instr.instr.operands[1].mem.base == ZYDIS_REGISTER_RDI &&
						instr.instr.operands[1].mem.disp.value == 0xE0)
						return true;

					return calc_jmp_check(instr.addr);
				}
			);

			// remove calc_jmp from the vm handler vector...
			if (result != vm_handler.end())
				vm_handler.erase(result, vm_handler.end());
			else // locate the last mov al, [rsi], 
				// then remove all instructions after that...
			{
				zydis_routine_t::iterator last = vm_handler.end();
				result = vm_handler.begin();

				while (result != vm_handler.end())
				{
					result = std::find_if(
						++result, vm_handler.end(),
						[](const zydis_instr_t& instr_data) -> bool
						{
							// mov/movsx/movzx rax/eax/ax/al, [rsi]
							if (instr_data.instr.operand_count > 1 &&
								(instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOV ||
									instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVSX ||
									instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVZX) &&
								instr_data.instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								util::reg::to64(instr_data.instr.operands[0].reg.value) == ZYDIS_REGISTER_RAX &&
								instr_data.instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
								instr_data.instr.operands[1].mem.base == ZYDIS_REGISTER_RSI)
								return true;
							return false;
						}
					);

					if (result != vm_handler.end())
						last = result;
				}

				if (last != vm_handler.end())
					vm_handler.erase(last, vm_handler.end());
			}
			return true;
		}

		bool get_all(std::uintptr_t module_base, std::uintptr_t image_base, 
			zydis_routine_t& vm_entry, std::uintptr_t* vm_handler_table, std::vector<vm::handler_t>& vm_handlers)
		{
			ZydisDecodedInstruction instr;
			if (!vm::handler::table::get_transform(vm_entry, &instr))
				return false;

			zydis_routine_t calc_jmp;
			if (!vm::get_calc_jmp(vm_entry, calc_jmp))
				return false;

			for (auto idx = 0u; idx < 256; ++idx)
			{
				const auto decrypt_val =
					vm::handler::table::decrypt(
						instr, vm_handler_table[idx]);

				vm::handler_t vm_handler;
				vm::transform::map_t transforms;
				zydis_routine_t vm_handler_instrs;

				if (!vm::handler::get(calc_jmp, vm_handler_instrs, (decrypt_val - image_base) + module_base))
					return false;

				const auto has_imm =
					vm::handler::has_imm(vm_handler_instrs);

				const auto imm_size =
					vm::handler::imm_size(vm_handler_instrs);

				if (has_imm && !vm::handler::get_operand_transforms(vm_handler_instrs, transforms))
					return false;

				vm_handler.instrs = vm_handler_instrs;
				vm_handler.imm_size = imm_size;
				vm_handler.transforms = transforms;
				vm_handler.profile = vm::handler::get_profile(vm_handler);
				vm_handlers.push_back(vm_handler);
			}

			return true;
		}

		bool has_imm(const zydis_routine_t& vm_handler)
		{
			const auto result = std::find_if(
				vm_handler.begin(), vm_handler.end(), 
				[](const zydis_instr_t& instr_data) -> bool
				{
					// mov/movsx/movzx rax/eax/ax/al, [rsi]
					if (instr_data.instr.operand_count > 1 &&
						(instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOV ||
							instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVSX ||
							instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVZX) &&
						instr_data.instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
						util::reg::to64(instr_data.instr.operands[0].reg.value) == ZYDIS_REGISTER_RAX &&
						instr_data.instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
						instr_data.instr.operands[1].mem.base == ZYDIS_REGISTER_RSI)
						return true;
					return false;
				}
			);

			return result != vm_handler.end();
		}

		std::uint8_t imm_size(const zydis_routine_t& vm_handler)
		{
			const auto result = std::find_if(
				vm_handler.begin(), vm_handler.end(),
				[](const zydis_instr_t& instr_data) -> bool
				{
					// mov/movsx/movzx rax/eax/ax/al, [rsi]
					if (instr_data.instr.operand_count > 1 &&
						(instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOV ||
							instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVSX ||
							instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVZX) &&
						instr_data.instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
						util::reg::to64(instr_data.instr.operands[0].reg.value) == ZYDIS_REGISTER_RAX &&
						instr_data.instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
						instr_data.instr.operands[1].mem.base == ZYDIS_REGISTER_RSI)
						return true;
					return false;
				}
			);

			if (result == vm_handler.end())
				return 0u;

			return result->instr.operands[1].size;
		}

		bool get_operand_transforms(const zydis_routine_t& vm_handler, transform::map_t& transforms)
		{
			auto imm_fetch = std::find_if(
				vm_handler.begin(), vm_handler.end(),
				[](const zydis_instr_t& instr_data) -> bool
				{
					// mov/movsx/movzx rax/eax/ax/al, [rsi]
					if (instr_data.instr.operand_count > 1 &&
						(instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOV ||
							instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVSX ||
							instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOVZX) &&
						instr_data.instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
						util::reg::to64(instr_data.instr.operands[0].reg.value) == ZYDIS_REGISTER_RAX &&
						instr_data.instr.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
						instr_data.instr.operands[1].mem.base == ZYDIS_REGISTER_RSI)
						return true;
					return false;
				}
			);

			if (imm_fetch == vm_handler.end())
				return false;

			// this finds the first transformation which looks like:
			// transform rax, rbx <--- note these registers can be smaller so we to64 them...
			auto key_transform = std::find_if(imm_fetch, vm_handler.end(), 
				[](const zydis_instr_t& instr_data) -> bool 
				{
					if (util::reg::compare(instr_data.instr.operands[0].reg.value, ZYDIS_REGISTER_RAX) &&
						util::reg::compare(instr_data.instr.operands[1].reg.value, ZYDIS_REGISTER_RBX))
						return true;
					return false;
				}
			);

			// last transformation is the same as the first except src and dest are swwapped...
			transforms[transform::type::rolling_key] = key_transform->instr;
			auto instr_copy = key_transform->instr;
			instr_copy.operands[0].reg.value = key_transform->instr.operands[1].reg.value;
			instr_copy.operands[1].reg.value = key_transform->instr.operands[0].reg.value;
			transforms[transform::type::update_key] = instr_copy;

			if (key_transform == vm_handler.end())
				return false;

			// three generic transformations...
			auto generic_transform = key_transform;

			for (auto idx = 0u; idx < 3; ++idx)
			{
				generic_transform = std::find_if(++generic_transform, vm_handler.end(),
					[](const zydis_instr_t& instr_data) -> bool
					{
						if (util::reg::compare(instr_data.instr.operands[0].reg.value, ZYDIS_REGISTER_RAX))
							return true;

						return false;
					}
				);

				if (generic_transform == vm_handler.end())
					return false;

				transforms[(transform::type)(idx + 1)] = generic_transform->instr;
			}

			return true;
		}

		vm::handler::profile_t* get_profile(vm::handler_t& vm_handler)
		{
			static const auto vcontains =
				[](vm::handler::profile_t* vprofile, vm::handler_t* vm_handler) -> bool
			{
				if (vprofile->imm_size != vm_handler->imm_size)
					return false;

				for (auto& instr : vprofile->signature)
				{
					const auto contains = std::find_if
					(
						vm_handler->instrs.begin(),
						vm_handler->instrs.end(),

						[&](zydis_instr_t& instr_data) -> bool
						{
							if (instr_data.raw.size() != instr.size())
								return false;

							return std::equal
							(
								instr_data.raw.begin(),
								instr_data.raw.end(),
								instr.begin()
							);
						}
					);

					if (contains == vm_handler->instrs.end())
						return false;
				}

				return true;
			};

			for (auto profile : vm::handler::profile::all)
				if (vcontains(profile, &vm_handler))
					return profile;

			return nullptr;
		}

		namespace table
		{
			std::uintptr_t* get(const zydis_routine_t& vm_entry)
			{
				const auto result = std::find_if(
					vm_entry.begin(), vm_entry.end(),
					[](const zydis_instr_t& instr_data) -> bool
					{
						const auto instr = &instr_data.instr;
						// lea r12, vm_handlers... (always r12)...
						if (instr->mnemonic == ZYDIS_MNEMONIC_LEA &&
							instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
							instr->operands[0].reg.value == ZYDIS_REGISTER_R12 &&
							!instr->raw.sib.base) // no register used for the sib base...
							return true;

						return false;
					}
				);

				if (result == vm_entry.end())
					return nullptr;

				std::uintptr_t ptr = 0u;
				ZydisCalcAbsoluteAddress(&result->instr,
					&result->instr.operands[1], result->addr, &ptr);

				return reinterpret_cast<std::uintptr_t*>(ptr);
			}

			bool get_transform(const zydis_routine_t& vm_entry, ZydisDecodedInstruction* transform_instr)
			{
				ZydisRegister rcx_or_rdx = ZYDIS_REGISTER_NONE;

				auto handler_fetch = std::find_if(
					vm_entry.begin(), vm_entry.end(),
					[&](const zydis_instr_t& instr_data) -> bool
					{
						const auto instr = &instr_data.instr;
						if (instr->mnemonic == ZYDIS_MNEMONIC_MOV &&
							instr->operand_count == 2 &&
							instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
							instr->operands[1].mem.base == ZYDIS_REGISTER_R12 &&
							instr->operands[1].mem.index == ZYDIS_REGISTER_RAX &&
							instr->operands[1].mem.scale == 8 &&
							instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
							(instr->operands[0].reg.value == ZYDIS_REGISTER_RDX ||
								instr->operands[0].reg.value == ZYDIS_REGISTER_RCX))
						{
							rcx_or_rdx = instr->operands[0].reg.value;
							return true;
						}

						return false;
					}
				);

				// check to see if we found the fetch instruction and if the next instruction
				// is not the end of the vector...
				if (handler_fetch == vm_entry.end() || ++handler_fetch == vm_entry.end() ||
					// must be RCX or RDX... else something went wrong...
					(rcx_or_rdx != ZYDIS_REGISTER_RCX && rcx_or_rdx != ZYDIS_REGISTER_RDX))
					return false;

				// find the next instruction that writes to RCX or RDX...
				// the register is determined by the vm handler fetch above...
				auto handler_transform = std::find_if(
					handler_fetch, vm_entry.end(),
					[&](const zydis_instr_t& instr_data) -> bool
					{
						if (instr_data.instr.operands[0].reg.value == rcx_or_rdx &&
							instr_data.instr.operands[0].actions & ZYDIS_OPERAND_ACTION_WRITE)
							return true;
						return false;
					}
				);

				if (handler_transform == vm_entry.end())
					return false;

				*transform_instr = handler_transform->instr;
				return true;
			}

			std::uint64_t encrypt(ZydisDecodedInstruction& transform_instr, std::uint64_t val)
			{
				assert(transform_instr.operands[0].size == 64,
					"invalid transformation for vm handler table entries...");

				const auto operation = vm::transform::inverse[transform_instr.mnemonic];
				const auto bitsize = transform_instr.operands[0].size;
				const auto imm = vm::transform::has_imm(&transform_instr) ?
					transform_instr.operands[1].imm.value.u : 0u;

				return vm::transform::apply(bitsize, operation, val, imm);
			}

			std::uint64_t decrypt(ZydisDecodedInstruction& transform_instr, std::uint64_t val)
			{
				assert(transform_instr.operands[0].size == 64,
					"invalid transformation for vm handler table entries...");

				const auto operation = transform_instr.mnemonic;
				const auto bitsize = transform_instr.operands[0].size;
				const auto imm = vm::transform::has_imm(&transform_instr) ?
					transform_instr.operands[1].imm.value.u : 0u;

				return vm::transform::apply(bitsize, operation, val, imm);
			}
		}
	}
}