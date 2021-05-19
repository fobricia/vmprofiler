#include "vmctx.h"

namespace vm
{
	vmctx_t::vmctx_t(
		vmp2::file_header* file_header,
		vmp2::entry_t* entry_list,
		std::vector<vm::handler_t>& vm_handlers,
		std::uintptr_t module_base,
		std::uintptr_t image_base
	)
		: module_base(module_base),
		image_base(image_base),
		entry_list(entry_list),
		file_header(file_header),
		vm_handlers(vm_handlers),
		idx(0)
	{}

	std::pair<std::string, const vmp2::entry_t*> vmctx_t::step() const
	{
		if (idx >= file_header->entry_count)
			return {};

		const auto vm_handler = &vm_handlers[entry_list[idx].handler_idx];

		if (vm_handler->imm_size)
		{
			const auto operand = get_imm(file_header->advancement,
				entry_list[idx].vip, vm_handler->imm_size / 8);

			auto transforms = vm_handler->transforms;
			auto [decrypted_operand, rolling_key] =
				vm::decrypt_operand(transforms,
					operand, entry_list[idx].decrypt_key);

			if (vm_handler->profile)
			{
				if (vm_handler->profile->extention == 
					vm::handler::extention_t::sign_extend)
				{
					switch (vm_handler->imm_size)
					{
					case 8:
					{
						if ((u8)(decrypted_operand >> 7))
							decrypted_operand += ~0xFFull;
						break;
					}
					case 16:
					{
						if ((u16)(decrypted_operand >> 15))
							decrypted_operand += ~0xFFFFull;
						break;
					}
					case 32:
					{
						if ((u32)(decrypted_operand >> 31))
							decrypted_operand += ~0xFFFFFFFFull;
						break;
					}
					default:
						throw std::invalid_argument(
							"invalid imm size for sign extention...\n");
					}
				}
			}

			char buff[256];
			if (vm_handler->profile)
			{
				snprintf(buff, sizeof buff, "%s 0x%p", 
					vm_handler->profile->name, decrypted_operand);
			}
			else
			{
				snprintf(buff, sizeof buff, "UNK(%d) 0x%p", 
					entry_list[idx].handler_idx, decrypted_operand);
			}

			return { buff, &entry_list[idx++] };
		}

		if (vm_handler->profile)
			return { vm_handler->profile->name, &entry_list[idx++] };

		char buff[256];
		snprintf(buff, sizeof buff, "UNK(%d)", entry_list[idx++].handler_idx);
		return { buff, &entry_list[idx++] };
	}

	std::uintptr_t vmctx_t::get_imm(vmp2::exec_type_t exec_type_t, 
		std::uint32_t vip_offset, std::uint8_t imm_size) const
	{
		std::uintptr_t operand = 0u;
		if (file_header->advancement == vmp2::exec_type_t::forward)
		{
			const auto operand_ptr =
				reinterpret_cast<void*>((entry_list[idx].vip -
					file_header->module_base) + module_base);

			memcpy(&operand, operand_ptr, imm_size);
		}
		else
		{
			const auto operand_ptr =
				reinterpret_cast<void*>(((entry_list[idx].vip -
					file_header->module_base) + module_base) - imm_size);

			memcpy(&operand, operand_ptr, imm_size);
		}

		return operand;
	}
}