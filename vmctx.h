#pragma once
#include <vm.h>
#include <vmp2.hpp>

namespace vm
{
	class vmctx_t
	{
	public:
		explicit vmctx_t(
			vmp2::file_header* file_header, 
			vmp2::entry_t* entry_list, 
			std::vector<vm::handler_t>& vm_handlers, 
			std::uintptr_t module_base, 
			std::uintptr_t image_base
		);

		std::pair<std::string, const vmp2::entry_t*> step() const;
	private:
		std::uintptr_t get_imm(vmp2::exec_type_t exec_type_t, 
			std::uint32_t vip_offset, std::uint8_t imm_size) const;

		mutable std::uint32_t idx;
		const std::uintptr_t image_base, module_base;
		const vmp2::entry_t* entry_list;
		const vmp2::file_header* file_header;
		std::vector<vm::handler_t> vm_handlers;
	};
}