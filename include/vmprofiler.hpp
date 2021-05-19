#pragma once
#include <transform.hpp>

namespace vm
{
	namespace handler
	{
        enum extention_t
        {
            none,
            sign_extend,
            zero_extend
        };

        struct profile_t
        {
            const char* name;
            u8 imm_size;
            std::vector<std::vector<u8>> signature;
            extention_t extention;
        };

		namespace profile
		{
			// store a value from the stack into scratch register X (RDI+X)...
			// where X is an 8bit immediate value...
			inline vm::handler::profile_t sregq =
			{
				"SREGQ", 8,
				{
					{ 0x48, 0x8B, 0x55, 0x0 },  // mov rdx, [rbp+0]
					{ 0x48, 0x83, 0xC5, 0x8 },  // add rbp, 8
					{ 0x48, 0x89, 0x14, 0x38 }, // mov [rax+rdi], rdx
				}
			};

			inline vm::handler::profile_t sregdw =
			{
				"SREGDW", 8,
				{
					{ 0x8B, 0x55, 0x00 },
					{ 0x48, 0x83, 0xC5, 0x04 },
					{ 0x89, 0x14, 0x38 }
				}
			};

			inline vm::handler::profile_t sregw =
			{
				"SREGW", 8,
				{
					{ 0x66, 0x8B, 0x55, 0x00 },	// mov dx, [rbp]
					{ 0x48, 0x83, 0xC5, 0x02 },	// add rbp, 0x02
					{ 0x66, 0x89, 0x14, 0x38 }	// mov [rax+rdi], dx
				}
			};

			// load scratch register value onto virtual stack...
			inline vm::handler::profile_t lregq =
			{
				"LREGQ", 8,
				{
					{0x48, 0x8B, 0x14, 0x38},	// mov rdx, [rax+rdi]
					{0x48, 0x83, 0xED, 0x08},	// sub rbp, 8
					{0x48, 0x89, 0x55, 0x0}		// mov [rbp+0], rdx
				}
			};

			/*
				> 0x00007FF64724445C mov edx, [rax+rdi*1]
				> 0x00007FF647244463 sub rbp, 0x04
				> 0x00007FF647246333 mov [rbp], edx
			*/
			inline vm::handler::profile_t lregdw =
			{
				"LREGDW", 8,
				{
					{ 0x8B, 0x14, 0x38 },
					{ 0x48, 0x83, 0xED, 0x04 },
					{ 0x89, 0x55, 0x00 }
				}
			};

			// load constant value into stack....
			inline vm::handler::profile_t lconstq =
			{
				"LCONSTQ", 64,
				{
					{0x48, 0x83, 0xED, 0x08},	// sub rbp, 8
					{0x48, 0x89, 0x45, 0x00}	// mov [rbp+0], rax
				}
			};

			// load 1 byte constant zero extended into 2bytes on the stack...
			inline vm::handler::profile_t lconstbzx =
			{
				"LCONSTBZX", 8,
				{
					{0x48, 0x83, 0xED, 0x02},	// sub rbp, 2
					{0x66, 0x89, 0x45, 0x00}	// mov [rbp+0], ax
				}
			};

			inline vm::handler::profile_t lconstbsx =
			{
				"LCONSTBSX", 8,
				{
					{ 0x98 },
					{ 0x48, 0x83, 0xED, 0x04 },
					{ 0x89, 0x45, 0x00 }
				},
				vm::handler::extention_t::sign_extend
			};

			// load 4 byte constant value sign extended qword into vsp...
			inline vm::handler::profile_t lconstbsx1 =
			{
				"LCONSTBSX", 8,
				{
					{0x48, 0x98},					// cdqe
					{0x48, 0x83, 0xED, 0x8},		// sub rbp, 8
					{0x48, 0x89, 0x45, 0x0},		// mov [rbp+0], rax
				},
				vm::handler::extention_t::sign_extend
			};

			// load 4 byte constant value sign extended qword into vsp...
			inline vm::handler::profile_t lconstdsx =
			{
				"LCONSTDSX", 32,
				{
					{0x48, 0x98},					// cdqe
					{0x48, 0x83, 0xED, 0x8},		// sub rbp, 8
					{0x48, 0x89, 0x45, 0x0},		// mov [rbp+0], rax
				},
				vm::handler::extention_t::sign_extend
			};

			// load 2 byte constant value sign extended qword into vsp...
			inline vm::handler::profile_t lconstwsx =
			{
				"LCONSTWSX", 16,
				{
					{0x48, 0x98},					// cdqe
					{0x48, 0x83, 0xED, 0x8},		// sub rbp, 8
					{0x48, 0x89, 0x45, 0x0},		// mov [rbp+0], rax
				},
				vm::handler::extention_t::sign_extend
			};

			inline vm::handler::profile_t lconstw =
			{
				"LCONSTW", 8,
				{
					{ 0x48, 0x83, 0xED, 0x02 },		// sub rbp, 0x02
					{ 0x66, 0x89, 0x45, 0x00 }		// mov [rbp], ax
				}
			};

			inline vm::handler::profile_t lconstdw =
			{
				"LCONSTDW", 32,
				{
					{ 0x48, 0x83, 0xED, 0x04 },
					{ 0x89, 0x45, 0x00 }
				}
			};

			inline vm::handler::profile_t pushvsp =
			{
				"PUSHVSP", 0,
				{
					{0x48, 0x89, 0xE8},				// mov rax, rbp
					{0x48, 0x83, 0xED, 0x08},		// sub rbp, 8
					{0x48, 0x89, 0x45, 0x0}			// mov [rbp+0], rax
				}
			};

			// add two stack values together...
			inline vm::handler::profile_t addq =
			{
				"ADDQ", 0,
				{
					{0x48, 0x1, 0x45, 0x8},		// add [rbp+8], rax
					{0x9C},						// pushfq
					{0x8F, 0x45, 0x0}			// pop qword ptr [rbp+0]
				}
			};

			inline vm::handler::profile_t adddw =
			{
				"ADDDW", 0,
				{
					{ 0x01, 0x45, 0x08 },		// add [rbp+0x08], eax
					{ 0x9C },					// pushfq
					{ 0x8F, 0x45, 0x00 }		// pop [rbp]
				}
			};

			// two qwords on the top of the stack together then not the result...
			// ~(VSP[0] | VSP[1])...
			inline vm::handler::profile_t nandq =
			{
				"NANDQ", 0,
				{
					{0x48, 0x8B, 0x45, 0x0},	// mov rax, [rbp+0]
					{0x48, 0x8B, 0x55, 0x8},	// mov rdx, [rbp+8]
					{0x48, 0xF7, 0xD0},			// not rax
					{0x48, 0xF7, 0xD2},			// not rdx
					{0x48, 0x21, 0xD0},			// and rax, rdx
					{0x48, 0x89, 0x45, 0x8},	// mov [rbp+8], rax
					{0x9C},						// pushfq
					{0x8F, 0x45, 0x0}			// pop qword ptr [rbp+0]
				}
			};

			// leaves the virtual machine...
			inline vm::handler::profile_t vmexit =
			{
				"VMEXIT", 0,
				{
					{0x48, 0x89, 0xec},			// mov rsp, rbp
					{0x9d},						// popfq
					{0xc3}						// ret
				}
			};

			inline vm::handler::profile_t jmp =
			{
				"JMP", 0,
				{
					{ 0x8B, 0x75, 0x00 },		// mov esi, [rbp]
					{ 0x48, 0x01, 0xC6 },		// add rsi, rax
					{ 0x48, 0x89, 0xF3 },		// mov rbx, rsi
					{ 0x48, 0x03, 0x75, 0x00 }	// add rsi, [rbp]
				}
			};

			inline vm::handler::profile_t readw =
			{
				"READW", 0,
				{
					{ 0x48, 0x8B, 0x45, 0x00 },	// mov rax, [rbp]
					{ 0x48, 0x83, 0xC5, 0x06 }, // add rbp, 0x06
					{ 0x36, 0x66, 0x8B, 0x00 }, // mov ax, ss:[rax]
					{ 0x66, 0x89, 0x45, 0x00 }	// mov [rbp], ax
				}
			};

			inline vm::handler::profile_t writeq =
			{
				"WRITEQ", 0,
				{
					{ 0x48, 0x8B, 0x45, 0x00 },	// mov rax, [rbp]
					{ 0x48, 0x8B, 0x55, 0x08 },	// mov rdx, [rbp+0x08]
					{ 0x48, 0x83, 0xC5, 0x10 }, // add rbp, 0x10
					{ 0x36, 0x48, 0x89, 0x10 }, // mov ss:[rax], rdx
				}
			};

			inline vm::handler::profile_t writeq1 =
			{
				"WRITEQ", 0,
				{
					{ 0x48, 0x8B, 0x45, 0x00 },	// mov rax, [rbp]
					{ 0x48, 0x8B, 0x55, 0x08 },	// mov rdx, [rbp+0x08]
					{ 0x48, 0x83, 0xC5, 0x10 }, // add rbp, 0x10
					{ 0x48, 0x89, 0x10 }		// mov [rax], rdx
				}
			};

			inline vm::handler::profile_t shrw =
			{
				"SHRW", 0,
				{
					{ 0x66, 0x8B, 0x45, 0x00 },
					{ 0x8A, 0x4D, 0x02 },
					{ 0x48, 0x83, 0xED, 0x06 },
					{ 0x66, 0xD3, 0xE8 },
					{ 0x66, 0x89, 0x45, 0x08 },
					{ 0x9C },
					{ 0x8F, 0x45, 0x00 }
				}
			};

			inline vm::handler::profile_t shrdw =
			{
				"SHRDW", 0,
				{
					{ 0x8B, 0x45, 0x00 },
					{ 0x8A, 0x4D, 0x04 },
					{ 0x48, 0x83, 0xED, 0x06 },
					{ 0xD3, 0xE8 },
					{ 0x89, 0x45, 0x08 },
					{ 0x9C },
					{ 0x8F, 0x45, 0x00 }
				}
			};

			inline vm::handler::profile_t shrq =
			{
				"SHRQ", 0,
				{
					{ 0x48, 0x8B, 0x45, 0x00 },
					{ 0x8A, 0x4D, 0x08 },
					{ 0x48, 0x83, 0xED, 0x06 },
					{ 0x48, 0xD3, 0xE8 },
					{ 0x48, 0x89, 0x45, 0x08 },
					{ 0x9C },
					{ 0x8F, 0x45, 0x00 },
				}
			};

			inline vm::handler::profile_t nanddw =
			{
				"NANDDW", 0,
				{
					{ 0x48, 0xF7, 0x55, 0x00 }, // not     qword ptr [rbp+0]
					{ 0x8B, 0x45, 0x00 },		// mov     eax, [rbp+0]
					{ 0x48, 0x83, 0xED, 0x04 }, // sub     rbp, 4
					{ 0x21, 0x45, 0x08 },		// and     [rbp+8], eax
					{ 0x9C },					// pushfq
					{ 0x8F, 0x45, 0x00 }		// pop     qword ptr [rbp+0]
				}
			};

			inline vm::handler::profile_t lvsp =
			{
				"LVSP", 0,
				{
					{ 0x48, 0x8B, 0x6D, 0x00 }	// mov rbp, [rbp]
				}
			};

			inline std::vector<vm::handler::profile_t*> all =
			{
				&sregq,
				&lregq,
				&lconstq,
				&lconstdsx,
				&lconstwsx,
				&lconstbzx,
				&addq,
				&nandq,
				&pushvsp,
				&vmexit,
				&jmp,
				&adddw,
				&writeq,
				&sregw,
				&lconstw,
				&shrw,
				&shrq,
				&writeq1,
				&readw,
				&lregdw,
				&shrdw,
				&sregdw,
				&lconstbsx,
				&lconstbsx1,
				&shrq,
				&lvsp,
				&lconstdw,
				&nanddw
			};
		}
	}
}