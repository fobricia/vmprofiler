#include "vmutils.h"
#include <Windows.h>

namespace vm
{
    namespace util
    {
        namespace reg
        {
            ZydisRegister to64(ZydisRegister reg)
            {
                switch (reg)
                {
                case ZYDIS_REGISTER_AL:
                    return ZYDIS_REGISTER_RAX;
                case ZYDIS_REGISTER_CL:
                    return ZYDIS_REGISTER_RCX;
                case ZYDIS_REGISTER_DL:
                    return ZYDIS_REGISTER_RDX;
                case ZYDIS_REGISTER_BL:
                    return ZYDIS_REGISTER_RBX;
                case ZYDIS_REGISTER_AH:
                    return ZYDIS_REGISTER_RAX;
                case ZYDIS_REGISTER_CH:
                    return ZYDIS_REGISTER_RCX;
                case ZYDIS_REGISTER_DH:
                    return ZYDIS_REGISTER_RDX;
                case ZYDIS_REGISTER_BH:
                    return ZYDIS_REGISTER_RBX;
                case ZYDIS_REGISTER_SPL:
                    return ZYDIS_REGISTER_RSP;
                case ZYDIS_REGISTER_BPL:
                    return ZYDIS_REGISTER_RBP;
                case ZYDIS_REGISTER_SIL:
                    return ZYDIS_REGISTER_RSI;
                case ZYDIS_REGISTER_DIL:
                    return ZYDIS_REGISTER_RDI;
                case ZYDIS_REGISTER_R8B:
                    return ZYDIS_REGISTER_R8;
                case ZYDIS_REGISTER_R9B:
                    return ZYDIS_REGISTER_R9;
                case ZYDIS_REGISTER_R10B:
                    return ZYDIS_REGISTER_R10;
                case ZYDIS_REGISTER_R11B:
                    return ZYDIS_REGISTER_R11;
                case ZYDIS_REGISTER_R12B:
                    return ZYDIS_REGISTER_R12;
                case ZYDIS_REGISTER_R13B:
                    return ZYDIS_REGISTER_R13;
                case ZYDIS_REGISTER_R14B:
                    return ZYDIS_REGISTER_R14;
                case ZYDIS_REGISTER_R15B:
                    return ZYDIS_REGISTER_R15;
                case ZYDIS_REGISTER_AX:
                    return ZYDIS_REGISTER_RAX;
                case ZYDIS_REGISTER_CX:
                    return ZYDIS_REGISTER_RCX;
                case ZYDIS_REGISTER_DX:
                    return ZYDIS_REGISTER_RDX;
                case ZYDIS_REGISTER_BX:
                    return ZYDIS_REGISTER_RBX;
                case ZYDIS_REGISTER_SP:
                    return ZYDIS_REGISTER_RSP;
                case ZYDIS_REGISTER_BP:
                    return ZYDIS_REGISTER_RBP;
                case ZYDIS_REGISTER_SI:
                    return ZYDIS_REGISTER_RSI;
                case ZYDIS_REGISTER_DI:
                    return ZYDIS_REGISTER_RDI;
                case ZYDIS_REGISTER_R8W:
                    return ZYDIS_REGISTER_R8;
                case ZYDIS_REGISTER_R9W:
                    return ZYDIS_REGISTER_R9;
                case ZYDIS_REGISTER_R10W:
                    return ZYDIS_REGISTER_R10;
                case ZYDIS_REGISTER_R11W:
                    return ZYDIS_REGISTER_R11;
                case ZYDIS_REGISTER_R12W:
                    return ZYDIS_REGISTER_R12;
                case ZYDIS_REGISTER_R13W:
                    return ZYDIS_REGISTER_R13;
                case ZYDIS_REGISTER_R14W:
                    return ZYDIS_REGISTER_R14;
                case ZYDIS_REGISTER_R15W:
                    return ZYDIS_REGISTER_R15;
                case ZYDIS_REGISTER_EAX:
                    return ZYDIS_REGISTER_RAX;
                case ZYDIS_REGISTER_ECX:
                    return ZYDIS_REGISTER_RCX;
                case ZYDIS_REGISTER_EDX:
                    return ZYDIS_REGISTER_RDX;
                case ZYDIS_REGISTER_EBX:
                    return ZYDIS_REGISTER_RBX;
                case ZYDIS_REGISTER_ESP:
                    return ZYDIS_REGISTER_RSP;
                case ZYDIS_REGISTER_EBP:
                    return ZYDIS_REGISTER_RBP;
                case ZYDIS_REGISTER_ESI:
                    return ZYDIS_REGISTER_RSI;
                case ZYDIS_REGISTER_EDI:
                    return ZYDIS_REGISTER_RDI;
                case ZYDIS_REGISTER_R8D:
                    return ZYDIS_REGISTER_R8;
                case ZYDIS_REGISTER_R9D:
                    return ZYDIS_REGISTER_R9;
                case ZYDIS_REGISTER_R10D:
                    return ZYDIS_REGISTER_R10;
                case ZYDIS_REGISTER_R11D:
                    return ZYDIS_REGISTER_R11;
                case ZYDIS_REGISTER_R12D:
                    return ZYDIS_REGISTER_R12;
                case ZYDIS_REGISTER_R13D:
                    return ZYDIS_REGISTER_R13;
                case ZYDIS_REGISTER_R14D:
                    return ZYDIS_REGISTER_R14;
                case ZYDIS_REGISTER_R15D:
                    return ZYDIS_REGISTER_R15;
                }
                return reg;
            }

            bool compare(ZydisRegister a, ZydisRegister b)
            {
                return to64(a) == to64(b);
            }
        }
        
        void print(const ZydisDecodedInstruction& instr)
        {
            char buffer[256];
            ZydisFormatter formatter;
            ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
            ZydisFormatterFormatInstruction(&formatter, &instr,
                buffer, sizeof(buffer), 0u);

            puts(buffer);
        }

        void print(zydis_routine_t& routine)
        {
            char buffer[256];
            ZydisFormatter formatter;
            ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

            for (auto [instr, raw, addr] : routine)
            {
                std::printf("> 0x%p ", addr);
                ZydisFormatterFormatInstruction(&formatter, &instr,
                    buffer, sizeof(buffer), addr);

                puts(buffer);
            }
        }

        bool is_jmp(const ZydisDecodedInstruction& instr)
        {
            switch (instr.mnemonic)
            {
                case ZYDIS_MNEMONIC_JB:
                case ZYDIS_MNEMONIC_JBE:
                case ZYDIS_MNEMONIC_JCXZ:
                case ZYDIS_MNEMONIC_JECXZ:
                case ZYDIS_MNEMONIC_JKNZD:
                case ZYDIS_MNEMONIC_JKZD:
                case ZYDIS_MNEMONIC_JL:
                case ZYDIS_MNEMONIC_JLE:
                case ZYDIS_MNEMONIC_JMP:
                case ZYDIS_MNEMONIC_JNB:
                case ZYDIS_MNEMONIC_JNBE:
                case ZYDIS_MNEMONIC_JNL:
                case ZYDIS_MNEMONIC_JNLE:
                case ZYDIS_MNEMONIC_JNO:
                case ZYDIS_MNEMONIC_JNP:
                case ZYDIS_MNEMONIC_JNS:
                case ZYDIS_MNEMONIC_JNZ:
                case ZYDIS_MNEMONIC_JO:
                case ZYDIS_MNEMONIC_JP:
                case ZYDIS_MNEMONIC_JRCXZ:
                case ZYDIS_MNEMONIC_JS:
                case ZYDIS_MNEMONIC_JZ:
                    return true;
                default:
                    break;
            }
            return false;
        }

        bool flatten(zydis_routine_t& routine, std::uintptr_t routine_addr, bool keep_jmps)
        {
            ZydisDecoder decoder;
            ZydisDecodedInstruction instr;
            ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
            
            while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, reinterpret_cast<void*>(
                routine_addr), 0x1000, &instr)))
            {
                std::vector<u8> raw_instr;
                raw_instr.insert(raw_instr.begin(),
                    (u8*)routine_addr,
                    (u8*)routine_addr + instr.length);

                if (is_jmp(instr))
                {
                    if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                    {
                        routine.push_back({ instr, raw_instr, routine_addr });
                        return true;
                    }

                    if (keep_jmps)
                        routine.push_back({ instr, raw_instr, routine_addr });

                    ZydisCalcAbsoluteAddress(&instr, &instr.operands[0], routine_addr, &routine_addr);
                }
                else if (instr.mnemonic == ZYDIS_MNEMONIC_RET)
                {
                    routine.push_back({ instr, raw_instr, routine_addr });
                    return true;
                }
                else
                {
                    routine.push_back({ instr, raw_instr, routine_addr });
                    routine_addr += instr.length;
                }
            }
            return false;
        }

        void deobfuscate(zydis_routine_t& routine)
        {
            static const auto _uses =
                [](ZydisDecodedOperand& op, ZydisRegister reg) -> bool
            {
                switch (op.type)
                {
                    case ZYDIS_OPERAND_TYPE_MEMORY:
                    {
                        return reg::compare(op.mem.base, reg) || reg::compare(op.mem.index, reg);
                    }
                    case ZYDIS_OPERAND_TYPE_REGISTER:
                    {
                        return reg::compare(op.reg.value, reg);
                    }
                }

                return false;
            };

            static const auto _writes =
                [](ZydisDecodedInstruction& inst) -> bool
            {
                for (auto idx = 0; idx < inst.operand_count; ++idx)
                    if (inst.operands[idx].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                        return true;

                return false;
            };

            static const auto _remove =
                [](zydis_routine_t& routine, zydis_routine_t::iterator itr,
                    ZydisRegister reg, u32 opcode_size) -> void
            {
                for (; itr >= routine.begin(); --itr)
                {
                    const auto instruction = &itr->instr;
                    bool stop = false;

                    if (instruction->mnemonic == ZYDIS_MNEMONIC_JMP)
                        continue;

                    for (auto op_idx = 0u; op_idx < instruction->operand_count; ++op_idx)
                    {
                        const auto op = &instruction->operands[op_idx];

                        if (!_uses(*op, reg))
                            continue;

                        if (op->type == ZYDIS_OPERAND_TYPE_MEMORY)
                        {
                            stop = true;
                            continue;
                        }

                        if (opcode_size < 32 && op->size > opcode_size)
                            continue;

                        if (op->actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                            op->actions &= ~ZYDIS_OPERAND_ACTION_MASK_WRITE;
                        else stop = true;
                    }

                    if (!_writes(*instruction))
                        routine.erase(itr);

                    else if (stop) break;
                }
            };

            for (const auto& instr_data : routine)
            {
                if (routine.empty() || routine.size() == 1 || 
                    instr_data.instr.mnemonic == ZYDIS_MNEMONIC_JMP)
                    continue;

                for (auto itr = routine.begin() + 1; itr != routine.end(); itr++)
                {
                    if (itr->instr.mnemonic == ZYDIS_MNEMONIC_JMP ||
                        itr->instr.mnemonic == ZYDIS_MNEMONIC_RET)
                        break;

                    // find the write operations that happen...
                    for (auto idx = 0u; idx < itr->instr.operand_count; ++idx)
                    {
                        const auto op = &itr->instr.operands[idx];
                        // if its a read, continue to next opcode...
                        if (op->actions & ZYDIS_OPERAND_ACTION_MASK_READ)
                            continue;

                        // if its not a write then continue to next opcode...
                        if (!(op->actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                            continue;

                        // if this operand is not a register then we continue...
                        if (op->type != ZYDIS_OPERAND_TYPE_REGISTER)
                            continue;

                        // else we see if we can remove dead writes to this register...
                        _remove(routine, itr - 1, op->reg.value, op->size);
                    }
                }
            }
        }
	}
}