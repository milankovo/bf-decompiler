#-------------------------------------------------------------------------------
#
# IDAPython script that adds brainfuck language to the hex-rays decompiler
#
# Copyright (c) 2020, Milankovo
# Licensed under the GNU GPL v3.
#
#-------------------------------------------------------------------------------

from __future__ import print_function
import ida_xref
import ida_idp
import ida_bytes
import ida_allins
import ida_ua
import ida_hexrays
import ida_typeinf

chars = "><+-.,[]"
chars_ord = map(ord, chars)

ITYPES = []
ITYPETOCHAR = {}
CHARTOITYPE = {}
for i, ch in enumerate(chars_ord):
    ITYPES.append(ida_idp.CUSTOM_INSN_ITYPE + i)
    ITYPETOCHAR[ida_idp.CUSTOM_INSN_ITYPE + i] = chars[i]
    CHARTOITYPE[ch] = ida_idp.CUSTOM_INSN_ITYPE + i

ITYPE_BUGINSN = ida_idp.CUSTOM_INSN_ITYPE
MNEM_WIDTH = 16

"""
>	posun datového ukazatele o jednu buňku doprava	                                                                        ++ptr;	Inc(Ptr);
<	posun datového ukazatele o jednu buňku doleva	                                                                        --ptr;	Dec(Ptr);
+	zvýšení hodnoty aktivní buňky o 1 (buňky, nad kterou je ukazatel)                                                   	++*ptr;	Inc(Ptr^);
-	snížení hodnoty aktivní buňky o 1	                                                                                    --*ptr	Dec(Ptr^);
.	výpis hodnoty aktivní buňky na standardní výstup (v drtivé většině případů na obrazovku).
Pro výpis se používá hodnota aktivní buňky převedená dle kódování ASCII na znak.                                        	putchar(*ptr);	Write(Char(Ptr^));
,	uložení hodnoty ze vstupu do aktivní buňky	                                                                            *ptr=getchar();	Read(Char(Ptr^));
[	pokud je hodnota aktivní buňky rovna nule, provede přesun instrukčního ukazatele doprava za odpovídající ]	            while (*ptr) {	while Ptr^ <> 0 do begin
]	pokud je hodnota aktivní buňky různá od nuly, provede přesun instrukčního ukazatele doleva na odpovídající [	        }	end;

"""


#out_tif = ida_typeinf.tinfo_t()
#ida_typeinf.parse_decl(out_tif, None, "void __usercall __spoils<> out(char ch@<bl>);", ida_typeinf.PT_TYP)


class bf_idp_hook(ida_idp.IDP_Hooks):

    def __init__(self):
        ida_idp.IDP_Hooks.__init__(self)
        self.reported = []

    def ev_ana_insn(self, insn):
        b = ida_bytes.get_wide_byte(insn.ea)

        if b == ord(">"):
            insn_inc(insn)
            return insn.size

        if b == ord("<"):
            insn_dec(insn)
            return insn.size

        #if b == ord("+"):
        #    # insn_movzx(insn)
        #    insn_mem_store(insn)
        #    return insn.size
        if b == ord('['):
            depth = 0
            ea = insn.ea + 1
            #TODO change the constant
            while ea < 1000:
                b1 = ida_bytes.get_wide_byte(ea)
                if b1 == ord('['):
                    depth += 1
                if b1 == ord(']'):
                    if depth == 0:
                        break
                    depth -= 1
                ea += 1
            if ea != 1000:
                op1_addr(insn, ea+1)
            #return insn.size


        if b == ord(']'):
            depth = 0
            ea = insn.ea - 1 
            #TODO change the constant
            while ea >= 0:
                b1 = ida_bytes.get_wide_byte(ea)
                if b1 == ord(']'):
                    depth += 1
                if b1 == ord('['):
                    if depth == 0:
                        break
                    depth -= 1
                ea -= 1
            if ea != -1:
                op1_addr(insn, ea)
            #return insn.size

        if b == ord('+'):
            insn.itype = CHARTOITYPE[b]
            ea = insn.ea + 1
            insn.size = 1
            while ida_bytes.get_wide_byte(ea) == ord('+'):
                insn.size += 1
                ea += 1
            if insn.size != 1:
                op1_num(insn, insn.size)
            
            return insn.size

        if b == ord('-'):
            insn.itype = CHARTOITYPE[b]
            ea = insn.ea + 1
            insn.size = 1
            while ida_bytes.get_wide_byte(ea) == ord('-'):
                insn.size += 1
                ea += 1
            if insn.size != 1:
                op1_num(insn, insn.size)
            
            return insn.size


        if b in chars_ord:
            insn.itype = CHARTOITYPE[b]
            insn.size = 1
            return insn.size

        insn.itype = ida_allins.NN_nop
        insn.size = 1
        return insn.size

    def ev_emu_insn(self, insn):
        if insn.itype in ITYPES:
            #print("emu %x"%insn.ea)
            ida_ua.insn_add_cref(insn, insn.ea + insn.size, 0, ida_xref.fl_F)

            if insn.Op1.type == 0x7:
                ida_ua.insn_add_cref(insn, insn.Op1.addr, 0, ida_xref.fl_JN)
                #out_custom_mnem("%03x" % (outctx.insn.Op1.addr), MNEM_WIDTH)
            #print("em2 %x"%insn.ea)
            return 1
        return 0

    def ev_out_mnem(self, outctx):
        if outctx.insn.itype in ITYPES:
            outctx.out_custom_mnem(ITYPETOCHAR[outctx.insn.itype], MNEM_WIDTH)
            #outctx.out_custom_mnem(hex(outctx.insn.itype), MNEM_WIDTH)
            #outctx.out_custom_mnem("%03x" % (outctx.insn.ea), MNEM_WIDTH)
            #out.Op1.type = 0x7 # o_near
            #if outctx.insn.Op1.type == 0x7:
            #    outctx.out_custom_mnem("%03x" % (outctx.insn.Op1.addr), MNEM_WIDTH)
            return 1

        return 0


def insn_movzx(out):
    #out = ida_ua.insn_t()
    out.size = 0x1
    
    out.itype = 0x7e  # NN_movzx
    out.auxpref = 0x1808
    out.segpref = chr(0x0)
    out.insnpref = chr(0x0)
    out.flags = 0

    out.Op1.type = 0x1  # o_reg
    out.Op1.offb = 0x0
    out.Op1.offo = 0x0
    out.Op1.flags = 0x8
    out.Op1.dtype = 0x2  # dt_dword
    out.Op1.reg = ida_idp.str2reg('ebx')

    out.Op2.type = 0x3  # o_phrase
    out.Op2.offb = 0x0
    out.Op2.offo = 0x0
    out.Op2.flags = 0x8
    out.Op2.dtype = 0x0  # dt_3byte,dt_byte
    out.Op2.reg = ida_idp.str2reg('eax')  # cl

    out.Op2.specval = 0x200000
    return out


def insn_inc(out):
    out.size = 0x1
    out.itype = ida_allins.NN_inc  # NN_inc
    out.auxpref = 0x1810
    out.segpref = chr(0x0)
    out.insnpref = chr(0x0)
    out.flags = 0

    out.Op1.type = 0x1  # o_reg
    out.Op1.offb = 0x0
    out.Op1.offo = 0x0
    out.Op1.flags = 0x8
    out.Op1.dtype = 0x2  # dt_dword
    out.Op1.reg = ida_idp.str2reg('eax')  # eax


def insn_dec(out):
    out.size = 0x1
    out.itype = ida_allins.NN_dec  # NN_inc
    out.auxpref = 0x1810
    out.segpref = chr(0x0)
    out.insnpref = chr(0x0)
    out.flags = 0

    out.Op1.type = 0x1  # o_reg
    out.Op1.offb = 0x0
    out.Op1.offo = 0x0
    out.Op1.flags = 0x8
    out.Op1.dtype = 0x2  # dt_dword
    out.Op1.reg = ida_idp.str2reg('eax')  # eax


def op1_addr(out, dst):
    out.Op1.type = 0x7 # o_near
    out.Op1.offb = 0x1
    out.Op1.offo = 0x0
    out.Op1.flags = 0x8
    out.Op1.dtype = 0x0 # dt_3byte,dt_byte
    out.Op1.reg = 0x0  #al
    out.Op1.phrase = 0x0
    out.Op1.value = 0x0
    out.Op1.addr = dst
    out.Op1.specval = 0x1e0000
    out.Op1.specflag1 = 0x0
    out.Op1.specflag2 = 0x0
    out.Op1.specflag3 = 0x0
    out.Op1.specflag4 = 0x0    

def op1_num(out, n):
    out.Op1.type = 0x5 # o_imm
    out.Op1.offb = 0x2
    out.Op1.offo = 0x0
    out.Op1.flags = 0x8
    out.Op1.dtype = 0x0 
    out.Op1.reg = 0x0  
    out.Op1.phrase = 0x0
    out.Op1.value = n
    out.Op1.addr = 0x0
    out.Op1.specval = 0x0
    out.Op1.specflag1 = 0x0
    out.Op1.specflag2 = 0x0
    out.Op1.specflag3 = 0x0
    out.Op1.specflag4 = 0x0

def insn_jz(out, dst):
    
    out.itype = 0x55 # NN_jz
    out.auxpref = 0x1808
    out.segpref = chr(0x0)
    out.insnpref = chr(0x0)
    out.flags = 0

    out.Op1.type = 0x7 # o_near
    out.Op1.offb = 0x1
    out.Op1.offo = 0x0
    out.Op1.flags = 0x8
    out.Op1.dtype = 0x0 # dt_3byte,dt_byte
    out.Op1.reg = 0x0  #al
    out.Op1.phrase = 0x0
    out.Op1.value = 0x0
    out.Op1.addr = dst
    out.Op1.specval = 0x1e0000
    out.Op1.specflag1 = 0x0
    out.Op1.specflag2 = 0x0
    out.Op1.specflag3 = 0x0
    out.Op1.specflag4 = 0x0    

def insn_jnz(out, dst):
   
    out.itype = 0x4f # NN_jnz
    out.auxpref = 0x1808
    out.segpref = chr(0x0)
    out.insnpref = chr(0x0)
    out.flags = 0

    out.Op1.type = 0x7 # o_near
    out.Op1.offb = 0x1
    out.Op1.offo = 0x0
    out.Op1.flags = 0x8
    out.Op1.dtype = 0x0 # dt_3byte,dt_byte
    out.Op1.reg = 0x0  #al
    out.Op1.phrase = 0x0
    out.Op1.value = 0x0
    out.Op1.addr = dst
    out.Op1.specval = 0x1e0000
    out.Op1.specflag1 = 0x0
    out.Op1.specflag2 = 0x0
    out.Op1.specflag3 = 0x0
    out.Op1.specflag4 = 0x0    


def insn_cmp_bl(out):
    #cmp     bl, 0
    out.size = 0x1
    
    out.itype = 0x1b # NN_cmp
    out.auxpref = 0x1808
    out.segpref = chr(0x0)
    out.insnpref = chr(0x0)
    out.flags = 0

    out.Op1.type = 0x1 # o_reg
    out.Op1.offb = 0x0
    out.Op1.offo = 0x0
    out.Op1.flags = 0x8
    out.Op1.dtype = 0x2 # dt_dword
    out.Op1.reg = ida_idp.str2reg('ebx')  #bl    
    out.Op1.value = 0x0
    out.Op1.addr = 0x0
    out.Op1.specval = 0x0
    out.Op1.specflag1 = 0x0
    out.Op1.specflag2 = 0x0
    out.Op1.specflag3 = 0x0
    out.Op1.specflag4 = 0x0

    out.Op2.type = 0x5 # o_imm
    out.Op2.offb = 0x2
    out.Op2.offo = 0x0
    out.Op2.flags = 0x8
    out.Op2.dtype = 0x2 # dt_3byte,dt_byte
    out.Op2.reg = 0x0  #al
    out.Op2.phrase = 0x0
    out.Op2.value = 0x0
    out.Op2.addr = 0x0
    out.Op2.specval = 0x0
    out.Op2.specflag1 = 0x0
    out.Op2.specflag2 = 0x0
    out.Op2.specflag3 = 0x0
    out.Op2.specflag4 = 0x0

def insn_mem_store(out):
    #mov     [rax], r12

    out.size = 0x1
    out.itype = 0x7a  # NN_mov
    out.auxpref = 0x1808
    out.segpref = chr(0x0)
    out.insnpref = chr(0x0)
    out.flags = 0

    out.Op1.type = 0x3  # o_phrase
    out.Op1.offb = 0x0
    out.Op1.offo = 0x0
    out.Op1.flags = 0x8
    out.Op1.dtype = 0x0  # dt_byte
    out.Op1.reg = ida_idp.str2reg('eax')  # rax
    out.Op1.phrase = 0x0
    out.Op1.value = 0x0
    out.Op1.addr = 0x0
    out.Op1.specval = 0x200000
    
    
    out.Op2.type = 0x1  # o_reg
    out.Op2.offb = 0x0
    out.Op2.offo = 0x0
    out.Op2.flags = 0x8
    out.Op2.dtype = 0x0  # dt_byte
    out.Op2.reg = ida_idp.str2reg('bl')  # r12


def mk_regop(r):
    op1 = ida_hexrays.mop_t()
    if isinstance(r, str):
        rr = ida_hexrays.reg2mreg(ida_idp.str2reg(r))
    elif isinstance(r, int):
        rr = r
    else:
        assert False
    op1.make_reg(rr, 4)
    return op1


def mk_num(nn):
    op1 = ida_hexrays.mop_t()
    op1.make_number(nn, 4)
    return op1


def mk_push(cdg, r):
    op1 = mk_regop(r)
    cdg.emit(ida_hexrays.m_push, op1, None, None)


def mk_inc(cdg, regname='eax', n=1):
    op1 = mk_regop(regname)
    op2 = mk_num(n)
    cdg.emit(ida_hexrays.m_add, op1, op2, op1)


def mk_dec(cdg, regname='eax', n=1):
    op1 = mk_regop(regname)
    op2 = mk_num(n)
    cdg.emit(ida_hexrays.m_sub, op1, op2, op1)

def mk_out(cdg, regname='eax'):
    op1 = ida_hexrays.mop_t()
    op1.make_helper("out")
    #op1.size = 1
    #print("op1 size: ", op1.size)# = -1

    opd = ida_hexrays.mop_t()
    #opd.erase()

    out_tif = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(out_tif, None, "void __usercall __spoils<> out(char ch@<bl>);", 0)

    cif = ida_hexrays.mcallinfo_t()
    cif.set_type(out_tif)
    opd._make_callinfo(cif)
    #opd.t = ida_hexrays.mop_f
    opd.size = 0
    cif.args[0].make_reg(  ida_hexrays.reg2mreg(ida_idp.str2reg('bl'))  , 1)
    #print(opd.dstr())
    

    cdg.emit(ida_hexrays.m_call, op1, None, opd)

def mk_in(cdg, regname='eax'):
    op1 = ida_hexrays.mop_t()
    op1.make_helper("in")
    #op1.size = 1
    #print("op1 size: ", op1.size)# = -1

    opd = ida_hexrays.mop_t()
    #opd.erase()

    out_tif = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(out_tif, None, "char __usercall __spoils<> in@<bl>();", 0)

    cif = ida_hexrays.mcallinfo_t()
    cif.set_type(out_tif)


    retu = ida_hexrays.mop_t()
    retu.make_reg(  ida_hexrays.reg2mreg(ida_idp.str2reg('bl'))  , 1)

    cif.retregs.push_back(retu)
    #print(dir(cif.retregs))
    cif.return_regs.add( ida_hexrays.reg2mreg(ida_idp.str2reg('bl')) , 1 )
    cif.spoiled.add( ida_hexrays.reg2mreg(ida_idp.str2reg('bl')) , 1 )
    

    opd._make_callinfo(cif)
    
    opd.size = 1
    #cif.args[0].make_reg(  ida_hexrays.reg2mreg(ida_idp.str2reg('bl'))  , 1)
    #print(opd.dstr())    

    cdg.emit(ida_hexrays.m_call, op1, None, opd)

def mk_nop(cdg):
    cdg.emit(ida_hexrays.m_nop, None, None, None)
    #backup = cdg.insn
    # cdg.insn = *other
    #cdg.insn.ea = backup.ea
    #m_in_recursion_trick = true
    # merror_t result = cdg.gen_micro()


class bf_microcode_filter_t(ida_hexrays.microcode_filter_t):
    def __init__(self):
        ida_hexrays.microcode_filter_t.__init__(self)

    def match(self, cdg):
        #print("matching at %03x"%cdg.insn.ea)
        if cdg.insn.itype not in ITYPES:
            return False
        # return True
        return True

    def apply(self, cdg):
        """
  /// Emit one microinstruction.
  /// The L, R, D arguments usually mean the register number. However, they depend
  /// on CODE. For example:
  ///   - for m_goto and m_jcnd L is the target address
  ///   - for m_ldc L is the constant value to load
  /// \\param code  instruction opcode
  /// \\param width operand size in bytes
  /// \\param l     left operand
  /// \\param r     right operand
  /// \\param d     destination operand
  /// \\param offsize for ldx/stx, the size of the offset operand
  ///                for ldc, operand number of the constant value
  ///                -1, set the FP instruction (e.g. for m_mov)
  /// \\return created microinstruction. can be NULL if the instruction got
  ///         immediately optimized away.
  minsn_t *hexapi emit(mcode_t code, int width, uval_t l, uval_t r, uval_t d, int offsize);
        """
        #print("applying at %03x" % cdg.insn.ea)
        try:
            #r = ida_hexrays.reg2mreg(ida_idp.str2reg('eax'))
            itype = cdg.insn.itype

            if itype == ida_allins.NN_nop:
                mk_nop(cdg)
                return ida_hexrays.MERR_OK

            ch = ITYPETOCHAR[itype]
            """
            m_add    = 0x0C, // add  l,   r,      d       // l + r -> dst
            m_sub    = 0x0D, // sub  l,   r,      d       // l - r -> dst
            """
            if ch == '>':
                mk_inc(cdg)
                return ida_hexrays.MERR_OK
            elif ch == '<':
                mk_dec(cdg)
                return ida_hexrays.MERR_OK
            elif ch == ".":
                #print("emulating .")
                insn_movzx(cdg.insn)
                cdg.gen_micro()
                mk_out(cdg)
                return ida_hexrays.MERR_OK

            elif ch == ",":
                #print("emulating ,")
                mk_in(cdg)
                insn_mem_store(cdg.insn)
                cdg.gen_micro()
                return ida_hexrays.MERR_OK            

            elif ch == '+':
                #print("emulating +")

                n = 1
                if cdg.insn.Op1.type == 0x5:
                    n = cdg.insn.Op1.value
            
                insn_movzx(cdg.insn)
                cdg.gen_micro()
                
                mk_inc(cdg, 'ebx', n=n)
                insn_mem_store(cdg.insn)
                cdg.gen_micro()
                return ida_hexrays.MERR_OK

            elif ch == '-':
                #print("emulating -")
                n = 1
                if cdg.insn.Op1.type == 0x5:
                    n = cdg.insn.Op1.value
                insn_movzx(cdg.insn)
                cdg.gen_micro()
                mk_dec(cdg, 'ebx', n=n)
                insn_mem_store(cdg.insn)
                cdg.gen_micro()
                return ida_hexrays.MERR_OK
            elif ch == ']':
                #print("emulating ]")
                dst = cdg.insn.Op1.addr
                insn_movzx(cdg.insn)
                cdg.gen_micro()
                
                insn_cmp_bl(cdg.insn)
                cdg.gen_micro()

                insn_jnz(cdg.insn, dst)
                cdg.gen_micro()
                return ida_hexrays.MERR_OK

            elif ch == '[':
                #print("emulating [")
                dst = cdg.insn.Op1.addr
                insn_movzx(cdg.insn)
                cdg.gen_micro()
                
                insn_cmp_bl(cdg.insn)
                cdg.gen_micro()

                insn_jz(cdg.insn, dst)
                cdg.gen_micro()
                return ida_hexrays.MERR_OK

            else:
                #mk_nop(cdg)
                return ida_hexrays.MERR_INSN

            pass
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(e)

        return ida_hexrays.MERR_INSN

    def install(self):
        ida_hexrays.install_microcode_filter(self, True)
        self.installed = True

    def uninstall(self):
        ida_hexrays.install_microcode_filter(self, False)
        self.installed = False

    def toggle_install(self):
        if self.installed:
            self.uninstall()
        else:
            self.install()


class udc_out_t(ida_hexrays.udc_filter_t):
    def __init__(self):
        ida_hexrays.udc_filter_t.__init__(self)
        if not self.init("void __usercall __spoils<> out(char ch@<bl>);"):
            raise Exception("Couldn't initialize udc_out_t instance")
        self.installed = False

    def match(self, cdg):
        if cdg.insn.itype not in ITYPES:
            return False
        return ITYPETOCHAR[cdg.insn.itype] == '.'

    def install(self):
        ida_hexrays.install_microcode_filter(self, True)
        self.installed = True

    def uninstall(self):
        ida_hexrays.install_microcode_filter(self, False)
        self.installed = False

class udc_in_t(ida_hexrays.udc_filter_t):
    def __init__(self):
        ida_hexrays.udc_filter_t.__init__(self)
        if not self.init("char __usercall __spoils<> in<bl>();"):
            raise Exception("Couldn't initialize udc_in_t instance")
        self.installed = False

    def match(self, cdg):
        if cdg.insn.itype not in ITYPES:
            return False
        return ITYPETOCHAR[cdg.insn.itype] == ','

    def install(self):
        ida_hexrays.install_microcode_filter(self, True)
        self.installed = True

    def uninstall(self):
        ida_hexrays.install_microcode_filter(self, False)
        self.installed = False


def __quick_unload_script():
    global hook
    hook.unhook()
    del hook
    global myfilter
    myfilter.uninstall()
    del myfilter

    #global udc_out
    #udc_out.uninstall()
    #del udc_out
#
    #global udc_in
    #udc_in.uninstall()
    #del udc_in


if __name__ == "__main__":
    print("hooking...")
    if 'myfilter' in globals():
        try:
            myfilter.uninstall()
        except:
            pass

    #if 'udc_out' in globals():
    #    try:
    #        udc_out.uninstall()
    #    except:
    #        pass
#
    #if 'udc_in' in globals():
    if 'hook' in globals():
        try:
            hook.unhook()
        except:
            pass

    

    hook = bf_idp_hook()
    hook.hook()
    myfilter = bf_microcode_filter_t()
    myfilter.install()
