#include <iostream>
#include <set>
#include <iomanip>
#include <utility>
#include <string>
#include <fstream>
#include <unordered_map>
#include <unistd.h>
#include "pin.H"

using std::cerr;
using std::pair;
using std::endl;
using std::set;
using std::string;
using std::unordered_map;

#define MAX_INLINE_ABLE_RTN_SIZE 0xfff
#define MIN_INLINE_ABLE_RTN_SIZE 0x20


typedef struct {

	unordered_map< ADDRINT, UINT64> call_sites;

}INLINEABLE_RTN_Info;


//typedef struct {
//
//    const& string rtn_name;
//    ADDRINT       source_hot_call_site;
//    ADDRINT       rtn_address;
//
//} INLINE_RTN_Info;

/* ===================================================================== */
/* global variables                                                      */
/* ===================================================================== */

unordered_map< ADDRINT, INLINEABLE_RTN_Info> called_rtns;
set< ADDRINT>                                inlineable_rtns;


/* ===================================================================== */
/* docount functions                                                     */
/* ===================================================================== */

VOID docount_rtn(UINT64* icount) { (*icount)++; }


/* ===================================================================== */
/* Functions.                                                            */
/* ===================================================================== */


VOID Trace(TRACE trace, VOID* v) {

	INS     tail;
	RTN     routine;
	ADDRINT tail_address, branch_target;

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		tail = BBL_InsTail(bbl);

		/* - INS_IsCall(tail): This function checks if the instruction represented by tail is a call instruction.
		   - INS_IsDirecControlFlow(tail): This function checks if the instruction represented by tail is a direct control flow instruction.
			 A direct control flow instruction alters the normal flow of program execution by branching to a different part of the code.
			 It includes instructions like jumps and branches.
			 In other words, it checks if tail is a direct control flow instruction that is a call instruction.*/

		if (INS_IsCall(tail) && INS_IsDirectControlFlow(tail)) {

			//  check for valid routine.
			tail_address = INS_Address(tail);
			routine = RTN_FindByAddress(tail_address);
			if (!RTN_Valid(routine)) {
				continue;
			}

			//routine_address = RTN_Address(routine);
			IMG img = IMG_FindByAddress(tail_address);
			if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
				continue;
			}

			branch_target = INS_DirectControlFlowTargetAddress(tail);
			if (!RTN_Valid(RTN_FindByAddress(branch_target))) {
				std::cout << "invalid rtn target at 0x" << branch_target << std::endl;
				continue;
			}

			/* first call of a function (rtn) */
			if (called_rtns.find(branch_target) == called_rtns.end()) {

				INLINEABLE_RTN_Info rtn_call_site;
				rtn_call_site.call_sites = { { tail_address , 0} };
				called_rtns[branch_target] = rtn_call_site;
			}
			INS_InsertCall(tail, IPOINT_BEFORE, (AFUNPTR)docount_rtn, IARG_PTR, &(called_rtns[branch_target].call_sites[tail_address]), IARG_END);
		}
	}
}

VOID Routine(RTN rtn, VOID* v)
{
	if (!RTN_Valid(rtn) || !IMG_IsMainExecutable(SEC_Img(RTN_Sec(rtn))))
		return;

	if (RTN_Name(rtn).find("plt") != std::string::npos)
		return;

	RTN_Open(rtn);
	ADDRINT rtn_address, tail_address;
	rtn_address = RTN_Address(rtn);
	tail_address = INS_Address(RTN_InsTail(rtn));

	/*if (rtn_address == 0x40c2bb) {
		std::ofstream debug1Err;
		debug1Err.open("debug1Err.txt");
		debug1Err << "0x40c2bb" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			debug1Err << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		return;
	}
	if (rtn_address == 0x40c330) {
		std::ofstream debug2Err;
		debug2Err.open("debug2Err.txt");
		debug2Err << "0x40c330" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			debug2Err << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		return;
	}
	if (rtn_address == 0x407cd0) {
		std::ofstream debug1Works;
		debug1Works.open("debug1Works.txt");
		debug1Works << "0x407cd0" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			debug1Works << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		return;
	}
	if (rtn_address == 0x405a4b) {
		std::ofstream debug2Works;
		debug2Works.open("debug2Works.txt");
		debug2Works << "0x405a4b" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			debug2Works << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		return;
	}
	if (rtn_address == 0x406e3b) {
		std::ofstream debug3Works;
		debug3Works.open("debug3Works.txt");
		debug3Works << "0x406e3b" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			debug3Works << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		return;
	}
	if (rtn_address == 0x407da4) {
		std::ofstream debug4Works;
		debug4Works.open("debug4Works.txt");
		debug4Works << "0x407da4" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			debug4Works << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		return;
	}
	if (rtn_address == 0x40c144) {
		std::ofstream debug5Works;
		debug5Works.open("debug5Works.txt");
		debug5Works << "0x40c144" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			debug5Works << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		return;
	}
	if (rtn_address == 0x40c1e8) {
		std::ofstream fuckingaddress;
		fuckingaddress.open("fuckingaddress.txt");
		fuckingaddress << "0x40c1e8" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			fuckingaddress << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		return;
	}*/

	/*if (rtn_address == 0x62e860) {
		std::ofstream cc1Works;
		cc1Works.open("cc1Works.txt");
		cc1Works << "0x62e860" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			cc1Works << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		cc1Works.close();
		return;
	}
	if (rtn_address == 0x483d40) {
		std::ofstream cc2Works;
		cc2Works.open("cc2Works.txt");
		cc2Works << "0x483d40" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			cc2Works << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		cc2Works.close();
		return;
	}
	if (rtn_address == 0x44a4b0) {
		std::ofstream cc1Prob;
		cc1Prob.open("cc1Prob.txt");
		cc1Prob << "0x44a4b0" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			cc1Prob << INS_Disassemble(instruction) << std::endl;
		}
		RTN_Close(rtn);
		cc1Prob.close();
		return;
	}*/

	if (rtn_address == 0x62c100) {
		std::ofstream cc2Worksss;
		cc2Worksss.open("cc2Worksss.txt");
		cc2Worksss << "0x62c100" << std::endl;
		for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
		{
			cc2Worksss << INS_Disassemble(instruction) << std::endl;
		}
		cc2Worksss.close();
	}


	/* check conditions for iniline-able functions (rtns). conditions:
	* 1. size of rtn.
	* 2. no INS_IsDirectControlFlow (branch) inside one of the instructions in the rtn.
	* 3. has only one return (at the end of the function).
	* 4. there is no jumps with positive offset of RBP (no call for the function which called us).
	* */
	/*std::ofstream aaa;
	aaa.open("monmmon.txt");
	for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
	{
		ADDRINT ins_addr = INS_Address(instruction);
		if (ins_addr == 0x405c53 || ins_addr == 0x407e08 || ins_addr == 0x406e85 || ins_addr == 0x40841b || ins_addr == 0x411b19) {
			ADDRINT rtn_addr_t = RTN_Address(rtn);
			aaa << rtn_addr_t << std::endl;
		}
	}
	aaa.close();*/

	// check if tail is a return instruction (3rd cond).
	if (!INS_IsRet(RTN_InsTail(rtn))) {
		RTN_Close(rtn);
		return;
	}

	// check the second cond.
	for (INS instruction = RTN_InsHead(rtn); INS_Address(instruction) < tail_address; instruction = INS_Next(instruction))
	{
		/*INS next_ins = INS_Next(INS_Next(instruction));
		if (INS_Address(next_ins) == tail_address)
		{
			if (INS_IsDirectControlFlow(instruction) && INS_IsCall(instruction)) {
				std::cout << "last inst is call" << std::endl;
				RTN_Close(rtn);
				return;
			}
		}*/

		if (INS_IsRet(instruction) || (INS_IsDirectControlFlow(instruction) && !INS_IsCall(instruction)))
		{
			RTN_Close(rtn);
			return;
		}
		if (INS_IsMemoryRead(instruction) || INS_IsMemoryWrite(instruction))
		{
			REG baseReg = INS_MemoryBaseReg(instruction);
			INT32 displacement = INS_MemoryDisplacement(instruction);
			if (baseReg == REG_RBP) // Check if base register is RBP
			{
				if (displacement > 0) {
					std::cout << "RBP displacement = " << displacement << std::endl;
					RTN_Close(rtn);
					return;
				}
			}

			if (baseReg == REG_RSP)
			{
				if (displacement < 0) {
					std::cout << "RSP displacement = " << displacement << std::endl;
					RTN_Close(rtn);
					return;
				}
			}
		}
	}

	// add rtn to the inline-ables rtns set.
	if (inlineable_rtns.find(rtn_address) == inlineable_rtns.end()) {
		if (!RTN_Valid(rtn) || !RTN_Valid(RTN_FindByAddress(rtn_address))) {
			std::cout << "something went wrong with address 0x" << rtn_address << std::endl;
		}
		else {
			std::cout << "valid inlieable rtn " << RTN_Name(rtn) << "was added, with address = 0x" << std::hex << rtn_address << std::endl;
			inlineable_rtns.insert(rtn_address);
		}
	}

	RTN_Close(rtn);
}

VOID Fini(int n, void* v) {

	// acronym (hcsfir): Hottest Call Sites For Inlinables Routines.
	unordered_map <ADDRINT, ADDRINT> hcsfir;
	//             rtn_address | hot_call_site


	//open file
	std::ofstream output;
	output.open("count.csv");
	if (!output)
		std::cerr << "error openning the file." << std::endl;

	for (auto& iter : called_rtns) {

		if (inlineable_rtns.find(iter.first) == inlineable_rtns.end()) {
			continue;
		}

		// is inline-able routine
		UINT64  max_calls = 0;
		ADDRINT hottest_call_site = 0;
		for (auto call_site : iter.second.call_sites) {

			if (call_site.second > max_calls) {
				max_calls = call_site.second;
				hottest_call_site = call_site.first;
			}
		}

		if (max_calls == 0) {
			std::cout << "there are no hot call sites for RTN in address: " << iter.first << std::endl;
		}

		else {
			hcsfir[iter.first] = hottest_call_site;
		}
	}

	// dump collected inline-able profile into count.csv
	output << "inline-able functions data and number of inlined functions is" << ", " << std::dec << hcsfir.size() << std::endl;
	for (auto& iter : hcsfir) {
		output << "0x" << std::hex << iter.first << ", " << "0x" << std::hex << iter.second << std::endl;
	}

	output.close();

}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int setProfile(int argc, char* argv[])
{

	TRACE_AddInstrumentFunction(Trace, 0);
	RTN_AddInstrumentFunction(Routine, 0);
	PIN_AddFiniFunction(Fini, 0);

	// Never returns
	PIN_StartProgram();

	return 0;
}
