#include "profile.cpp"
#include <stdio.h>
#include <iostream>
#include <fstream>
//#include "profile.cpp"
#include "pin.H"
#include <map>
#include <set>
#include <string>
#include "rtn-translation.cpp"

using namespace std;
std::ifstream file;
std::string line;

extern "C" {
#include "xed-interface.h"
}


/* ===================================================================== */
/* functions definitions                                                 */
/* ===================================================================== */
void collect_profile(int argc, char* argv[]);
std::vector<std::string> split(const string& str, char delimiter);
void getProfile(const char* filename);

/* ===================================================================== */
/* knob definitions                                                      */
/* ===================================================================== */
KNOB<BOOL> KnobProf(KNOB_MODE_WRITEONCE, "pintool", "prof", "0", "collect loop counting of every frequently executed loop, and generate loop-count.csv");
KNOB<BOOL> KnobOpt(KNOB_MODE_WRITEONCE, "pintool", "opt", "0", "Probe mode and implement function inlining of functions that have a single Hot call site, followed by Code Reordering");


/* ===================================================================== */
/* Main()                                                                */
/* ===================================================================== */
int main(int argc, char* argv[]) {
	PIN_InitSymbols();
	PIN_Init(argc, argv);

	if (KnobOpt) {
		const char* f_name = "count.csv";
		if (!(access(f_name, F_OK) != -1)) {
			std::cout << "error openning file loop-count.csv, exiting pintool..." << std::endl;
			exit(1);
		}

		getProfile(f_name);
		main_r(argc, argv);
	}

	else if (KnobProf) {
		collect_profile(argc, argv);
		return 0;
	}

	else {
		PIN_StartProgram();
	}
	return 0;
}

void collect_profile(int argc, char* argv[]) {
	setProfile(argc, argv);
}


void getProfile(const char* filename) {
	file.open(filename);

	std::getline(file, line);
	int numOfInlinablesRtns, i;
	i = 0;
	vector<string> splitted = split(line, ',');
	std::istringstream iss_numInline(splitted[1]);
	iss_numInline >> std::dec >> numOfInlinablesRtns;
	while (std::getline(file, line) && i < numOfInlinablesRtns) {
		i++;
		splitted = split(line, ',');
		ADDRINT inlineable_rtn_address;
		ADDRINT hot_call_site;
		std::istringstream iss_address(splitted[0]);
		std::istringstream iss_call_site(splitted[1]);
		iss_address >> std::hex >> inlineable_rtn_address;
		iss_call_site >> std::hex >> hot_call_site;
		vector<Inst_t> vec;
		inlineable_rtns_info_t info;
		info.insts = vec;
		info.inlineable_rtn_address = inlineable_rtn_address;

		/*RTN rtn = RTN_FindByAddress(inlineable_rtn_address);
		if (!RTN_Valid(rtn)) {
			cout << "invalid routine in address 0x" << std::hex << inlineable_rtn_address << endl;
			continue;
		}

		RTN hot_rtn = RTN_FindByAddress(hot_call_site);
		if (!RTN_Valid(hot_rtn)) {
			cout << "invalid hot routine in address 0x" << std::hex << hot_call_site << endl;
			continue;
		}*/

		/*for (INS ins = RTN_InsHead(rtn); INS_Address(ins) < INS_Address(RTN_InsTail(rtn)); ins = INS_Next(ins)) {
			xed_decoded_inst_t xed_inst;
			xed_error_enum_t   xed_error;
			ADDRINT ins_addr = INS_Address(ins);
			xed_decoded_inst_zero_set_mode(&xed_inst, &dstate);

			xed_error = xed_decode(&xed_inst, reinterpret_cast<UINT8*>(ins_addr), max_inst_len);
			if (xed_error != XED_ERROR_NONE) {
				cerr << "ERROR: xed decode failed for instr at: " << "0x" << std::hex << ins_addr << endl;
				break;
			}
			vec.push_back({ xed_inst, ins_addr, INS_Size(ins) });
			cout << " added successfull rtn in address 0x" << inlineable_rtn_address << endl;
		}*/

		inlineable_rtns_translation[hot_call_site] = info;

	}


}

std::vector<std::string> split(const string& s, char delimiter) {
	std::vector<std::string> tokens;
	std::istringstream iss(s);
	std::string token;

	while (std::getline(iss, token, delimiter)) {
		tokens.push_back(token);
	}
	return tokens;
}
