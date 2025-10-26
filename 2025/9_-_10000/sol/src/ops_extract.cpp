#include <capstone/capstone.h>
#include <nlohmann/json.hpp>
#include <pe-parse/parse.h>
#include <cstdio>
#include <cinttypes>
#include <vector>
#include <iostream>
#include <utility>
#include <fstream>


int find_check(void* data, const peparse::VA& va, const std::string&, const std::string& name) {
	if (name == "_Z5checkPh") {
		*static_cast<peparse::VA*>(data) = va;
		return 1;
	}
	return 0;
}

struct find_text_struct {
	peparse::VA va;
	std::vector<std::uint8_t> data;
};

int find_text(void* data, const peparse::VA& va, const std::string& sec_name, const peparse::image_section_header& hdr, const peparse::bounded_buffer* buf) {
	if (sec_name == ".text") {
		auto& ft_data = *static_cast<find_text_struct*>(data);
		ft_data.va = va;
		ft_data.data.resize(buf->bufLen);
		std::memcpy(ft_data.data.data(), buf->buf, buf->bufLen);
		return 1;
	}
	return 0;
}


int cb_imports(void* data, const peparse::VA& va, const std::string& dllname, const std::string& funcname) {
	auto &mp = *static_cast<std::map<std::uint64_t, std::pair<int, std::string>>*>(data);
	if (std::isdigit(dllname[0])) {
		auto d = dllname.substr(0, 4);
		mp[va] = { std::stoi(d), funcname };
	}
	return 0;
}

std::map<std::uint64_t, std::pair<int, std::string>> get_imports(peparse::parsed_pe* pe) {
	std::map<std::uint64_t, std::pair<int, std::string>> ret;
	peparse::IterImpVAString(pe, cb_imports, &ret);
	return ret;
}

int export_cb(void* data, const peparse::VA& va, const std::string&, const std::string& name) {
	auto& exports = *static_cast<std::map<std::uint64_t, std::string>*>(data);
	exports[va] = name;
	return 0;
}

std::map<std::uint64_t, std::string> get_exports(peparse::parsed_pe* pe) {
	std::map<std::uint64_t, std::string> exports;
	peparse::IterExpVA(pe, export_cb, &exports);
	return exports;
}

std::vector<std::pair<int, std::string>> process_file(peparse::parsed_pe* pe, int cur, csh& handle) {
	peparse::VA checkva;
	peparse::IterExpVA(pe, find_check, &checkva);

	find_text_struct st;
	peparse::IterSec(pe, find_text, &st);

	auto at = checkva - st.va;
	cs_insn* insn;
	auto count = cs_disasm(handle, st.data.data() + at, st.data.size() - at, st.va + at, 0, &insn);
	//for (int i = 0; i < 200; i++) {
	//	printf("0x%" PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
	//}

	auto imports = get_imports(pe);
	auto exports = get_exports(pe);

	cs_insn* insn_st = &insn[11];
	constexpr uint64_t need = 0x000005d0858b48;

	std::vector<std::pair<int, std::string>> ops;
	while (true) {
		if (std::memcmp(&need, insn_st->bytes, std::min(static_cast<int>(insn_st->size), 5))) {
			//std::cout << "FAILIONG" << std::hex << (long long) insn_st->address << ' ' << (long long) *reinterpret_cast<uint64_t*>(insn_st->bytes);
			break;
		}
		if (insn_st[2].bytes[0] == 0xe8) {
			int rel = *reinterpret_cast<int*>(insn_st[2].bytes + 1);
			auto addr = insn_st[3].address + rel;

			auto iter = exports.find(addr);
			if (iter == exports.end()) {
				std::cout << "FAILLL";
				exit(1);
			}

			ops.emplace_back(cur, iter->second);
			insn_st += 3;
		} else {
			int rel = *reinterpret_cast<int*>(insn_st[2].bytes + 3);
			auto addr = insn_st[3].address + rel;
			auto iter = imports.find(addr);
			if (iter == imports.end()) {
				std::cout << "FAILLL";
				exit(1);
			}
			//std::cout << std::hex << (int)addr << '\n';
			ops.push_back(iter->second);
			insn_st += 4;
		}
	}

	cs_free(insn, count);
	return ops;
}

int main() {
	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		std::cout << "fail";
		return 1;
	}
	nlohmann::json res;
	for (int i = 0; i < 10000; i++) {
		char dllname[100];
		sprintf(dllname, "%s//dlls//%04d.dll", BASEDIR, i);

		auto pefile = peparse::ParsePEFromFile(dllname);
		auto j = process_file(pefile, i, handle);
		res[i] = j;
		peparse::DestructParsedPE(pefile);
	}

	auto fname = BASEDIR"/sol/ops.txt";
	std::ofstream ofs(fname);
	ofs << res.dump();
}