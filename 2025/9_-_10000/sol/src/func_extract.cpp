#include <capstone/capstone.h>
#include <nlohmann/json.hpp>
#include <pe-parse/parse.h>
#include <cstdio>
#include <cinttypes>
#include <vector>
#include <iostream>
#include <utility>
#include <fstream>

int export_cb(void* data, const peparse::VA& va, const std::string&, const std::string& name) {
	auto& exports = *static_cast<std::vector<std::pair<peparse::VA, std::string>>*>(data);
	exports.emplace_back(va, name);
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


enum FnKind {
	SubBytes,
	Shuffle,
	Exponent
};

FnKind determine_kind(cs_insn insn) {
	if (strcmp(insn.mnemonic, "sub")) {
		return SubBytes;
	}
	
	if (insn.bytes[3] == 0xc0) {
		return Exponent;
	}

	if (insn.bytes[3] == 0x50) {
		return Shuffle;
	}

	assert(false);
}

std::vector<uint8_t> process_subbytes(cs_insn* insn) {
	std::vector<uint8_t> ret;
	int at = 0;
	for (int i = 0; i < 32; i++) {
		while (strcmp(insn[at].mnemonic, "movabs")) {
			at++;
		}

		uint64_t imm = *reinterpret_cast<uint64_t*>(insn[at].bytes + 2);
		for (int b = 0; b < 8; b++) {
			ret.push_back(imm >> (8 * b));
		}
		at++;
	}
	return ret;
}

std::vector<uint8_t> process_shuffle(cs_insn* insn) {
	std::vector<uint8_t> ret;
	int at = 0;
	for (int i = 0; i < 4; i++) {
		while (strcmp(insn[at].mnemonic, "movabs")) {
			at++;
		}
		uint64_t imm = *reinterpret_cast<uint64_t*>(insn[at].bytes + 2);
		for (int b = 0; b < 8; b++) {
			ret.push_back(imm >> (8 * b));
		}
		at++;
	}
	return ret;
}

std::vector<uint8_t> process_exponent(cs_insn* insn) {
	std::vector<uint8_t> ret;
	int at = 0;
	for (int i = 0; i < 4; i++) {
		while (strcmp(insn[at].mnemonic, "movabs")) {
			at++;
		}
		uint64_t imm = *reinterpret_cast<uint64_t*>(insn[at].bytes + 2);
		for (int b = 0; b < 8 - (i == 1); b++) {
			ret.push_back(imm >> (8 * b));
		}
		at++;
	}
	return ret;
}

nlohmann::json process_function(cs_insn* insn) {
	auto kind = determine_kind(insn[2]);
	std::vector<uint8_t> ret;
	nlohmann::json j;
	if (kind == SubBytes) {
		ret = process_subbytes(insn);
	}
	else if (kind == Shuffle) {
		ret = process_shuffle(insn);
	}
	else {
		ret = process_exponent(insn);
	}

	std::stringstream ss;
	ss << std::hex;

	for (auto b : ret) {
		ss << std::setw(2) << std::setfill('0') << (int)b;
	}
	j["kind"] = kind;
	j["ops"] = ss.str();
	return j;
}

nlohmann::json process_file(peparse::parsed_pe* pe, csh &handle) {
	std::vector<std::pair<peparse::VA, std::string>> exports;
	peparse::IterExpVA(pe, export_cb, &exports);

	find_text_struct st;
	peparse::IterSec(pe, find_text, &st);


	nlohmann::json j;

	for (auto& [va, name] : exports) {
		if (name != "_Z5checkPh") {
			cs_insn* insn;
			auto at = va - st.va;
			auto count = cs_disasm(handle, st.data.data() + at, st.data.size(), st.va + at, 100, &insn);
			auto ret = process_function(insn);
			ret["va"] = va;
			j[name] = ret;
			cs_free(insn, count);
		}
	}

	return j;
}

int main() {
	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		std::cout << "fail";
		return 1;
	}
	nlohmann::json res;
	for (int i = 0; i < 200; i++) {
		char dllname[100];
		sprintf(dllname, "%s//dlls//%04d.dll", BASEDIR, i);

		auto pefile = peparse::ParsePEFromFile(dllname);
		auto j = process_file(pefile, handle);
		res[i] = j;
		if (i % 100 == 0) {
			std::cout << i << '\n';
		}
		peparse::DestructParsedPE(pefile);
	}

	auto fname = BASEDIR"/sol/funcs_test.txt";
	std::ofstream ofs(fname);
	ofs << res.dump();
}