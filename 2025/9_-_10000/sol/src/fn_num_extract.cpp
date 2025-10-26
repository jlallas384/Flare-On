#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include <iostream>

int main() {
	std::ifstream f(BASEDIR"/sol/imports.txt");
	std::vector<std::vector<int>> imports = nlohmann::json::parse(f);

	f = std::ifstream(BASEDIR"/sol/nums.txt");
	std::vector<int> nums = nlohmann::json::parse(f);
	std::vector<int> imported_cnt(10000);

	for (int i = 0; i < 10000; i++) {
		for (int u : imports[i]) if (u != i) {
			imported_cnt[u]++;
		}
	}


	std::vector<int> fns(10000, -1);
	std::vector<int> qu;

	for (int i = 0; i < 10000; i++) {
		if (imported_cnt[i] == 0) {
			qu.push_back(i);
		}
	}

	while (!qu.empty()) {
		int v = qu.back(); qu.pop_back();
		fns[nums[v]] = v;
		for (int u : imports[v]) if (u != v) {
			imported_cnt[u]--;
			nums[u] -= nums[v];
			if (imported_cnt[u] == 0) {
				qu.push_back(u);
			}
		}
	}


	std::ofstream of(BASEDIR"/sol/fn_nums.txt");

	nlohmann::json j(fns);
	of << j.dump();
}