#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include <iostream>

int main() {
	std::ifstream f(BASEDIR"/sol/imports.txt");
	std::vector<std::vector<int>> imports = nlohmann::json::parse(f);

	f = std::ifstream(BASEDIR"/sol/nums.txt");
	std::vector<int> nums = nlohmann::json::parse(f);

	f = std::ifstream(BASEDIR"/sol/fn_nums.txt");
	std::vector<int> fns = nlohmann::json::parse(f);
	std::vector<int> res(10000);

	for (int i = 0; i < 10000; i++) {
		int x = fns[i];

		for (int u : imports[x]) {
			res[u] += i;
		}
	}

	for (int i = 0; i < 10000; i++) {
		if (res[i] != nums[i]) {
			std::cout << i << '\n';
		}
	}
}