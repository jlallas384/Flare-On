#include <pe-parse/parse.h>
#include <string>
#include <cassert>
#include <vector>
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

std::vector<std::vector<int>> imports(10000);
int cb(void* data, const peparse::VA&, const std::string& name, const std::string&) {
    int num = *static_cast<int*>(data);
    if (std::isdigit(name[0])) {
        auto d = name.substr(0, 4);
        imports[num].push_back(std::stoi(d));
    }
    return 0;
}

int main() {
    for (int i = 0; i < 10000; i++) {
        char dllname[100];
        sprintf(dllname, "%s//dlls//%04d.dll", BASEDIR, i);

        auto file = peparse::ParsePEFromFile(dllname);
        assert(file != nullptr);
        peparse::IterImpVAString(file, cb, &i);
        peparse::DestructParsedPE(file);
    }

    std::vector<std::vector<int>> used;

    for (int st = 0; st < 10000; st++) {
        std::vector<int> qu = {st};
        std::vector<int> vis(10000);

        while (!qu.empty()) {
            int v = qu.back(); qu.pop_back();
            vis[v] = 1;

            for (int u : imports[v]) if (!vis[u]) {
                qu.push_back(u);
            }
        }

        used.emplace_back();
        for (int i = 0; i < 10000; i++) {
	        if (vis[i]) {
                used.back().push_back(i);
	        }
        }
    }

    auto j = nlohmann::json(used);

    std::ofstream f(BASEDIR"/sol/imports.txt");

    f << j.dump();
}