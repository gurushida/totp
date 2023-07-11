#include <string>
#include <totp/totp.hpp>
#include <cxxopts.hpp>

int main(int argc, char* argv[]) {
	try {
        cxxopts::Options options("totp test", "totp test");
		options.allow_unrecognised_options().add_options()
			("key", "key", cxxopts::value<std::string>()->default_value(""))
			;
		const auto result = options.parse(argc, argv);
		const auto key = result["key"].as<std::string>();
		const auto [lifetime, totp] = totp::get_totp(key.c_str());
		std::cout << "otp: " << totp << ", lifetime: " << lifetime << std::endl;
	}
	catch (const std::exception& e) {
		std::string msg = e.what();
		std::cout << msg << std::endl;
	}

	return 0;
}