#include <iostream>
#include <string>
#include <cstdint>

/* Simple Espresso output converter from KISS to hex */
int main()
{
	std::string s;
	std::cout.setf(std::ios::hex, std::ios::basefield);
	std::cout.fill('0');
	while (std::getline(std::cin, s))
	{
		size_t idx = 0;
		uint32_t val = 0;
		uint32_t mask = 0;

		while (std::isspace(s[idx]))
		{
			++idx;
		}

		for (size_t bit = 0; bit < 32; ++bit)
		{
			val <<= 1;
			mask <<= 1;
			switch (s[idx + bit])
			{
				case '1':
					val |= 1;
					break;
				case '0':
					/* do nothing */
					break;
				case '-':
					mask |= 1;
					break;
				default:
					std::cerr << "Unknown character in input: " << s[idx + bit] << std::endl;
					return 1;
			}
		}

		mask = ~mask;

		std::cout << "0x";
		std::cout.width(8);
		std::cout << val << " 0x";
		std::cout.width(8);
		std::cout << mask << std::endl;
	}
	return 0;
}
