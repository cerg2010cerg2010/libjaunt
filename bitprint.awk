#!/bin/awk -f
BEGIN {
	RS="\r\n"
	print ".type f"
	print ".i 32"
	print ".o 1"
}

function bits2str(bits, data, mask)
{
	if (bits == 0)
		return "0"

	mask = 1
	for (; bits != 0; bits = rshift(bits, 1))
		data = (and(bits, mask) ? "1" : "0") data

	while (length(data) != 32)
		data = "0" data

	return data
}

$2 == "SIGILL_OFFBY2" { print bits2str(strtonum(substr($1, 2, length($1) - 1))) " 1" }
#$2 ~ /^SIGILL/ { print bits2str(strtonum(substr($1, 2, length($1) - 1))) " 1" }

