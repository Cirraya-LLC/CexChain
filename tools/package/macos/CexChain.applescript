-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Cirraya
--
-- CexChain.app: opens the web console, starting it if it is stopped; a
-- proposal or consent file opened with the app opens in the console.

on cexchain(arguments)
	set tool to quoted form of (POSIX path of (path to me) & "Contents/MacOS/cexchain")
	try
		do shell script tool & " console open" & arguments & " > /dev/null 2>&1"
	on error
		set logFile to POSIX path of (path to home folder) & "Library/Application Support/CexChain/ledger/console/console.log"
		display alert "CexChain did not open" message "See " & logFile & " or run: cexchain console open" as critical
	end try
end cexchain

on run
	cexchain("")
end run

on open theFiles
	repeat with f in theFiles
		cexchain(" " & quoted form of (POSIX path of f))
	end repeat
end open
