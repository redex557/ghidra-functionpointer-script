# ghidra-functionpointer-script

## Functionality
This script extends Ghidra with a way to analyze function calls. It shows direct calls (fixed address) and indirect calls (address referenced to by a fixed pointer or address inside a register). If the content of a register is called, the script provides a backtrace of instructions (possibly) working on this register.

## Usage
1. Place into your scripts folder. e.g.:  
```$USER_HOME/ghidra_scripts/```  
(1.1 If not existing add it to the "Script Directories" in the Ghidra Script Manager's Toolbar.)
2. Activate the script in the "_NEW" section.
3. Load your binary and run the default analysis tasks.  
4. Place your cursor somewhere in the disassembled code.  
5. Press F9 to run the script.
6. Click on addresses in the console output to jump to the matching instruction in the disassembled code.
7. Place your cursor on a instruction before running to get additional backtracking.
