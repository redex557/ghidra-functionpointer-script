# coding=utf8
# Awesome new script to find all the function pointer magic.
# @author MFR
# @category _NEW_
# @keybinding F9
# @menupath Tools.Find Function Pointers
# @toolbar

import sys

from java.awt import Color

from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet


functionTable = []	# Table of all known function and their start address
backtrackTable = []	# Table of instructions already run backtrack_call() on
MAXDEPTH = 5            # Adjust this value to set the limit of recursive backtracking depth

service = state.getTool().getService(ColorizingService)
if service is None:
     print "Can't find ColorizingService service"
  

# Loops over all functions found by Ghidra and puts 
# function names and entry points into functionTable[] 
def build_function_table():
	print "Initializing table of functions detected by ghidra..."
	print "Known functions in the current program:"
	function = getFirstFunction()
	while function is not None:
		print "    0x"+str(function.getEntryPoint())+"  "+str(function.getName())
		funEntryPoint = function.getEntryPoint()
		functionTable.append((str(funEntryPoint), function.getName()))
		tmpfun = function
		function = getFunctionAfter(function)
	lastaddr = int(str(funEntryPoint),16) + tmpfun.getBody().getNumAddresses()
	functionTable.append((str(lastaddr), "--LAST_INSTRUCTION--"))
	print "    0x"+str(lastaddr)+"  --LAST_INSTRUCTION--\n"

	
# Given an address "adr" (int) this function returns the name of the function containing this address
# If no function in this address region is known, -1 is returned.
def find_containing_function(adr):
	i = 0
	while int(functionTable[i][0],16)<=int(str(adr),16):
			i += 1			
	if i == 0 or i == len(functionTable):
		return -1	
	return functionTable[i-1][1]


# Returns the range of addresses of a given function (by name)
# Returns tuple of form (entryPoint, lastAddressInFunction) or (0,0) for unknown functions
def function_adr_range(functionName):	 
	for i, f in enumerate(functionTable):
		if f[1] == functionName and functionTable[i+1]:
				return int(functionTable[i][0],16), int(functionTable[i+1][0],16)-1
	return 0, 0


# Backtracks a register for modifications 
# stays inside bounds of the function currently in
def backtrack_call(instruction, register, depth=0):
	global backtrackTable
	if depth > MAXDEPTH:    # limiting recursiv backtracking depth by setting MAXDEPT
		return 0
	if depth == 0:          # reset backtracking table
		backtrackTable = []
	func = find_containing_function(instruction.address)
	func_range = function_adr_range(func)
	instruction = instruction.getPrevious()     # jump to previous instruction to avoid endless loop :)
	
	if (instruction, register) in backtrackTable:   # already visited this instruction regarding this register change 
		return 0

	while int(str(instruction.address),16) >= func_range[0]+2:      # first instruction of function +2 to skip default PUSH RBP and MOV RDP, RSP on function beginning
		mnemonic = instruction.mnemonicString
		atr1 = instruction.getOpObjects(0)
		atr2 = instruction.getOpObjects(1)
		
		for a1 in atr1:
			if (instruction, a1) in backtrackTable:
				break
			elif isinstance(a1,ghidra.program.model.lang.Register) and register.contains(a1) :
					if atr2 and isinstance(atr2[0], ghidra.program.model.scalar.Scalar):
						cf = find_containing_function(atr2[0])
						if not cf == -1:
							print "  "*depth+"   -->  0x"+str(instruction.address)+"  "+str(instruction)+"    (Address of known function: "+str(find_containing_function(atr2[0]))+")"
						else:
							print "  "*depth+"   -->  0x"+str(instruction.address)+"  "+str(instruction)+"    (Static value assignment found in code)"
					elif instruction.mnemonicString == "XOR" and atr1 == atr2:
							print "  "*depth+"   -->  0x"+str(instruction.address)+"  "+str(instruction)+"    (Resets "+str(a1)+" to 0x0)"
					elif instruction.mnemonicString == "MOV" and atr1 == atr2:
							print "  "*depth+"   -->  0x"+str(instruction.address)+"  "+str(instruction)+"    (2-byte NOP for alignment)"
					else:
						print "  "*depth+"   -->  0x"+str(instruction.address)+"  "+str(instruction)
					
					setBackgroundColor(instruction.address, Color(255/MAXDEPTH*depth,255,255/MAXDEPTH*depth))
					backtrackTable.append((instruction, register))
					
					for a2 in atr2:
						if isinstance(a2, ghidra.program.model.lang.Register):
							backtrack_call(instruction, a2, depth+1)
		instruction = instruction.getPrevious()


build_function_table()
print "CALL instructions in the current program:"
instruction = getFirstInstruction()
while instruction is not None:			        # Iterate over all instructions in the binary
	clearBackgroundColor(instruction.address)       # Clear up the background color of previous runs
	if (instruction.mnemonicString == "CALL"):	# For now we are only interested in CALLs 
		print ""
		if isinstance(instruction.getOpObjects(0)[0], ghidra.program.model.lang.Register):
			setBackgroundColor(instruction.address, Color.GREEN)
			if getReferencesFrom(instruction.address):
				ref = getReferencesFrom(instruction.address)[0]
				to_addr = ref.getToAddress()
				func_ref = find_containing_function(to_addr)
				print "--> 0x"+str(instruction.address)+"  "+str(instruction)+"\n           Indirect calling function: "+str(func_ref)
			else:
				print "--> 0x"+str(instruction.address)+"  "+str(instruction)
				if currentAddress == instruction.address:
					print "         Backtracking changing operations on register:"
					backtrack_call(instruction, instruction.getOpObjects(0)[0])
				else: 
					print "         If you want to backtrack register changes affecting this call put your cursor on the line with the instruction."
		elif isinstance(instruction.getOpObjects(0)[0], ghidra.program.model.address.GenericAddress):
			print "    0x"+str(instruction.address)+"  "+str(instruction)
			if "ptr" in str(instruction):
				ptr = instruction.getOpObjects(0)[0]
				fun = find_containing_function(getReferencesFrom(ptr)[0].getToAddress())
				if fun != -1:
					print "           Direct calling function via a ptr: "+fun
			else:
				fun = find_containing_function(instruction.getOpObjects(0)[0])
				if fun != -1:
					print "           Direct calling function: "+fun
		else:
			print "  ? 0x"+str(instruction.address)+"  "+str(instruction)
	instruction = instruction.getNext()
print "\nExecution finished!"
