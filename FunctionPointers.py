# coding=utf8
# Awesome new script to find all the function pointer magic.
# @author MFR
# @category _NEW_
# @keybinding F9
# @menupath Tools.Find Function Pointers
# @toolbar
# @category: FunctionPointers

import sys

from java.awt import Color

from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address, GenericAddress
from ghidra.program.model.address import AddressSet
from ghidra.program.model.lang import Register
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.pcode.PcodeOp import INT_XOR, COPY
from ghidra.program.model.symbol.FlowType import COMPUTED_CALL
from ghidra.program.model.symbol.SourceType import USER_DEFINED


backtrackTable = []	# Table of instructions already run backtrack_call() on
backtrackStart = None
MAXDEPTH = 5            # Adjust this value to set the limit of recursive backtracking depth

service = state.getTool().getService(ColorizingService)
if service is None:
     print "Can't find ColorizingService service"

# Backtracks a register for modifications 
# stays inside bounds of the function currently in
def backtrack_call(instruction, register, depth=0):
	global backtrackTable
	global backtrackStart
	if depth > MAXDEPTH:    # limiting recursiv backtracking depth by setting MAXDEPT
		return 0
	if depth == 0:          # reset backtracking table
		backtrackTable = []
		backtrackStart = instruction
	func = getFunctionContaining(instruction.address)
	instruction = instruction.previous     # jump to previous instruction to avoid endless loop :)
	
	if (instruction, register) in backtrackTable:   # already visited this instruction regarding this register change 
		return 0

	while func.getBody().contains(instruction.address):
		monitor.checkCanceled()
		mnemonic = instruction.mnemonicString
		atr1 = instruction.getOpObjects(0)
		atr2 = instruction.getOpObjects(1)
		
		for a1 in atr1:
			monitor.checkCanceled()
			if not isinstance(a1, Register):
				continue
			if (instruction, a1) in backtrackTable:
				break
			elif register.getBaseRegister().contains(a1) :
				line_start = '%s  --> 0x%s %s\t' % ('\t'*depth, instruction.address, instruction)
				if atr2 and isinstance(atr2[0], Scalar):
					cf = getFunctionContaining(toAddr(atr2[0].getUnsignedValue()))
					if cf:
						print(line_start+'(Address of known function: %s)' % cf.entryPoint)
						if not backtrackStart.getOperandReferences(0):
							backtrackStart.addOperandReference(0, cf.entryPoint, COMPUTED_CALL, USER_DEFINED)
					else:
						print(line_start+'(Static value assignment found in code) %s' % atr2[0])
				elif instruction.pcode[0].opcode == INT_XOR and atr1 == atr2:
					print(line_start+'(Resets %s to 0x0)' % a1)
				elif instruction.pcode[0].opcode == COPY and atr1 == atr2:
					print(line_start+'(2-byte NOP for alignment)')
				else:
					print(line_start)
				
				setBackgroundColor(instruction.address, Color(255/MAXDEPTH*depth,255,255/MAXDEPTH*depth))
				backtrackTable.append((instruction, register))
				
				for a2 in atr2:
					if isinstance(a2, Register):
						backtrack_call(instruction, a2, depth+1)
		instruction = instruction.previous

def main():
	if getFunctionContaining(currentAddress):
		instruction = getInstructionAt(currentAddress)
		if instruction and instruction.flowType.call and instruction.flowType.computed:
			if not instruction.referencesFrom:
				print("Backtracking changing operations on register:")
				backtrack_call(instruction, instruction.inputObjects[0])
				return
	print "CALL instructions in the current program:"
	for instruction in currentProgram.getListing().getInstructions(True): # Iterate over all instructions in the binary
		monitor.checkCanceled()
		clearBackgroundColor(instruction.address)       # Clear up the background color of previous runs
		if (instruction.flowType.call):	# For now we are only interested in CALLs 
			if isinstance(instruction.getOpObjects(0)[0], Register):
				setBackgroundColor(instruction.address, Color.GREEN)
				if instruction.flowType.computed and instruction.referencesFrom: # computed FlowType is an indirect call)
					func_ref = getFunctionContaining(instruction.referencesFrom[0].toAddress)
					print('--> 0x%s %s' % instruction.address, instruction)
					print('\t\tIndirect calling function: %s %s' % (func_ref.entryPoint, func_ref.name))
				else:
					print('--> 0x%s %s' % (instruction.address, instruction))
					print("\t\tIf you want to backtrack register changes affecting this call"
						  " put your cursor on the line with the instruction.")
			elif instruction.resultObjects and isinstance(instruction.inputObjects[0], GenericAddress):
				print('\t0x%s %s' % (instruction.address, instruction))
				if getReferencesFrom(instruction.inputObjects[0]):
					fun = getFunctionContaining(getReferencesFrom(instruction.getOpObjects[0])[0].toAddress)
					if fun:
						if "ptr" in str(instruction):
							print('\t\tDirect calling function via a ptr: 0x%s %s' % (fun.entryPoint, fun.getName()))
						else:
							print('\t\tDirect calling function: 0x%s %s' % (fun.entryPoint, fun.getName()))
			else:
				print('  ? 0x%s %s' % (instruction.address, instruction))
		instruction = instruction.getNext()
	print("\nExecution finished!")

if __name__ == '__main__':
	main()
