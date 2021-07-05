#correct md5 (with null bytes stripped) = F7E0DF9539BA6D547BF3DBF578D455F0
import sys, struct, clr
from System.Reflection import Assembly, MethodInfo, BindingFlags
from System import Type

clr.AddReference(r"dnlib")
import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes

class payloadScanner:

	def __init__(self, obfuscatedBinary):
		self.target = obfuscatedBinary

	def scanBinary(self, decryptedBlob):

		mod = dnlib.DotNet.ModuleDefMD.Load(self.target)
		opt = dnlib.DotNet.Writer.ModuleWriterOptions(mod)	
		opt.MetadataOptions.Flags = opt.MetadataOptions.Flags | dnlib.DotNet.Writer.MetadataFlags.PreserveAll;
		totalNumTypes = 0
		stringMethodName = "pyM1eVFCveMv9BuGJ6"

		for var in mod.Types:

			if not var.HasMethods: 																									
				pass

			for method in var.Methods:
			    if not method.HasBody: 
			    	break

			    if not method.Body.HasInstructions: 
			    	break

			    i = 0
			    operand = ""
			    while i < len(method.Body.Instructions):

			        operand = str(method.Body.Instructions[i].Operand).encode()
			        if method.Body.Instructions[i].OpCode == OpCodes.Call and operand.find(str(stringMethodName).encode()) != -1:
			            keyValue = method.Body.Instructions[i - 1].GetLdcI4Value()
			            string_length = struct.unpack("I", decryptedBlob[keyValue:keyValue + 4])[0]
			            string = decryptedBlob[keyValue + 4:keyValue + 4 + string_length]
			            print("Namespace: %s\nMethod: %s\n%d: %s\n" % (var, method.Name, keyValue, string.replace("\x00", "")))

			        i += 1
		return

class blobDecryption:

	def __init__(self, resourceData, array1Dump):
		self.resourceData = open(resourceData, "rb").read()
		self.array1 = open(array1Dump, "rb").read()

	def decryptStringBlob_internalCalculation(self, value):

		num = value ^ value << 3  & 0xFFFFFFFF
		num = (num + 3302414041)  & 0xFFFFFFFF
		num = (num ^ (num << 11)) & 0xFFFFFFFF
		num = (num + 2323220752)  & 0xFFFFFFFF
		num = (num ^ (num >> 27)) & 0xFFFFFFFF
		num = (num + 1568112929)  & 0xFFFFFFFF
		num = (319228767 - num)   & 0xFFFFFFFF 
		return num

	def decryptStringBlob(self):
		
		array = []
		num = len(self.resourceData) % 4
		num2 = len(self.resourceData) / 4
		num3 = len(self.array1) / 4
		num4 = 0

		if num > 0:
			num2 += 1

		for i in range(0, num2):
			num5 = (i % num3)
			num6 = i * 4
			num7 = num5 * 4
			num8 = struct.unpack("<I", self.array1[num7:num7 + 4])[0]
			if i == num2 - 1 and num > 0:
				num9 = 0
				num10 = 255
				num11 = 0
				for j in range(0, num):
					if j > 0:
						num9 <<= 8
					num9 |= ord(self.resourceData[len(self.resourceData) - (1 + j)])

				num4 += num8
				num4 += self.decryptStringBlob_internalCalculation(num4) 
				num12 = (num4 ^ num9) & 0xFFFFFFFF

				for k in range(0, num):
					if k > 0:
						num10 <<= 8
						num11 += 8
					#array[num6 + k] = (num12 & num10) >> num11  # in this case, only adds \x2E at end of file, so not critical 

			else:

				num7 = num6
				num9 = struct.unpack("<I", self.resourceData[num7:num7 + 4])[0]
				num4 += num8
				num4 += self.decryptStringBlob_internalCalculation(num4)  
				num13 = (num4 ^ num9) 

				array.append(struct.pack("I", num13 & 0xFFFFFFFF))

		return array

def main():

	try:
		obfuscatedBinary = sys.argv[1]
		resourceData = sys.argv[2]
		array1Dump = sys.argv[3]
	except:
		print("Incorrect Arguments.")
		print("reactor_decrypt.py <obfuscated binary> <dumped resource> <dumped array>")
		return 1

	scanClass = payloadScanner(obfuscatedBinary)
	decryptedBlob = "".join(blobDecryption(resourceData, array1Dump).decryptStringBlob())
	scanClass.scanBinary(decryptedBlob)

	return 0

if __name__ == '__main__':
	main()
