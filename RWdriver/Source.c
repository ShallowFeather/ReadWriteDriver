#include <ntifs.h>
#include <windef.h>
#include <ntdef.h>
#include <ntifs.h>
#include <intrin.h>
#include <ntimage.h>
#include <minwindef.h>

NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern NTSYSAPI PVOID RtlPcToFileHeader(PVOID PcValue, PVOID* BaseOfImage);

#define init_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x775, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define read_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x776, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define write_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x777, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct info_t {
    HANDLE target_pid;
    ULONG64 target_address;
    PBYTE buffer_address;
    SIZE_T Size;
} UserData, * PUserData;

typedef struct _MMPTE_HARDWARE64
{
    ULONG64 Valid : 1;
    ULONG64 Dirty1 : 1;
    ULONG64 Owner : 1;
    ULONG64 WriteThrough : 1;
    ULONG64 CacheDisable : 1;
    ULONG64 Accessed : 1;
    ULONG64 Dirty : 1;
    ULONG64 LargePage : 1;
    ULONG64 Global : 1;
    ULONG64 CopyOnWrite : 1;
    ULONG64 Prototype : 1;
    ULONG64 Write : 1;
    ULONG64 PageFrameNumber : 36;
    ULONG64 Reserved1 : 4;
    ULONG64 SoftwareWsIndex : 11;
    ULONG64 NoExecute : 1;
} PTE;

typedef struct PageTable
{
    PTE* Pte;
    ULONG64 VirtualAddress;
    ULONG64 OldPageFrameNumber;
} PageTable;

typedef PVOID(__fastcall* MmAllocateIndependentPages_t)(IN  SIZE_T NumberOfBytes, IN  ULONG Node);
MmAllocateIndependentPages_t MmAllocateIndependentPages;

typedef ULONG64(__fastcall* MiGetPteAddress_t)(IN  ULONG64 baseAddress);
MiGetPteAddress_t MiGetPteAddress;

static uintptr_t ntoskrnl_imagebase;

PageTable List[64];

VOID ReadPhysicalAddress(UINT32 Index, ULONG64 phy, PVOID buffer, SIZE_T size)
{
    PageTable* page = &List[Index];
    page->Pte->PageFrameNumber = phy >> PAGE_SHIFT;
    //DbgPrint("Physical Address: 0x%x\n", phy);
    __invlpg(page->VirtualAddress);
    __movsb((PUCHAR)buffer, (PUCHAR)page->VirtualAddress + (phy & 0xFFF), size);
    page->Pte->PageFrameNumber = page->OldPageFrameNumber;
    __invlpg(page->VirtualAddress);
}

ULONG64 TransformationCR3(UINT32 Index, ULONG64 cr3, ULONG64 VirtualAddress)
{
    cr3 &= ~0xf;
    ULONG64 PAGE_OFFSET = VirtualAddress & ~(~0ul << 12);
    SIZE_T BytesTransferred = 0;
    ULONG64 a = 0, b = 0, c = 0;
    ReadPhysicalAddress(Index, (cr3 + 8 * ((VirtualAddress >> 39) & (0x1ffll))), &a, sizeof(a));
    if (~a & 1)
    {
        return 0;
    }
    ReadPhysicalAddress(Index, ((a & ((~0xfull << 8) & 0xfffffffffull)) + 8 *
        ((VirtualAddress >> 30) & (0x1ffll))), &b, sizeof(b));
    if (~b & 1)
    {
        return 0;
    }
    if (b & 0x80)
    {
        return (b & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));
    }
    ReadPhysicalAddress(Index, ((b & ((~0xfull << 8) & 0xfffffffffull)) + 8 *
        ((VirtualAddress >> 21) & (0x1ffll))), &c, sizeof(c));
    if (~c & 1)
    {
        return 0;
    }
    if (c & 0x80)
    {
        return (c & ((~0xfull << 8) & 0xfffffffffull)) + (VirtualAddress & ~(~0ull <<
            21));
    }
    ULONG64 address = 0;
    ReadPhysicalAddress(Index, ((c & ((~0xfull << 8) & 0xfffffffffull)) + 8 *
        ((VirtualAddress >> 12) & (0x1ffll))), &address, sizeof(address));
    address &= ((~0xfull << 8) & 0xfffffffffull);
    if (!address)
    {
        return 0;
    }
    return address + PAGE_OFFSET;
}

VOID ReadVirtualMemory(UINT32 Index, ULONG64 cr3, ULONG64 VirtualAddress, PVOID Buffer) {
    UINT32 PageIndex = Index % 64;
    ULONG64 PhysicalMemory = TransformationCR3(PageIndex, cr3, VirtualAddress);
    DbgPrint("PhysicalMemory: %p\n", PhysicalMemory);
    ReadPhysicalAddress(Index, PhysicalMemory, Buffer, sizeof(Buffer));
}




NTSTATUS ctl_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Information = sizeof(UserData);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    PUserData Buffer = (PUserData)irp->AssociatedIrp.SystemBuffer;
    DbgPrint("IOCTL\n");


    if (stack) {
        if (Buffer && sizeof(*Buffer) >= sizeof(UserData)) {
            ULONG ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
            if (ctl_code == init_code) {
                /*
                DbgPrint("Init\n");
                for (int i = 0; i < 64; i++) {
                    List[i].VirtualAddress = MmAllocateIndependentPages(0x1000, -1);
                    memset(List[i].VirtualAddress, 0, 0x1000);
                    List[i].Pte = MiGetPteAddress(List[i].VirtualAddress);
                    DbgPrint("Pte: %x\n", List[i].Pte);
                    List[i].OldPageFrameNumber = List[i].Pte->PageFrameNumber;
                }
                PsLookupProcessByProcessId((HANDLE)Buffer->target_pid, &Process);
                cr3 = *(ULONG64*)(Process + 0x28); 
                */
            }
            else if (ctl_code == read_code) {
                DbgPrint("READ\n");
                UINT32 Index = KeGetCurrentProcessorIndex();
                PEPROCESS Process;
                PsLookupProcessByProcessId((HANDLE)Buffer->target_pid, &Process);
                PUCHAR Var = (PUCHAR)Process;
                ULONG64 cr3 = *(ULONG64*)(Var + 0x28);
                DbgPrint("Address: %llx\n", Buffer->target_address);
                DbgPrint("Cr3: %x\n", cr3);
                ReadVirtualMemory(Index, cr3, (ULONG64)Buffer->target_address, Buffer->buffer_address, Buffer->Size);
                //ReadVirtualMemory(Index, cr3, (ULONG64)Buffer->target_address, Buffer->buffer_address, Buffer->Size);
            }
            else if (ctl_code == write_code) {
                DbgPrint("WRITE\n");
                UINT32 Index = KeGetCurrentProcessorIndex();
            }
            irp->IoStatus.Information = sizeof(UserData);
        }
    }

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
    UNREFERENCED_PARAMETER(registery_path);
    UNICODE_STRING dev_name, sym_link;
    PDEVICE_OBJECT dev_obj;

    RtlInitUnicodeString(&dev_name, L"\\Device\\cartidriver");
    auto status = IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);
    if (status != STATUS_SUCCESS) return status;

    RtlInitUnicodeString(&sym_link, L"\\DosDevices\\cartidriver");
    status = IoCreateSymbolicLink(&sym_link, &dev_name);
    if (status != STATUS_SUCCESS) return status;

    /* Init */
    uintptr_t ntoskrnl_imagebase;
    RtlPcToFileHeader(&RtlPcToFileHeader, &ntoskrnl_imagebase);
    DbgPrint("ntoskrnl_imagebase: %p\n", ntoskrnl_imagebase);
    uintptr_t pMmAllocateIndependentPages = ntoskrnl_imagebase + 0xfd590; // ntoskrnl!MmAllocateIndependentPages
    MmAllocateIndependentPages = (MmAllocateIndependentPages_t)(pMmAllocateIndependentPages);
    uintptr_t pMiGetPteAddress = ntoskrnl_imagebase + 0xBA9F8;
    MiGetPteAddress = (MiGetPteAddress_t)(pMiGetPteAddress);

    // Init Table
    for (int i = 0; i < 64; i++) {
        List[i].VirtualAddress = MmAllocateIndependentPages(0x1000, -1);
        memset(List[i].VirtualAddress, 0, 0x1000);
        List[i].Pte = MiGetPteAddress(List[i].VirtualAddress);
        //DbgPrint("PTE: %p\n", List[i].Pte);
        List[i].OldPageFrameNumber = List[i].Pte->PageFrameNumber;
    }
    /*Test*/
    /*
    UINT32 Index = KeGetCurrentProcessorIndex();
    PEPROCESS Process;
    PsLookupProcessByProcessId((HANDLE)0x24F0, &Process);
    PUCHAR Var = (PUCHAR)Process;
    ULONG64 cr3 = *(ULONG64*)(Var + 0x28);
    DbgPrint("cr3: %x\n", cr3);
    UCHAR buffer[64];
    ReadVirtualMemory(Index, cr3, 0x7FF7EF73B000, buffer, sizeof(buffer));
    for (int i = 0; i < 64; i++) {
        DbgPrint("%x ", buffer[i]);
    }
    */

    dev_obj->Flags |= DO_BUFFERED_IO;

    for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
        driver_obj->MajorFunction[t] = unsupported_io;

    driver_obj->MajorFunction[IRP_MJ_CREATE] = create_io;
    driver_obj->MajorFunction[IRP_MJ_CLOSE] = close_io;
    driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctl_io;
    driver_obj->DriverUnload = NULL;

    dev_obj->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrint("LOAD\n");
    return STATUS_SUCCESS;
}