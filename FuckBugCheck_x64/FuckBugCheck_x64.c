#include <ntddk.h>
#include <intrin.h>

// ԭʼ�����ֽڱ���
CHAR KeBugCheckExOriginal[12] = { 0 };
ULONG_PTR KeBugCheckExAddress = 0;

// ��ȫ�ָ�������
typedef struct _SAFE_CONTEXT {
    ULONG_PTR OriginalRip;
    ULONG_PTR OriginalRsp;
    KIRQL OriginalIrql;
} SAFE_CONTEXT, * PSAFE_CONTEXT;

// �Զ�������������
void KeHookedBugCheckEx(
    ULONG BugCheckCode,
    ULONG_PTR Code1,
    ULONG_PTR Code2,
    ULONG_PTR Code3,
    ULONG_PTR Code4)
{
    UNREFERENCED_PARAMETER(BugCheckCode);
    UNREFERENCED_PARAMETER(Code1);
    UNREFERENCED_PARAMETER(Code2);
    UNREFERENCED_PARAMETER(Code3);
    UNREFERENCED_PARAMETER(Code4);

    // ��ȡ��ǰִ��������
    PSAFE_CONTEXT ctx = ExAllocatePool(NonPagedPool, sizeof(SAFE_CONTEXT));
    if (ctx) {
        ctx->OriginalIrql = KeGetCurrentIrql();
        ctx->OriginalRsp = __readgsqword(0x1F8); // ��ȡ�û�ģʽRSP
        ctx->OriginalRip = __readgsqword(0x08);  // ��ȡ�û�ģʽRIP

        // ǿ�ƽ���IRQL����
        while (KeGetCurrentIrql() > PASSIVE_LEVEL) {
            KeLowerIrql(KeGetCurrentIrql() - 1);
        }

        // �ָ��ؼ��Ĵ���״̬
        __writegsqword(0x1F8, ctx->OriginalRsp);
        __writegsqword(0x08, ctx->OriginalRip);

        ExFreePool(ctx);
    }

    // ����ϵͳ����
    while (TRUE) {
        __halt();
    }
}

NTSTATUS MemoryPatch(PVOID TargetAddress, PVOID PatchData, SIZE_T PatchSize)
{
    PMDL pMdl = IoAllocateMdl(TargetAddress, (ULONG)PatchSize, FALSE, FALSE, NULL);
    if (!pMdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(pMdl, KernelMode, IoModifyAccess);
        PVOID MappedAddress = MmMapLockedPagesSpecifyCache(
            pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

        if (MappedAddress) {
            RtlCopyMemory(MappedAddress, PatchData, PatchSize);
            MmUnmapLockedPages(MappedAddress, pMdl);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(pMdl);
        return GetExceptionCode();
    }

    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // �ָ�ԭʼ�����ֽ�
    if (KeBugCheckExAddress && KeBugCheckExOriginal[0] != 0) {
        MemoryPatch((PVOID)KeBugCheckExAddress,
            KeBugCheckExOriginal,
            sizeof(KeBugCheckExOriginal));
    }
    DbgPrint("[Driver] Unloaded\n");
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    // ��ȡKeBugCheckEx��ַ
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"KeBugCheckEx");
    KeBugCheckExAddress = (ULONG_PTR)MmGetSystemRoutineAddress(&funcName);

    if (!KeBugCheckExAddress) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // ����ԭʼ�ֽ�
    RtlCopyMemory(KeBugCheckExOriginal, (PVOID)KeBugCheckExAddress, sizeof(KeBugCheckExOriginal));

    // ����x64��תָ��
#if defined(_M_X64)
    UCHAR jmpCode[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, address
        0xFF, 0xE0                                                  // jmp rax
    };
    *(ULONG_PTR*)(jmpCode + 2) = (ULONG_PTR)KeHookedBugCheckEx;
#endif

    // Ӧ�ò���
    NTSTATUS status = MemoryPatch(
        (PVOID)KeBugCheckExAddress,
        jmpCode,
        sizeof(jmpCode));

    if (!NT_SUCCESS(status)) {
        DbgPrint("Patching failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[Driver] Loaded\n");
    return STATUS_SUCCESS;
}