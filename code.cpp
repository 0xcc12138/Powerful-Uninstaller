#include "header.h"

VOID Delete_Process();
ULONG64 Pid = 0;

ULONG WideStringToULong(const UNICODE_STRING& unicodeStr)
{
    ULONG value = 0;
    NTSTATUS status = RtlUnicodeStringToInteger(&unicodeStr, 10, &value);
    if (!NT_SUCCESS(status))
    {
        // Handle the error (e.g., log, return a default value, etc.)
        return 0;
    }
    return value;
}


// MyWrite
NTSTATUS MyWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    //KdBreakPoint();
    DeviceObject;
    // PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(Irp);
    VOID* lpBuf = Irp->UserBuffer; // Use SystemBuffer
    if(!lpBuf)
        lpBuf = Irp->AssociatedIrp.SystemBuffer;

    KdPrint(("Write\n"));
    
    __try {
        //DEVICE_EXTENSION* device_extension_ptr = (DEVICE_EXTENSION*)DeviceObject->DeviceExtension;
        // Validate and probe user buffer
        if (MmIsAddressValid(lpBuf)) {
            ProbeForRead(lpBuf, sizeof(lpBuf), 1);
        }
        else {
            KdPrint(("Invalid user buffer address\n"));
            Irp->IoStatus.Status = STATUS_INVALID_USER_BUFFER;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INVALID_USER_BUFFER;
        }

        UNICODE_STRING unicodeStr;
        RtlInitUnicodeString(&unicodeStr, (PCWSTR)lpBuf);

        Pid = WideStringToULong(unicodeStr);

        


        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = wcslen((const wchar_t*)lpBuf) * sizeof(TCHAR);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Exception occurred: Access violation\n"));
        // Set IRP status for exception
        Irp->IoStatus.Status = GetExceptionCode();
        Irp->IoStatus.Information = 0;
    }
    // Complete the request
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    KdPrint(("0x%x", Pid));


    Delete_Process();
    Pid = 0;

    return Irp->IoStatus.Status;
}



NTSTATUS MyCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    DbgPrint("Create!\n");
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}



VOID Delete_Process()
{
    //KdBreakPoint();
    // ��ȡ PspTerminateThreadByPointerPtr ������ַ
    unsigned char* Func_Ptr = (unsigned char*)PsTerminateSystemThread;
    while (*Func_Ptr != 0xE8)
    {
        Func_Ptr++;
    }

    Func_Ptr++;
    int Offset = *(int*)Func_Ptr;
    NTSTATUS(*PspTerminateThreadByPointer)(PETHREAD pEThread, NTSTATUS ntExitCode, BOOLEAN bDirectTerminate);
    PspTerminateThreadByPointer = (NTSTATUS(*)(PETHREAD, NTSTATUS, BOOLEAN))(Func_Ptr - 1 + Offset + 5);

    NTSTATUS status;

    PEPROCESS pEProcess;
    // ��ȡ�������̵Ľ��̽ṹ����EPROCESS
    status = PsLookupProcessByProcessId((HANDLE)Pid, &pEProcess);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("PsLookupProcessByProcessId Error"));
        return;
    }

    // ���������̣߳�����������ָ�����̵��߳�
    for (ULONG64 i = 4; i < 0x80000; i += 4)
    {
        //KIRQL oldIrql;
        //// ������ HIGH_LEVEL �Խ����ж�
        //KeRaiseIrql(HIGH_LEVEL, &oldIrql);

        PETHREAD pEThread;
        status = PsLookupThreadByThreadId((HANDLE)i, &pEThread);
        if (NT_SUCCESS(status))
        {
            PEPROCESS pThreadEProcess = nullptr;
            // ��ȡ�̶߳�Ӧ�Ľ��̽ṹ����
            pThreadEProcess = PsGetThreadProcess(pEThread);

            if (pThreadEProcess != nullptr && pEProcess == pThreadEProcess)
            {
                // �����߳�
                PspTerminateThreadByPointer(pEThread, 0, 1);
                DbgPrint("PspTerminateThreadByPointer Thread:0x%x\n", i);
            }

            // ���� Dereference��������ĳЩʱ����������
            if (pEThread != nullptr)
                ObDereferenceObject(pEThread);

            // ȷ���̶߳�Ӧ�Ľ��̶�����Ч
            /*if(pThreadEProcess!=nullptr)
                ObDereferenceObject(pThreadEProcess);*/
            
        }

        //// �ָ�ԭʼ IRQL
        //KeLowerIrql(oldIrql);
    }
    
    KdPrint(("Finish\n"));
    if (pEProcess != nullptr)
        ObDereferenceObject(pEProcess);
}



NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    KdPrint(("Create!"));
    //KdBreakPoint();
    // ��������ж������&ע������
    DriverObject->DriverUnload = DriverUnloadRoutine;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreate;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = MyWrite;
    //�����豸
    NTSTATUS status;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DeviceName;
    RtlInitUnicodeString(&DeviceName, L"\\Device\\MyDevice");
    status = IoCreateDevice(
        DriverObject,                // �����������
        0,                           // �豸��չ��С
        &DeviceName,                 // �豸����
        FILE_DEVICE_UNKNOWN,         // �豸����
        0,                           // �豸����
        FALSE,                       // �Ƕ�ռ�豸
        &DeviceObject                // ���ص��豸����ָ��
    );

    if (!NT_SUCCESS(status))
    {
        KdPrint(("Failed to create device: %X\n", status));
        return status;
    }
    KdPrint(("Device created successfully\n"));

    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\MyDevice_Link");
    status = IoCreateSymbolicLink(&symbolicLink, &DeviceName);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("Failed to create device: %X\n", status));
        return status;
    }
    KdPrint(("Device created successfully\n"));

    //DeviceObject->Flags = DO_DIRECT_IO; //ʹ��ֱ��IO����UserBuffer������


   

    return STATUS_SUCCESS;
}


VOID DriverUnloadRoutine(IN PDRIVER_OBJECT DriverObject)
{
    if (DriverObject->DeviceObject != NULL)
    {
        UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\MyDevice_Link");
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrint("Driver unloaded\n");
}