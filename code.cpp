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
    // 获取 PspTerminateThreadByPointerPtr 函数地址
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
    // 获取结束进程的进程结构对象EPROCESS
    status = PsLookupProcessByProcessId((HANDLE)Pid, &pEProcess);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("PsLookupProcessByProcessId Error"));
        return;
    }

    // 遍历所有线程，并结束所有指定进程的线程
    for (ULONG64 i = 4; i < 0x80000; i += 4)
    {
        //KIRQL oldIrql;
        //// 提升到 HIGH_LEVEL 以禁用中断
        //KeRaiseIrql(HIGH_LEVEL, &oldIrql);

        PETHREAD pEThread;
        status = PsLookupThreadByThreadId((HANDLE)i, &pEThread);
        if (NT_SUCCESS(status))
        {
            PEPROCESS pThreadEProcess = nullptr;
            // 获取线程对应的进程结构对象
            pThreadEProcess = PsGetThreadProcess(pEThread);

            if (pThreadEProcess != nullptr && pEProcess == pThreadEProcess)
            {
                // 结束线程
                PspTerminateThreadByPointer(pEThread, 0, 1);
                DbgPrint("PspTerminateThreadByPointer Thread:0x%x\n", i);
            }

            // 必需 Dereference，否则在某些时候会造成蓝屏
            if (pEThread != nullptr)
                ObDereferenceObject(pEThread);

            // 确保线程对应的进程对象有效
            /*if(pThreadEProcess!=nullptr)
                ObDereferenceObject(pThreadEProcess);*/
            
        }

        //// 恢复原始 IRQL
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
    // 驱动程序卸载例程&注册例程
    DriverObject->DriverUnload = DriverUnloadRoutine;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreate;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = MyWrite;
    //创建设备
    NTSTATUS status;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DeviceName;
    RtlInitUnicodeString(&DeviceName, L"\\Device\\MyDevice");
    status = IoCreateDevice(
        DriverObject,                // 驱动程序对象
        0,                           // 设备扩展大小
        &DeviceName,                 // 设备名称
        FILE_DEVICE_UNKNOWN,         // 设备类型
        0,                           // 设备特征
        FALSE,                       // 非独占设备
        &DeviceObject                // 返回的设备对象指针
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

    //DeviceObject->Flags = DO_DIRECT_IO; //使用直接IO，从UserBuffer拿数据


   

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