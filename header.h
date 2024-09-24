#pragma once
extern "C"
{
#include <ntifs.h>
#include <ntddk.h>
	NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
	VOID DriverUnloadRoutine(IN PDRIVER_OBJECT DriverObject);

}
