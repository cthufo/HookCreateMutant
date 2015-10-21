#include <ntddk.h>

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
  PVOID   ServiceTableBase;
  PULONG  ServiceCounterTableBase;
  ULONG   NumberOfService;
  ULONG   ParamTableBase;
}SERVICE_DESCRIPTOR_TABLE,*PSERVICE_DESCRIPTOR_TABLE; 

typedef NTSTATUS (*NTCREATEMUTANT)(
				     OUT PHANDLE MutantHandle,
					 IN ACCESS_MASK DesiredAccess,
					 IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
					 IN BOOLEAN InitialOwner );

extern PSERVICE_DESCRIPTOR_TABLE    KeServiceDescriptorTable;

NTCREATEMUTANT RealNtCreateMutant;

NTSTATUS MyNtCreateMutant(OUT PHANDLE MutantHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN BOOLEAN InitialOwner );

ULONG BACKUP;

VOID EnableRW()
{
	__asm
	 {
		     cli
			 mov eax,cr0
			 and eax,not 10000h
			 mov cr0,eax
	 }

}

VOID DisableRW()
{
	__asm
	   {
		       mov eax,cr0
			   or eax,10000h
			   mov cr0,eax 
			   sti
	   }

}



int SSDTHook()
{
	ULONG majorVersion, minorVersion , Address;

	Address = (ULONG)KeServiceDescriptorTable->ServiceTableBase;
	
	DbgPrint("SSDTTalbe -> %08X",(ULONG)Address);

///////////////////////////////////////////////////////////////////////////////

	PsGetVersion( &majorVersion, &minorVersion, NULL, NULL );

	if (majorVersion == 5 && minorVersion == 1)
	{
		DbgPrint("Windows XP");
		Address = (ULONG)KeServiceDescriptorTable->ServiceTableBase + 0x2B*4;

	}
	else if (majorVersion == 6 && minorVersion == 1)
	{
		DbgPrint("Windows 7");
		Address = (ULONG)KeServiceDescriptorTable->ServiceTableBase + 0x4A*4;
	}
	else
	{
		DbgPrint("Unknown Windows");
		return 0;
	}

	RealNtCreateMutant = (NTCREATEMUTANT)*(ULONG*)Address;
	
	BACKUP = *(ULONG*)Address;

	EnableRW();

	*((ULONG*)Address) = (ULONG)MyNtCreateMutant;

	DisableRW();

	return 1;
}

VOID DriverUnload(PDRIVER_OBJECT driver)
{
	ULONG majorVersion, minorVersion , Address;

	Address = (ULONG)KeServiceDescriptorTable->ServiceTableBase;
	
	DbgPrint("SSDTTalbe -> %08X",(ULONG)Address);

///////////////////////////////////////////////////////////////////////////////

	PsGetVersion( &majorVersion, &minorVersion, NULL, NULL );

	if (majorVersion == 5 && minorVersion == 1)
	{
		DbgPrint("Windows XP");
		Address = (ULONG)KeServiceDescriptorTable->ServiceTableBase + 0x2B*4;
		EnableRW();
		*((ULONG*)Address) = (ULONG)BACKUP;
		DisableRW();
	}
	else if (majorVersion == 6 && minorVersion == 1)
	{
		DbgPrint("Windows 7");
		Address = (ULONG)KeServiceDescriptorTable->ServiceTableBase + 0x4A*4;
		EnableRW();
		*((ULONG*)Address) = (ULONG)BACKUP;
		DisableRW();
	}

	DbgPrint("DriveUnload.");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT MyDriver,PUNICODE_STRING reg_path)
{
	MyDriver->DriverUnload = DriverUnload;
	SSDTHook();
	return STATUS_SUCCESS;
}

NTSTATUS MyNtCreateMutant(OUT PHANDLE MutantHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN BOOLEAN InitialOwner )
{
    NTSTATUS  status;
	
	status = RealNtCreateMutant(MutantHandle,DesiredAccess, ObjectAttributes,InitialOwner);
	
	return STATUS_SUCCESS;
}

