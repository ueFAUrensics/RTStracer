#include <Uefi.h>

#include <Guid/Acpi.h>

#include <Protocol/HiiPackageList.h>
#include <Protocol/ManagedNetwork.h>
#include <Protocol/ShellDynamicCommand.h>
#include <Protocol/Tcp4.h>

#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/NetLib.h>
#include <Library/TcpIoLib.h>

#include <Protocol/DriverBinding.h>
#include <Protocol/ComponentName2.h>
#include <Protocol/ComponentName.h>

// Global variable for Exit Boot Service event
EFI_EVENT mExitBootServiceEvent = NULL;

// Global variable for Virtual Address Map event
EFI_EVENT mSetVirtualAddressMapEvent = NULL;

// All services from MdePkg/Include/Liobrary/UefiRuntimeLib.h
static EFI_GET_TIME g_GetTime;
static EFI_SET_TIME g_SetTime;
static EFI_GET_WAKEUP_TIME g_GetWakeupTime;
static EFI_SET_WAKEUP_TIME g_SetWakeupTime;
static EFI_GET_VARIABLE g_GetVariable;
static EFI_GET_NEXT_VARIABLE_NAME g_GetNextVariableName;
static EFI_SET_VARIABLE g_SetVariable;
// static EFI_GET_NEXT_HIGH_MONOTONIC_COUNT g_GetNextHighMonotonicCount;
static EFI_RESET_SYSTEM g_ResetSystem;
static EFI_CONVERT_POINTER g_ConvertPointer;
// ConvertFunctionPointer is wrapper for VirtualAddresMap
// VirtualAddressMap
static EFI_UPDATE_CAPSULE g_UpdateCapsule;
static EFI_QUERY_CAPSULE_CAPABILITIES g_QueryCapsuleCapabilities;
static EFI_QUERY_VARIABLE_INFO g_QueryVariableInfo;

// static EFI_GET_MEMORY_MAP g_GetMemoryMap;

UINT32 cur_id = 0;

static
VOID
EFIAPI
MyNotifyExitBootServices (
    IN EFI_EVENT    Event,
    IN VOID         *Context
    )
{ }

// ====== HOOKS ======
// =======================

static
EFI_STATUS
EFIAPI 
GetTimeHook (
        OUT EFI_TIME                *Time,
        OUT EFI_TIME_CAPABILITIES   *Capabilities OPTIONAL
)
{
    EFI_STATUS status;
    status = g_GetTime(Time, Capabilities);
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetTime', 'id':%u, 't':'OUT', 'a':'Time', 'd':{'Year': %u, 'Month': %u, 'Day':%u, 'Hour':%u, 'Minute':%u, 'Second':%u, 'Pad1':%u,'Nanoseconds':%u, 'TimeZone':%u, 'Daylight':%d, 'Pad2':%u}}\n",
                cur_id,
                Time->Year,
                Time->Month,
                Time->Day,
                Time->Hour,
                Time->Minute,
                Time->Second,
                Time->Pad1,
                Time->Nanosecond,
                Time->TimeZone,
                Time->Daylight,
                Time->Pad2
                ));

    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetTime', 'id':%u, 't':'OUT', 'a':'Capabilities', 'd':{'Resolution': %u, 'Accuracy': %u, 'SetsToZero':%u}}\n",
                cur_id,
                Capabilities->Resolution,
                Capabilities->Accuracy,
                Capabilities->SetsToZero
                ));

    cur_id += 1;
    return status;
}

static
EFI_STATUS
EFIAPI 
SetTimeHook (
        IN EFI_TIME     *Time
)
{
    EFI_STATUS status;
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'SetTime', 'id':%u, 't':'IN', 'a':'Time'}\n", cur_id));
    status = g_SetTime(Time);
    cur_id += 1;
    return status;
}

static
EFI_STATUS
EFIAPI 
GetWakeupTimeHook (
        OUT BOOLEAN     *Enabled,
        OUT BOOLEAN     *Pending,
        OUT EFI_TIME    *Time
)
{
    EFI_STATUS status;
    status = g_GetWakeupTime(Enabled, Pending, Time);
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetWakeupTime', 'id':%u, 't':'OUT', 'a':'Enabled'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetWakeupTime', 'id':%u, 't':'OUT', 'a':'Pending'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetWakeupTime', 'id':%u, 't':'OUT', 'a':'Time'}\n", cur_id));
    cur_id += 1;
    return status;
}

static
EFI_STATUS
EFIAPI 
SetWakeupTimeHook (
        IN BOOLEAN     Enable,
        IN EFI_TIME    *Time OPTIONAL
)
{
    EFI_STATUS status;
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'SetWakeupTime', 'id':%u, 't':'IN', 'a':'Enabled'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'SetWakeupTime', 'id':%u, 't':'IN', 'a':'Time'}\n", cur_id));
    status = g_SetWakeupTime(Enable, Time);
    cur_id += 1;
    return status;
}

static
EFI_STATUS
EFIAPI 
GetVariableHook (
        IN CHAR16       *VariableName, 
        IN EFI_GUID     *VendorGuid, 
        OUT UINT32      *Attributes OPTIONAL,
        IN OUT UINTN    *DataSize, 
        OUT VOID        *Data OPTIONAL
)
{
    EFI_STATUS status;
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetVariable', 'id':%u, 't':'IN', 'a': 'VariableName', 'd':'%s'}\n",
                cur_id, VariableName));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetVariable', 'id':%u, 't':'IN', 'a': 'VendorGuid', 'd':{'Data1':%u, 'Data2':%u, 'Data3':%u, 'Data4':%u}}\n",
                cur_id, VendorGuid->Data1, VendorGuid->Data2, VendorGuid->Data3, VendorGuid->Data4));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetVariable', 'id':%u, 't':'IN', 'a': 'DataSize', 'd':%u}\n",
                cur_id, DataSize));
    status = g_GetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetVariable', 'id':%u, 't':'OUT', 'a': 'DataSize', 'd':%u}\n",
                cur_id, DataSize));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetVariable', 'id':%u, 't':'OUT', 'a': 'Attributes', 'd':%u}\n",
                cur_id, Attributes));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetVariable', 'id':%u, 't':'OUT', 'a': 'Data', 'd':'%p'}\n",
                cur_id, Data));

    cur_id += 1;

    return status;
}

static
EFI_STATUS
EFIAPI 
GetNextVariableNameHook (
        IN OUT UINTN    *VariableNameSize,
        IN OUT CHAR16   *VariableName,
        IN OUT EFI_GUID *VendorGuid
)
{
    EFI_STATUS status;
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetNextVariableName', 'id':%u, 't':'IN', 'a': 'VariableNameSize'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetNextVariableName', 'id':%u, 't':'IN', 'a': 'VariableName'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetNextVariableName', 'id':%u, 't':'IN', 'a': 'VendorGuid'}\n", cur_id));
    status = g_GetNextVariableName(VariableNameSize, VariableName, VendorGuid);
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetNextVariableName', 'id':%u, 't':'OUT', 'a': 'VariableNameSize'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetNextVariableName', 'id':%u, 't':'OUT', 'a': 'VariableName'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'GetNextVariableName', 'id':%u, 't':'OUT', 'a': 'VendorGuid'}\n", cur_id));
    cur_id += 1;
    return status;
}

static
EFI_STATUS
EFIAPI 
SetVariableHook (
        IN CHAR16       *VariableName, 
        IN EFI_GUID     *VendorGuid, 
        OUT UINT32      Attributes,
        IN UINTN    DataSize, 
        IN VOID        *Data
)
{
    EFI_STATUS status;
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'SetVariable', 'id':%u, 't':'IN', 'a':'VariableName', 'd':'%s'}\n",
                cur_id, VariableName));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'SetVariable', 'id':%u, 't':'IN', 'a':'VendorGuid', 'd':{'Data1':%u, 'Data2':%u, 'Data3':%u, 'Data4':%u}}\n",
                cur_id, VendorGuid->Data1, VendorGuid->Data2, VendorGuid->Data3, VendorGuid->Data4));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'SetVariable', 'id':%u, 't':'IN', 'a':'DataSize', 'd':%u}\n",
                cur_id, DataSize));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'SetVariable', 'id':%u, 't':'IN', 'a':'Data', 'd':'%p'}\n",
                cur_id, Data));
    status = g_SetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'SetVariable', 'id':%u, 't':'OUT', 'a':'Attributes', 'd':%u}\n",
                cur_id, Attributes));

    cur_id += 1;
    return status;
}

/*
static
EFI_STATUS
EFIAPI 
GetNextHighMonotonicCountHook (
        VOID
)
{
    EFI_STATUS status;
    return status
}
*/

static
VOID
EFIAPI 
ResetSystemHook (
        IN EFI_RESET_TYPE   ResetType,
        IN EFI_STATUS       ResetStatus,
        IN UINTN            DataSize,
        IN VOID             *ResetData OPTIONAL
)
{
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'ResetSystem', 'id':%u, 't':'IN', 'a':'ResetType'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'ResetSystem', 'id':%u, 't':'IN', 'a':'ResetStatus'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'ResetSystem', 'id':%u, 't':'IN', 'a':'DataSize'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'ResetSystem', 'id':%u, 't':'IN', 'a':'ResetData'}\n", cur_id));
    g_ResetSystem(ResetType, ResetStatus, DataSize, ResetData);
}

static
EFI_STATUS
EFIAPI 
ConvertPointerHook (
        OUT UINTN       DebugDisposition,
        IN  OUT VOID    **Address
)
{
    EFI_STATUS status;
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'ConvertPointer', 'id':%u, 't':'IN', 'a':'Address', 'd':'%p'}\n",
                cur_id, Address));
    status = g_ConvertPointer(DebugDisposition, Address);
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'ConvertPointer', 'id':%u, 't':'OUT', 'a':'Address', 'd':'%p'}\n",
                cur_id, Address));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'ConvertPointer', 'id':%u, 't':'OUT', 'a':'DebugDisposition', 'd':%u}\n",
                cur_id, DebugDisposition));

    cur_id += 1;
    return status;
}

static
EFI_STATUS
EFIAPI 
UpdateCapsuleHook (
        IN EFI_CAPSULE_HEADER   **CapsuleHeaderArray,
        IN UINTN                CapsuleCount,
        IN EFI_PHYSICAL_ADDRESS ScatterGatherList OPTIONAL
)
{
    EFI_STATUS status;
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'UpdateCapsule', 'id':%u, 't':'IN', 'a':'CapsuleHeaderArray'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'UpdateCapsule', 'id':%u, 't':'IN', 'a':'CapsuleCount'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'UpdateCapsule', 'id':%u, 't':'IN', 'a':'ScatterGatherList'}\n", cur_id));
    status = g_UpdateCapsule(CapsuleHeaderArray, CapsuleCount, ScatterGatherList);
    cur_id += 1;
    return status;
}

static
EFI_STATUS
EFIAPI 
QueryCapsuleCapabilitiesHook (
        IN EFI_CAPSULE_HEADER   **CapsuleHeaderArray,
        IN UINTN                CapsuleCount,
        OUT UINT64              *MaximumCapsuleSize,
        OUT EFI_RESET_TYPE      *ResetType
)
{
    EFI_STATUS status;
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'QueryCapsuleCapabilities', 'id':%u, 't':'IN', 'a':'CapsuleHeaderArray'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'QueryCapsuleCapabilities', 'id':%u, 't':'IN', 'a':'CapsuleCount'}\n", cur_id));
    status = g_QueryCapsuleCapabilities(CapsuleHeaderArray, CapsuleCount, MaximumCapsuleSize, ResetType);
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'QueryCapsuleCapabilities', 'id':%u, 't':'OUT', 'a':'MaximumCapsuleSize'}\n", cur_id));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'QueryCapsuleCapabilities', 'id':%u, 't':'OUT', 'a':'ResetType'}\n", cur_id));
    cur_id += 1;
    return status;
}

static
EFI_STATUS
EFIAPI 
QueryVariableInfoHook (
        IN UINT32   Attributes,
        OUT UINT64  *MaximumVariableStorageSize,
        OUT UINT64  *RemainingVariableStorageSize,
        OUT UINT64  *MaximumVariableSize
)
{
    EFI_STATUS status;
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'QueryVariableInfo', 'id':%u, 't':'IN', 'a':'Attributes', 'd':%u}\n",
                cur_id, Attributes));
    status = g_QueryVariableInfo(Attributes, MaximumVariableStorageSize, RemainingVariableStorageSize, MaximumVariableSize);
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'QueryVariableInfo', 'id':%u, 't':'IN', 'a':'MaximumVariableStorageSize', 'd':%u}\n",
                cur_id, MaximumVariableStorageSize));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'QueryVariableInfo', 'id':%u, 't':'IN', 'a':'RemainingVariableStorageSize', 'd':%u}\n",
                cur_id, RemainingVariableStorageSize));
    DEBUG ((EFI_D_INFO, "[RtsTracer]{'m': 'QueryVariableInfo', 'id':%u, 't':'IN', 'a':'MaximumVariableSize', 'd':%u}\n",
                cur_id, MaximumVariableSize));

    cur_id += 1;
    return status;
}

// ====== END HOOKS ======
// =======================

static
VOID
EFIAPI
MyNotifySetVirtalAddressMap (
    IN EFI_EVENT    EVENT,
    IN VOID         *Context
    )
{
    EFI_STATUS Status;
    VOID* currentAddress;

    currentAddress = (VOID*)g_GetTime;
    Status = EfiConvertPointer(0, (VOID**)&g_GetTime);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] GetTime realocated from %p to %p\n",
                currentAddress, g_GetTime));

    currentAddress = (VOID*)g_SetTime;
    Status = EfiConvertPointer(0, (VOID**)&g_SetTime);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] SetTime realocated from %p to %p\n",
                currentAddress, g_SetTime));

    currentAddress = (VOID*)g_GetWakeupTime;
    Status = EfiConvertPointer(0, (VOID**)&g_GetWakeupTime);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] GetWakeupTime realocated from %p to %p\n",
                currentAddress, g_GetWakeupTime));

    currentAddress = (VOID*)g_SetWakeupTime;
    Status = EfiConvertPointer(0, (VOID**)&g_SetWakeupTime);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] SetWakeupTime realocated from %p to %p\n",
                currentAddress, g_SetWakeupTime));

    currentAddress = (VOID*)g_GetVariable;
    Status = EfiConvertPointer(0, (VOID**)&g_GetVariable);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] GetVariable realocated from %p to %p\n",
                currentAddress, g_GetVariable));

    currentAddress = (VOID*)g_GetNextVariableName;
    Status = EfiConvertPointer(0, (VOID**)&g_GetNextVariableName);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] GetNextVariableName realocated from %p to %p\n",
                currentAddress, g_GetNextVariableName));

    currentAddress = (VOID*)g_SetVariable;
    Status = EfiConvertPointer(0, (VOID**)&g_SetVariable);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] SetVariable realocated from %p to %p\n",
                currentAddress, g_SetVariable));

    currentAddress = (VOID*)g_ResetSystem;
    Status = EfiConvertPointer(0, (VOID**)&g_ResetSystem);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] ResetSystem realocated from %p to %p\n",
                currentAddress, g_ResetSystem));

    currentAddress = (VOID*)g_ConvertPointer;
    Status = EfiConvertPointer(0, (VOID**)&g_ConvertPointer);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] ConvertPointer realocated from %p to %p\n",
                currentAddress, g_ConvertPointer));

    currentAddress = (VOID*)g_UpdateCapsule;
    Status = EfiConvertPointer(0, (VOID**)&g_UpdateCapsule);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] UpdateCapsule realocated from %p to %p\n",
                currentAddress, g_UpdateCapsule));

    currentAddress = (VOID*)g_QueryCapsuleCapabilities;
    Status = EfiConvertPointer(0, (VOID**)&g_QueryCapsuleCapabilities);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] QueryCapsuleCapabilities realocated from %p to %p\n",
                currentAddress, g_QueryCapsuleCapabilities));

    currentAddress = (VOID*)g_QueryVariableInfo;
    Status = EfiConvertPointer(0, (VOID**)&g_QueryVariableInfo);
    ASSERT_EFI_ERROR(Status);
    DEBUG((EFI_D_INFO, "[RtsTracer] QueryVariableInfo realocated from %p to %p\n",
                currentAddress, g_QueryVariableInfo));

    // currentAddress = (VOID*)g_GetMemoryMap;
    // Status = EfiConvertPointer(0, (VOID**)&g_GetMemoryMap);
    // ASSERT_EFI_ERROR(Status);
    // DEBUG((EFI_D_INFO, "[RtsTracer] GetMemoryMap realocated from %p to %p\n",
                // currentAddress, g_GetMemoryMap));
}

static
EFI_STATUS
ExchangePointerInServiceTable (
        IN OUT VOID** AddressToUpdate,
        IN VOID* NewPointer,
        OUT VOID** OriginalPointer OPTIONAL
        )
{
    EFI_STATUS status;
    EFI_TPL tpl;

    ASSERT(*AddressToUpdate != NewPointer);

    // Disable interrupt
    tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);

    if (OriginalPointer != NULL)
        *OriginalPointer = *AddressToUpdate;
    *AddressToUpdate = NewPointer;

    // Update the CRC32 in the EFI System Table header
    gST->Hdr.CRC32 = 0;
    status = gBS->CalculateCrc32(&gST->Hdr, gST->Hdr.HeaderSize, &gST->Hdr.CRC32);
    ASSERT_EFI_ERROR(status);

    gBS->RestoreTPL(tpl);
    return status;
}

EFI_STATUS
EFIAPI
RtsTracerCommandInitialize (
  IN EFI_HANDLE                 ImageHandle,
  IN EFI_SYSTEM_TABLE           *SystemTable
  )
{
  DEBUG ((EFI_D_INFO, "[RtsTracer] Start service\n"));
  EFI_STATUS    status;
   
  // Catch Exit Boot Event
  status = gBS->CreateEvent (
          EVT_SIGNAL_EXIT_BOOT_SERVICES,
          TPL_NOTIFY,
          MyNotifyExitBootServices,
          NULL,
          &mExitBootServiceEvent
          );
  ASSERT_EFI_ERROR (status);

  // Catch Virt Addr Change Event
  status = gBS->CreateEvent (
          EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE,
          TPL_NOTIFY,
          MyNotifySetVirtalAddressMap,
          NULL,
          &mSetVirtualAddressMapEvent
          );
  ASSERT_EFI_ERROR (status);
 
  // Hook the var functions

  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->GetTime,
                                         (VOID*)GetTimeHook,
                                         (VOID**)&g_GetTime);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook GetTime failed: %r\n", status));

  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->SetTime,
                                         (VOID*)SetTimeHook,
                                         (VOID**)&g_SetTime);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook SetTime failed: %r\n", status));

  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->GetWakeupTime,
                                         (VOID*)GetWakeupTimeHook,
                                         (VOID**)&g_GetWakeupTime);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook GetWakeupTime failed: %r\n", status));

  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->SetWakeupTime,
                                         (VOID*)SetWakeupTimeHook,
                                         (VOID**)&g_SetWakeupTime);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook SetWakeupTime failed: %r\n", status));

  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->GetVariable,
                                         (VOID*)GetVariableHook,
                                         (VOID**)&g_GetVariable);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook GetVariable failed: %r\n", status));
 
  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->GetNextVariableName,
                                         (VOID*)GetNextVariableNameHook,
                                         (VOID**)&g_GetNextVariableName);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook GetNextVariableName failed: %r\n", status));
 
  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->SetVariable,
                                         (VOID*)SetVariableHook,
                                         (VOID**)&g_SetVariable);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook SetVariable failed: %r\n", status));
  
  /*
  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->GetNextHighMonotonicCount,
                                         (VOID*)GetNextHighMonotonicCountHook,
                                         (VOID**)&g_GetNextHighMonotonicCount);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook GetNextHighMonotonicCount failed: %r\n", status));
 */

  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->ResetSystem,
                                         (VOID*)ResetSystemHook,
                                         (VOID**)&g_ResetSystem);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook ResetSystem failed: %r\n", status));
 
  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->ConvertPointer,
                                         (VOID*)ConvertPointerHook,
                                         (VOID**)&g_ConvertPointer);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook ConvertPointer failed: %r\n", status));

  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->UpdateCapsule,
                                         (VOID*)UpdateCapsuleHook,
                                         (VOID**)&g_UpdateCapsule);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook UpdateCapsule failed: %r\n", status));
 
  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->QueryCapsuleCapabilities,
                                         (VOID*)QueryCapsuleCapabilitiesHook,
                                         (VOID**)&g_QueryCapsuleCapabilities);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook QueryCapsuleCapabilities failed: %r\n", status));
 
  status = ExchangePointerInServiceTable((VOID**)&gST->RuntimeServices->QueryVariableInfo,
                                         (VOID*)QueryVariableInfoHook,
                                         (VOID**)&g_QueryVariableInfo);
  if (EFI_ERROR(status))
    DEBUG((DEBUG_ERROR, "[RtsTracer] Hook QueryVariableInfo failed: %r\n", status));

  // g_GetMemoryMap = gBS->GetMemoryMap;
  DEBUG ((EFI_D_INFO, "[RtsTracer] Successfully hooked functions\n"));
  return status;
}

