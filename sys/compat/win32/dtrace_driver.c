/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*++

Copyright (c) Microsoft Corporation

Module Name:

    dtrace_driver.c

Abstract:

    This file implements the Dtrace/NT driver framework.

--*/

#include <stdlib.h>
#include <sys/dtrace.h>
#include "dtracep.h"
#include <ntdtrace.h>
#include <wdmsec.h>

typedef struct _DT_DEVICE_EXTENSION {
    LIST_ENTRY Links;
    UNICODE_STRING Name;
    ULONG TotalContextSize;
    LIST_ENTRY Handlers;
} DT_DEVICE_EXTENSION, *PDT_DEVICE_EXTENSION;


typedef struct _DT_DEVICE_EXTENSION_HANDLER {
    LIST_ENTRY Links;
    ULONG RegistrationId;
    ULONG ContextSize;
    __volatile LONG OpenCount;
    PCTRACE_CONTROL_CALLBACKS Callbacks;
} DT_DEVICE_EXTENSION_HANDLER, *PDT_DEVICE_EXTENSION_HANDLER;


NTSTATUS
DtDrvRegisterControlExtension (
    _In_opt_ PCUNICODE_STRING Name,
    _In_opt_ ULONG ContextSize,
    _In_opt_ PCTRACE_CONTROL_CALLBACKS Callbacks,
    _Out_ PULONG RegistrationId
    );

VOID
DtDrvUnregisterControlExtension (
    _In_ ULONG RegistrationId
    );

NTTRACE_PROVIDER_ID
DtDrvProviderRegister (
    _In_ PCSZ ProviderName,
    _In_opt_ PVOID ProviderContext,
    _In_ PCTRACE_PROVIDER_CALLBACKS Callbacks,
    _In_ TRACE_PROVIDER_ACCESS AccessLevel
    );

const TRACE_ENGINE DtEngineApi = {
    .Size = sizeof(TRACE_ENGINE),
    .ProviderRegister   = DtDrvProviderRegister,
    .ProviderUnregister = dtrace_unregister,
    .ProviderCleanup    = dtrace_condense,
    .ProbeLookup        = dtrace_probe_lookup,
    .ProbeCreate        = dtrace_probe_create,
    .ProbeFire          = dtrace_probe,
    .ModuleUnloaded     = dtrace_module_unloaded,
    .RegisterControlExtension   = DtDrvRegisterControlExtension,
    .UnregisterControlExtension = DtDrvUnregisterControlExtension,
};

static PCTRACE_ENGINE_HELPERS DtEngineHelpers;

static dtrace_pattr_t DtProviderAttributes = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE,  DTRACE_STABILITY_PRIVATE,  DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE,  DTRACE_STABILITY_PRIVATE,  DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE,  DTRACE_STABILITY_PRIVATE,  DTRACE_CLASS_ISA },
};


#pragma const_seg(push, "INITCONST")

const UNICODE_STRING DtDrvSddlString =
    RTL_CONSTANT_STRING(L"D:(A;;GA;;;SY)(A;;GA;;;BA)");

const UNICODE_STRING DtDrvDeviceNameString =
    RTL_CONSTANT_STRING(L"\\Device\\DTrace");

#pragma const_seg(pop)

#pragma const_seg(push, "PAGECONST")

const UNICODE_STRING DtDrvSymlink =
    RTL_CONSTANT_STRING(L"\\GLOBAL??\\DTrace");

const UNICODE_STRING DtProvidersDirectoryName =
    RTL_CONSTANT_STRING(L"provider");

const UNICODE_STRING DtDtraceControlDeviceName =
    RTL_CONSTANT_STRING(L"dtrace");

#pragma const_seg(pop)


#pragma bss_seg(push, "PAGEDATAZ")

//
// A pointer to the device object.
//

PDEVICE_OBJECT DtDeviceObject;
BOOLEAN DtEngineRegistered;

//
// The list of registered extensions.
//

LIST_ENTRY DtDeviceExtensions;
ULONG DtDeviceExtensionId;

//
// Two built-in elements - providers directory and
// control device id.
//

ULONG DtProvidersDirectoryId;
ULONG DtDtraceControlDeviceId;

#pragma bss_seg(pop)

//
// Prototypes.
//

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DtDrvUnload;
DRIVER_DISPATCH DtDevCreate;
DRIVER_DISPATCH DtDevClose;
DRIVER_DISPATCH DtDevControl;


#pragma code_seg(push, "PAGE")

NTSTATUS
DtDrvErrorToStatus (
    _In_ int error
    )

/*++

Routine Description:

    This routine converts one of known error codes to corresponding
    NTSTATUS values.

Arguments:

    error - Error code.

Return Value:

    NTSTATUS - Matching error code.

--*/

{

    PAGED_CODE();

    switch (error) {
    case 0:
        return STATUS_SUCCESS;

    case EINVAL:
        return STATUS_INVALID_PARAMETER;

    case EFAULT:
        return STATUS_ACCESS_VIOLATION;

    case EBUSY:
        return STATUS_INVALID_DEVICE_STATE;

    case ENOENT:
        return STATUS_NOT_FOUND;

    case ESRCH:
        return STATUS_NO_MATCH;

    case ENOTTY:
        return STATUS_INVALID_DEVICE_REQUEST;

    case EACCES:
        return STATUS_ACCESS_DENIED;

    default:
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS
DtDtraceControlDeviceControl (
    _In_opt_ PVOID Context,
    _In_ PIRP Irp,
    _Out_ PULONG BytesDone
    )

/*++

Routine Description:

    This routine implements the DTrace device control routine..

Arguments:

    Context - A pointer to the control device context.

    Irp - Supplies the Irp being processed

    BytesDone - Number of bytes written as output. Since this is Type3,
        the return will always be zero.

Return Value:

    NTSTATUS - Return status of the operation.

--*/

{

    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;
    int rv;

    PAGED_CODE();

    NT_ASSERT_ASSUME(ARGUMENT_PRESENT(Context));

    *BytesDone = 0;
    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    //
    // All expected control codes provide a pointer to original the user-mode
    // buffer that is used for both input and output. Buffer validation is
    // done entirely by the dtrace ioctl handler.
    // This mode preserves the semantics of the PUSIX ioctl() that is used
    // by the dtrace user-mode code.
    //

    if (METHOD_NEITHER != METHOD_FROM_CTL_CODE(IrpSp->Parameters.DeviceIoControl.IoControlCode)) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    rv = dtrace_ioctl(*(struct dtrace_state**)Context,
                      IrpSp->Parameters.DeviceIoControl.IoControlCode,
                      IrpSp->Parameters.DeviceIoControl.Type3InputBuffer);

    if (rv) {
        Status = DtDrvErrorToStatus(rv);
        goto Exit;
    }

    Status = STATUS_SUCCESS;

Exit:
    return Status;
}

NTSTATUS
DtDtraceControlDeviceOpen (
    _In_opt_ PVOID Context,
    _In_ PIRP Irp,
    _In_opt_ PCUNICODE_STRING ExtraPath
    )

/*++

Routine Description:

    This routine initializes the Dtrace control device.

Arguments:

    Context - A pointer to the control device context.

    Irp - 'create' IRP

    ExtraPath - Remaining path.

Return Value:

    NTSTATUS - Return status of the operation.

--*/

{

    NTSTATUS Status;

    PAGED_CODE();

    NT_ASSERT_ASSUME(ARGUMENT_PRESENT(Context));

    if (ARGUMENT_PRESENT(ExtraPath) && (0 != ExtraPath->Length)) {
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Exit;
    }

    if (0 != dtrace_open(IoGetCurrentIrpStackLocation(Irp)->DeviceObject,
                         (struct dtrace_state**)Context)) {

        Status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    Status = STATUS_SUCCESS;

Exit:
    return Status;
}

VOID
DtDtraceControlDeviceClose (
    _In_opt_ PVOID Context
    )

/*++

Routine Description:

    This routine closes the DTrace control device.

Arguments:

    Context - A pointer to the control device context.

Return Value:

    None.

--*/

{

    PAGED_CODE();

    NT_ASSERT_ASSUME(ARGUMENT_PRESENT(Context));
    dtrace_close(*(struct dtrace_state**)Context);
    return;
}

NTTRACE_PROVIDER_ID
DtDrvProviderRegister (
    _In_ PCSZ ProviderName,
    _In_opt_ PVOID ProviderContext,
    _In_ PCTRACE_PROVIDER_CALLBACKS Callbacks,
    _In_ TRACE_PROVIDER_ACCESS AccessLevel
    )

/*++

Routine Description:

    This function registers a trace probe provider with DTrace engine

Arguments:

    ProviderName - Name of the probe provider.

    ProviderContext - Provider's context.

    Callbacks - A pointer to the provider's callbacks.

    AccessLevel - Provider privileges.

Return Value:

    NTTRACE_PROVIDER_ID - Return the ID of the provider or 0 if unsuccessful.

--*/

{

    dtrace_provider_id_t id;
    dtrace_pops_t pops;
    int rv;

    PAGED_CODE();

    C_ASSERT(TRACE_PROVIDER_ACCESS_None    == DTRACE_PRIV_NONE);
    C_ASSERT(TRACE_PROVIDER_ACCESS_Kernel  == DTRACE_PRIV_KERNEL);
    C_ASSERT(TRACE_PROVIDER_ACCESS_User    == DTRACE_PRIV_USER);
    C_ASSERT(TRACE_PROVIDER_ACCESS_Process == DTRACE_PRIV_PROC);

    RtlZeroMemory(&pops, sizeof(pops));
    pops.dtps_provide    = Callbacks->Provide;
    pops.dtps_enable     = Callbacks->Enable;
    pops.dtps_disable    = Callbacks->Disable;
    pops.dtps_destroy    = Callbacks->Destroy;
    pops.dtps_getargdesc = Callbacks->GetArgumentType;
    pops.dtps_getargval  = Callbacks->GetArgument;
    pops.dtps_getframe   = Callbacks->GetContext;

    rv = dtrace_register(ProviderName, &DtProviderAttributes,
                         AccessLevel, NULL, &pops, ProviderContext, &id);

    if (0 != rv) {
        return 0;
    }

    return id;
}

_Use_decl_annotations_
NTSTATUS
DtDevClose (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )

/*++

Routine Description:

    This routine implements the device object delete callback.

Arguments:

    DeviceObject - Supplies the device object to handle its last dereference.

    Irp - Supplies the Irp being processed

Return Value:

    NTSTATUS - Return status of the operation.

--*/

{

    PFILE_OBJECT FileObject;
    PDT_DEVICE_EXTENSION Extension;
    PDT_DEVICE_EXTENSION_HANDLER Handler;
    PVOID ContextPtr;
    PVOID Context;
    PLIST_ENTRY Links;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    Extension = (PDT_DEVICE_EXTENSION)FileObject->FsContext;
    if (NULL == Extension) {
        goto exit;
    }

    ContextPtr = FileObject->FsContext2;
    Context = ContextPtr;

    for (Links = Extension->Handlers.Flink;
         Links != &Extension->Handlers;
         Links = Links->Flink) {

        Handler = CONTAINING_RECORD(Links, DT_DEVICE_EXTENSION_HANDLER, Links);
        if ((NULL != Handler->Callbacks) &&
            (Handler->Callbacks->Size >=
             RTL_SIZEOF_THROUGH_FIELD(TRACE_CONTROL_CALLBACKS, Close)) &&
            NULL != Handler->Callbacks->Close) {

            Handler->Callbacks->Close(Context);
        }

        InterlockedDecrement(&Handler->OpenCount);
        Context = RtlOffsetToPointer(Context, ALIGN_UP(Handler->ContextSize, 16));
    }

    if (NULL != ContextPtr) {
        ExFreePool(ContextPtr);
    }

exit:
    //
    // Complete the request with success.
    // Nobody ever looks at the result of the close operation.
    //

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DtDevControl (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )

/*++

Routine Description:

    This routine implements the device control callback.

Arguments:

    DeviceObject - Supplies the device object.

    Irp - Supplies the Irp being processed

Return Value:

    NTSTATUS - Return status of the operation.

--*/

{

    NTSTATUS Status;
    ULONG BytesDone;
    PFILE_OBJECT FileObject;
    PDT_DEVICE_EXTENSION Extension;
    PDT_DEVICE_EXTENSION_HANDLER Handler;
    PVOID ContextPtr;
    PVOID Context;
    PLIST_ENTRY Links;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    BytesDone = 0;
    Status = STATUS_INVALID_DEVICE_REQUEST;

    FileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    Extension = (PDT_DEVICE_EXTENSION)FileObject->FsContext;
    if (NULL == Extension) {
        goto exit;
    }

    ContextPtr = FileObject->FsContext2;
    Context = ContextPtr;

    for (Links = Extension->Handlers.Flink;
         Links != &Extension->Handlers;
         Links = Links->Flink) {

        Handler = CONTAINING_RECORD(Links, DT_DEVICE_EXTENSION_HANDLER, Links);
        if ((NULL != Handler->Callbacks) &&
            (Handler->Callbacks->Size >=
             RTL_SIZEOF_THROUGH_FIELD(TRACE_CONTROL_CALLBACKS, IoControl)) &&
            NULL != Handler->Callbacks->IoControl) {

            Status = Handler->Callbacks->IoControl(Context, Irp, &BytesDone);
            break; // only the first one.
        }

        Context = RtlOffsetToPointer(Context, ALIGN_UP(Handler->ContextSize, 16));
    }

exit:
    if (STATUS_PENDING != Status) {
        Irp->IoStatus.Information = BytesDone;
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return Status;
}

_Use_decl_annotations_
NTSTATUS
DtDevCreate (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )

/*++

Routine Description:

    This routine implements the driver part of the NtCreateFile and NtOpenFile
    API calls.

Arguments:

    DeviceObject - Supplies the device object where the
        file/directory exists that we are trying to open/create

    Irp - Supplies the Irp being processed

Return Value:

    NTSTATUS - Return status of the operation.

--*/

{

    PFILE_OBJECT FileObject;
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;
    NTSTATUS ThisStatus;
    UNICODE_STRING FirstName;
    UNICODE_STRING RemainingName;
    PDT_DEVICE_EXTENSION Extension;
    PDT_DEVICE_EXTENSION_HANDLER Handler;
    PVOID ContextPtr;
    PVOID Context;
    PLIST_ENTRY Links;
    BOOLEAN HandlerFound;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);
    ContextPtr = NULL;

    //
    // Reference the stack location and the file object.
    //

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    FileObject = IrpSp->FileObject;

    //
    // Relative opens are not implemented.
    //

    if (NULL != FileObject->RelatedFileObject) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    //
    // Lookup the handler for the path.
    //

    FsRtlDissectName(FileObject->FileName, &FirstName, &RemainingName);
    Extension = NULL;

    for (Links = DtDeviceExtensions.Flink;
         Links != &DtDeviceExtensions;
         Links = Links->Flink) {

        Extension = CONTAINING_RECORD(Links, DT_DEVICE_EXTENSION, Links);

        if (RtlEqualUnicodeString(&Extension->Name, &FirstName, TRUE)) {
            break;
        }

        Extension = NULL;
    }

    if (NULL == Extension) {
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Exit;
    }

    if (0 != Extension->TotalContextSize) {
        ContextPtr = ExAllocatePoolWithTag(NonPagedPoolNx,
                                           Extension->TotalContextSize,
                                           'crtD');

        if (NULL == ContextPtr) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        RtlZeroMemory(ContextPtr, Extension->TotalContextSize);
        Context = ContextPtr;
    }

    Status = STATUS_SUCCESS;
    for (Links = Extension->Handlers.Flink;
         Links != &Extension->Handlers;
         Links = Links->Flink) {

        Handler = CONTAINING_RECORD(Links, DT_DEVICE_EXTENSION_HANDLER, Links);

        for (;;) {
            LONG OldCount = ReadForWriteAccess(&Handler->OpenCount);
            LONG NewCount = OldCount + 1;
            if (NewCount < OldCount) {
                Status = STATUS_SHARING_VIOLATION;
                goto unwind_creates;
            }

            if (OldCount == InterlockedCompareExchange(&Handler->OpenCount,
                                                       NewCount,
                                                       OldCount)) {
                break;
            }
        }

        if ((NULL != Handler->Callbacks) &&
            (Handler->Callbacks->Size >=
             RTL_SIZEOF_THROUGH_FIELD(TRACE_CONTROL_CALLBACKS, Create)) &&
            (NULL != Handler->Callbacks->Create)) {
            ThisStatus = Handler->Callbacks->Create(Context, Irp, &RemainingName);
            if (!NT_SUCCESS(ThisStatus)) {
                goto unwind_creates;
            }
        }

        Context = RtlOffsetToPointer(Context, ALIGN_UP(Handler->ContextSize, 16));
        continue;

    unwind_creates:
        for (Links = Handler->Links.Blink;
             Links != &Extension->Handlers;
             Links = Links->Blink) {

            Context = RtlOffsetToPointer(Context,
                                         -ALIGN_UP(Handler->ContextSize, 16));

            Handler = CONTAINING_RECORD(Links, DT_DEVICE_EXTENSION_HANDLER, Links);
            if ((NULL != Handler->Callbacks) &&
                (Handler->Callbacks->Size >=
                 RTL_SIZEOF_THROUGH_FIELD(TRACE_CONTROL_CALLBACKS, Close)) &&
                (NULL != Handler->Callbacks->Close)) {

                Handler->Callbacks->Close(Context);
            }

            InterlockedDecrement(&Handler->OpenCount);
        }

        Status = ThisStatus;
        goto Exit;
    }


    //
    // Set the completion info.
    //

    FileObject->FsContext = Extension;
    FileObject->FsContext2 = ContextPtr;
    ContextPtr = NULL;
    Irp->IoStatus.Information = FILE_OPENED;
    Status = STATUS_SUCCESS;

Exit:
    if (STATUS_SUCCESS != Status) {
        Irp->IoStatus.Information = 0;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (NULL != ContextPtr) {
        ExFreePool(ContextPtr);
    }

    return Status;
}

_Use_decl_annotations_
NTSTATUS
DtDrvRegisterControlExtension (
    _In_opt_ PCUNICODE_STRING Name,
    _In_opt_ ULONG ContextSize,
    _In_opt_ PCTRACE_CONTROL_CALLBACKS Callbacks,
    _Out_ PULONG RegistrationId
    )

/*++

Routine Description:

    This routine registers a handled for the control device.

Arguments:

    Name - The subcomponent name

    ContextSize - The byte size of the extension context.

    Callbacks - Extension callbacks.

    RegistrationId - On success receives a registration handle.

Return Value:

    NTSTATUS - Return status of the operation.

--*/

{

    NTSTATUS Status;
    PDT_DEVICE_EXTENSION Extension;
    PDT_DEVICE_EXTENSION_HANDLER Handler;
    PLIST_ENTRY Links;
    UNICODE_STRING EmptyName = {0};
    BOOLEAN ExtensionInList;

    PAGED_CODE();

    //
    // Find/allocate the extension.
    //

    if (!ARGUMENT_PRESENT(Name)) {
        Name = &EmptyName;
    }

    Extension = NULL;
    ExtensionInList = FALSE;
    for (Links = DtDeviceExtensions.Flink;
         Links != &DtDeviceExtensions;
         Links = Links->Flink) {

        Extension = CONTAINING_RECORD(Links, DT_DEVICE_EXTENSION, Links);
        if (RtlEqualUnicodeString(&Extension->Name, Name, TRUE)) {
            ExtensionInList = TRUE;
            break;
        }
    }

    if (!ExtensionInList) {
        Extension = ExAllocatePoolWithTag(PagedPool,
                                          sizeof(DT_DEVICE_EXTENSION) + Name->Length,
                                         'crtD');
        if (NULL == Extension) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }

        Extension->TotalContextSize = 0;
        InitializeListHead(&Extension->Links);
        InitializeListHead(&Extension->Handlers);
        Extension->Name.MaximumLength = Extension->Name.Length = Name->Length;
        Extension->Name.Buffer = (PWSTR)(Extension + 1);
        RtlCopyMemory(Extension->Name.Buffer, Name->Buffer, Name->Length);
    }

    //
    // Allocate/link the handler.
    //

    Handler = ExAllocatePoolWithTag(PagedPool,
                                    sizeof(DT_DEVICE_EXTENSION_HANDLER),
                                    'crtD');

    if (NULL == Handler) {
        if (!ExtensionInList) {
            ExFreePool(Extension);
        }

        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }

    RtlZeroMemory(Handler, sizeof(DT_DEVICE_EXTENSION_HANDLER));

    *RegistrationId = Handler->RegistrationId = ++DtDeviceExtensionId;
    Handler->OpenCount = 0;
    Handler->ContextSize = ContextSize;
    Handler->Callbacks = Callbacks;

    Extension->TotalContextSize += ALIGN_UP(ContextSize, 16);
    InsertTailList(&Extension->Handlers, &Handler->Links);

    if (!ExtensionInList) {
        InsertTailList(&DtDeviceExtensions, &Extension->Links);
    }

    Status = STATUS_SUCCESS;

exit:
    return Status;
}

_Use_decl_annotations_
VOID
DtDrvUnregisterControlExtension (
    ULONG RegistrationId
    )

/*++

Routine Description:

    This routine deregisters a handled for the control device.

Arguments:

    RegistrationId - Registration handle.

Return Value:

    None.

--*/

{

    PDT_DEVICE_EXTENSION Extension;
    PDT_DEVICE_EXTENSION_HANDLER Handler;
    PLIST_ENTRY eLinks;
    PLIST_ENTRY hLinks;

    PAGED_CODE();

    for (eLinks = DtDeviceExtensions.Flink;
         eLinks != &DtDeviceExtensions;
         eLinks = eLinks->Flink) {

        Extension = CONTAINING_RECORD(eLinks, DT_DEVICE_EXTENSION, Links);
        for (hLinks = Extension->Handlers.Flink;
             hLinks != &Extension->Handlers;
             hLinks = hLinks->Flink) {

            Handler = CONTAINING_RECORD(hLinks, DT_DEVICE_EXTENSION_HANDLER, Links);
            if (RegistrationId == Handler->RegistrationId) {
                RemoveEntryList(&Handler->Links);
                ExFreePool(Handler);
                if (IsListEmpty(&Extension->Handlers)) {
                    RemoveEntryList(&Extension->Links);
                    ExFreePool(Extension);
                    if (IsListEmpty(&DtDeviceExtensions)) {
                        DtDeviceExtensionId = 0;
                    }
                }

                return;
            }
        }
    }


    NT_ASSERT(FALSE);
    return;
}

_Use_decl_annotations_
VOID
DtDrvUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )

/*++

Routine Description:

    This is the unload handler for the driver object.

Arguments:

    DriverObject - Pointer to driver object.

Return Value:

    NTSTATUS - Return status of the operation.

--*/

{

    PAGED_CODE();

    IoDeleteSymbolicLink((PUNICODE_STRING)&DtDrvSymlink); // const_cast

    if (DtEngineRegistered) {
        NT_VERIFY(NT_SUCCESS(TraceRegisterEngine(NULL, NULL)));
    }

    DtDrvUnregisterControlExtension(DtProvidersDirectoryId);
    DtDrvUnregisterControlExtension(DtDtraceControlDeviceId);
    NT_VERIFY(!dtrace_unload());
    NT_ASSERT(IsListEmpty(&DtDeviceExtensions));

    while (NULL != DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    return;
}

static const TRACE_CONTROL_CALLBACKS DtControlDeviceCallbacks = {
    .Size      = sizeof(TRACE_CONTROL_CALLBACKS),
    .Create    = DtDtraceControlDeviceOpen,
    .Close     = DtDtraceControlDeviceClose,
    .IoControl = DtDtraceControlDeviceControl,
};

#pragma code_seg(pop)

#pragma code_seg(push, "INIT")

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )

/*++

Routine Description:

    This is the initialization routine for the driver object.

Arguments:

    DriverObject - Pointer to driver object created by the system.

    RegistryPath - Unused.

Return Value:

    NTSTATUS - Return status of the operation.

--*/

{

    PDEVICE_OBJECT DeviceObject;
    NTSTATUS Status;
    BOOLEAN UnwindInit;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(RegistryPath);

    UnwindInit = FALSE;
    DeviceObject = NULL;

    InitializeListHead(&DtDeviceExtensions);

    //
    // Setup the driver object event callbacks.
    //

    DriverObject->DriverUnload = DtDrvUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]            = DtDevCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]             = DtDevClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]    = DtDevControl;

    //
    // Create the device.
    //

    Status = IoCreateDeviceSecure(DriverObject,
                                  sizeof(DT_DEVICE_EXTENSION),
                                  (PUNICODE_STRING)&DtDrvDeviceNameString,
                                  FILE_DEVICE_NULL,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &DtDrvSddlString,
                                  NULL,
                                  &DeviceObject);

    if (!NT_SUCCESS (Status)) {
        goto Exit;
    }

    DtDeviceObject = DeviceObject;

    //
    // Setup global dtrace state.
    //

    if (dtrace_load()) {
        Status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    UnwindInit = TRUE;

    //
    // Register control extensions for providers directory and
    // dtrace control device.
    //

    Status = DtDrvRegisterControlExtension(&DtDtraceControlDeviceName,
                                           sizeof(PVOID),
                                           &DtControlDeviceCallbacks,
                                           &DtDtraceControlDeviceId);

    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    Status = DtDrvRegisterControlExtension(&DtProvidersDirectoryName,
                                           0,
                                           NULL,
                                           &DtProvidersDirectoryId);

    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    //
    // Register the engine with the system.
    // The result will be handled - even if system support is not present
    // (feature on demand is not installed), DTrace may still function
    // to some extent.
    //

    Status = TraceRegisterEngine(&DtEngineApi, &DtEngineHelpers);
    if (NT_SUCCESS(Status)) {
        DtEngineRegistered = TRUE;
        NT_ASSERT(NULL != DtEngineHelpers);
    }

    //
    // Expose the device object into the Win32 namespace.
    //

    Status = IoCreateSymbolicLink((PUNICODE_STRING)&DtDrvSymlink,
                                  (PUNICODE_STRING)&DtDrvDeviceNameString);

    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    Status = STATUS_SUCCESS;

Exit:
    if (!NT_SUCCESS(Status)) {
        if (DtEngineRegistered) {
            NT_VERIFY(NT_SUCCESS(TraceRegisterEngine(NULL, NULL)));
        }

        if (0 != DtProvidersDirectoryId) {
            DtDrvUnregisterControlExtension(DtProvidersDirectoryId);
        }

        if (0 != DtDtraceControlDeviceId) {
            DtDrvUnregisterControlExtension(DtDtraceControlDeviceId);
        }

        if (UnwindInit) {
            NT_VERIFY(!dtrace_unload());
            NT_ASSERT(IsListEmpty(&DtDeviceExtensions));
        }

        if (NULL != DeviceObject) {
            IoDeleteDevice(DeviceObject);
        }
    }

    return Status;
}

#pragma code_seg(pop)

int dtrace_safememcpy(void* sys, uintptr_t untr, size_t bytesize, size_t chunksize, int read)
{
    if ((NULL == DtEngineHelpers) || (NULL == DtEngineHelpers->AccessMemory)) {
        return 0;
    }
    return DtEngineHelpers->AccessMemory(sys, untr, bytesize, chunksize, read);
}

ULONG dtrace_userstackwalk(ULONG limit, PVOID* stack)
{
    if ((NULL == DtEngineHelpers) || (NULL == DtEngineHelpers->WalkUserStack)) {
        return 0;
    }
    return DtEngineHelpers->WalkUserStack(limit, stack);
}

PULONG_PTR dtrace_threadprivate(ULONG Index)
{
    if ((NULL == DtEngineHelpers) || (NULL == DtEngineHelpers->GetCurrentThreadTracePrivate)) {
        return NULL;
    }
    return DtEngineHelpers->GetCurrentThreadTracePrivate(Index);
}

void dtrace_priv_filter(KPROCESSOR_MODE PreviousMode, PBOOLEAN User, PBOOLEAN Kernel)
{
    if ((NULL == DtEngineHelpers) || (NULL == DtEngineHelpers->FilterAccess)) {
        *Kernel = *User = FALSE;
    } else {
        DtEngineHelpers->FilterAccess(PreviousMode, Kernel, User);
    }
}


