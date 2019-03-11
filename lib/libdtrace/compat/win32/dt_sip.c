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

    dt_sip.c

Abstract:

    This module contains the implementation of the Crypto SIP provider
    for signing and verifying DTrace scripts files (*.d).

    The signature is appended at the tail of the file as 'C'-style
    comment block.

--*/

#include <windows.h>

#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS // for SHA2 support
#include <wincrypt.h>
#include <wintrust.h>

#pragma warning(push,3)
#pragma warning(disable: 4201)    // nameless struct/union
#include <mssip.h>
#pragma warning(pop)

//
// The following define controls the mode of operation for this SIP provider.
// When not defined, SIP can either be manually instantiated, or it can be
// listed in wintrust.ini file.
// When defined, the module will register itself as a system SIP provider
// for the file type.
//

#define DTSIP_STANDALONE 1

//
// GUID of the DTrace SIP.
// {0f79decf-0727-4f6d-8ba1-55616d16ee75}
//
const GUID DtSipGUID = {
    0x0f79decf, 0x0727, 0x4f6d, {0x8b, 0xa1, 0x55, 0x61, 0x6d, 0x16, 0xee, 0x75}
};

//
// The version of the provider.
// Currently it is 1.0
//

#define DTSIP_VER_HI  1
#define DTSIP_VER_LO  0
#define DTSIP_VERSION ((DTSIP_VER_HI << 16) | DTSIP_VER_LO)


//
// The signature encoding type.
// 'Format 1' - PKCS#7 signature with X.509 certificate and
// counter-signature (standardized by the W3C).
//

#define DTSIP_ENCODING (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

//
// A macro to define an exported symbol w/o the need to modify the
// .def file.
//

#if defined(_M_IX86)
#define DTSIP_EXPORT(api, pc) \
    __pragma(comment(linker, "/export:"#api"=_"#api"@"#pc",PRIVATE"))
#else
#define DTSIP_EXPORT(api, pc) \
    __pragma(comment(linker, "/export:"#api",PRIVATE"))
#endif

//
// Signature block
//

static const CHAR DtSippSigBlockStart[] =
    "\r\n/* SIG * Begin signature block\r\n";

static const CHAR DtSippSigBlockLinePfx[] =
    " * SIG * ";

static const CHAR DtSippSigBlockEnd[] =
    " * SIG * End signature block */\r\n";

//
// Some usable macros.
//

#define ARGUMENT_PRESENT(v) (0 != (v))

//
//----------------------------------------------- Local support routines.
//

_Must_inspect_result_
_Ret_maybenull_
_Post_writable_byte_size_(Size)
static
PVOID
DtSippHeapAlloc (
    _In_ SIZE_T Size
    )
{
    return HeapAlloc(GetProcessHeap(), 0, Size);
}

static
VOID
DtSippHeapFree (
    _In_ _Post_invalid_ PVOID Address
    )
{
    HeapFree(GetProcessHeap(), 0, Address);
}

_Success_(return == 0)
static
DWORD
DtSippEncodeSignature (
    _In_reads_bytes_(BufferSize) const BYTE* Buffer,
    _In_ DWORD BufferSize,
    _Outptr_result_bytebuffer_(*SigTextSize) PBYTE* SigText,
    _Out_ PDWORD SigTextSize
    )
{
    DWORD Error;
    PBYTE Cursor;
    PSTR Base64String = NULL;
    DWORD Base64StringSize = 0;
    DWORD LineCount;
    DWORD SigTextRequeredSize;
    PCSTR LineStart;
    PCSTR LineEnd;
    size_t LineLen;

    if (!CryptBinaryToStringA(Buffer,
                              BufferSize,
                              CRYPT_STRING_BASE64,
                              NULL,
                              &Base64StringSize)) {

        Error = GetLastError();
        goto exit;
    }

    Base64String = DtSippHeapAlloc(Base64StringSize + 1);
    if (NULL == Base64String) {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }

    if (!CryptBinaryToStringA(Buffer,
                              BufferSize,
                              CRYPT_STRING_BASE64,
                              Base64String,
                              &Base64StringSize)) {

        Error = GetLastError();
        goto exit;
    }

    *(Base64String + Base64StringSize) = '\0';

    //
    // Put line prefix at the beginning and after each line break.
    //

    LineCount = 1;
    LineStart = Base64String;
    for (;;) {
        LineStart = strstr(LineStart, "\r\n");
        if (NULL == LineStart) {
            break;
        }

        LineStart += 2;
        LineCount += 1;
    }

    SigTextRequeredSize = Base64StringSize +
        (sizeof(DtSippSigBlockStart) - 1) +
        ((sizeof(DtSippSigBlockLinePfx) - 1) * LineCount) +
        (sizeof(DtSippSigBlockEnd) - 1) +
        1;

    *SigText = DtSippHeapAlloc(SigTextRequeredSize);
    if (NULL == *SigText) {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }

    Cursor = *SigText;
    memcpy(Cursor, DtSippSigBlockStart, sizeof(DtSippSigBlockStart) - 1);
    Cursor += sizeof(DtSippSigBlockStart) - 1;

    for (LineStart = Base64String; '\0' != *LineStart; ) {
        memcpy(Cursor, DtSippSigBlockLinePfx, sizeof(DtSippSigBlockLinePfx) - 1);
        Cursor += sizeof(DtSippSigBlockLinePfx) - 1;

        LineEnd = strstr(LineStart, "\r\n");
        if (NULL == LineEnd) {
            LineLen = strlen(LineStart);
        } else {
            LineLen = (LineEnd - LineStart) + 2;
        }

        memcpy(Cursor, LineStart, LineLen);
        Cursor += LineLen;
        LineStart += LineLen;
    }

    memcpy(Cursor, DtSippSigBlockEnd, sizeof(DtSippSigBlockEnd) - 1);
    Cursor += sizeof(DtSippSigBlockEnd) - 1;
    *SigTextSize = (DWORD)(Cursor - *SigText);

    if (*SigTextSize != (SIZE_T)(Cursor - *SigText)) {
        Error = ERROR_NOT_SUPPORTED;
        goto exit;
    }

    Error = NO_ERROR;

exit:
    if (NULL != Base64String) {
        DtSippHeapFree(Base64String);
    }

    return Error;
}

_Success_(return == 0)
static
DWORD
DtSippDecodeSignature (
    _In_reads_bytes_(SignatureSize) const BYTE* Signature,
    _In_ SIZE_T SignatureSize,
    _Out_writes_to_opt_(BufferSize, *BytesDone) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG BytesDone
    )
{

    DWORD Error;
    DWORD Skipped;
    PSTR SigText = NULL;
    PSTR Cursor;

    //
    // Strip all speaial headers from the signature block
    // leaving only its base64 contents.
    //

    if ((SignatureSize < (sizeof(DtSippSigBlockStart) - 1)) ||
        (0 != memcmp(Signature,
                     DtSippSigBlockStart,
                     sizeof(DtSippSigBlockStart) - 1))) {

        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    Signature += sizeof(DtSippSigBlockStart) - 1;
    SignatureSize -= sizeof(DtSippSigBlockStart) - 1;

    if ((SignatureSize < (sizeof(DtSippSigBlockEnd) - 1)) ||
        (0 != memcmp((Signature +
                      (SignatureSize - (sizeof(DtSippSigBlockEnd) - 1))),
                     DtSippSigBlockEnd,
                     sizeof(DtSippSigBlockEnd) - 1))) {

        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    SignatureSize -= sizeof(DtSippSigBlockEnd) - 1;

    SigText = DtSippHeapAlloc(SignatureSize + 1);
    if (NULL == SigText) {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }

    CopyMemory(SigText, Signature, SignatureSize);
    *(SigText + SignatureSize) = '\0';

    Cursor = SigText;
    while ('\0' != *Cursor) {
        Cursor = strstr(Cursor, DtSippSigBlockLinePfx);
        if (NULL == Cursor) {
            break;
        }

        char* d = Cursor;
        const char* s = Cursor + (sizeof(DtSippSigBlockLinePfx) - 1);
        do {
            *(d++) = *s;
        } while ('\0' != *(s++));
    }

    //
    // At this point 'SigText' contains NUL-terminated base64 string.
    // The only remaining concern here is for it to not have closing
    // 'C'-style comment in it, so attacker would not be able to craft the
    // code into the signature block itself.
    //

    if (NULL != strstr(SigText, "*/")) {
        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (!CryptStringToBinaryA(SigText,
                              0,
                              CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                              Buffer,
                              &BufferSize,
                              &Skipped,
                              NULL)) {

        Error = GetLastError();
        goto exit;
    }

    if (0 != Skipped) {
        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (NULL != BytesDone) {
        *BytesDone = BufferSize;
    }

    Error = NO_ERROR;

exit:
    if (NULL != SigText) {
        DtSippHeapFree(SigText);
    }

    return Error;
}

static
const BYTE*
DtSippFindSignature (
    _In_reads_bytes_(ByteSize) const BYTE* Buffer,
    _In_ DWORD ByteSize
    )
{

    DWORD Offset;

    //
    // First, quickly check if buffer ends with a signature terminator.
    //

    if (ByteSize <
        ((sizeof(DtSippSigBlockStart) - 1) +
         (sizeof(DtSippSigBlockEnd) - 1))) {

        return NULL;
    }

    Offset = ByteSize - (sizeof(DtSippSigBlockEnd) - 1);
    if (0 != memcmp(Buffer + Offset,
                    DtSippSigBlockEnd,
                    sizeof(DtSippSigBlockEnd) - 1)) {

        return NULL;
    }

    //
    // Find last occurance of the signature start.
    //

    Offset -= sizeof(DtSippSigBlockStart) - 1;
    do {
        if (0 == memcmp(Buffer + Offset,
                        DtSippSigBlockStart,
                        sizeof(DtSippSigBlockStart) - 1)) {

            return Buffer + Offset;
        }
    } while (Offset-- > 0);

    return NULL;
}

_Success_(return == 0)
static
DWORD
DtSippLoadFileContents (
    _In_ HANDLE FileHandle,
    _Outptr_result_bytebuffer_(*ByteSize) PBYTE* Contents,
    _Out_ PDWORD ByteSize
    )
{
    DWORD Error;
    PBYTE Buffer = NULL;
    DWORD FileSize;
    DWORD BytesDone;

    if (INVALID_SET_FILE_POINTER ==
        SetFilePointer(FileHandle, 0, NULL, FILE_BEGIN)) {

        Error = GetLastError();
        goto exit;
    }

    FileSize = GetFileSize(FileHandle, NULL);
    if (INVALID_FILE_SIZE == FileSize) {
        Error = GetLastError();
        goto exit;
    }

    Buffer = DtSippHeapAlloc(FileSize);
    if (NULL == Buffer) {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }

    if (!ReadFile(FileHandle, Buffer, FileSize, &BytesDone, NULL)) {
        Error = GetLastError();
        goto exit;
    }

    if (BytesDone != FileSize) {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }

    *Contents = Buffer;
    *ByteSize = FileSize;
    Buffer = NULL;
    Error = NO_ERROR;

exit:
    if (NULL != Buffer) {
        DtSippHeapFree(Buffer);
    }

    return Error;
}

_Success_(return == 0)
static
DWORD
DtSippOpenSubjectInfoFile (
    _In_ SIP_SUBJECTINFO* pSubjectInfo,
    _In_ BOOL WriteAccess,
    _Out_ PHANDLE Handle,
    _Out_ PBOOL ExternalHandle
    )
{

    HANDLE h;

    h = pSubjectInfo->hFile;
    if ((NULL != h) && (INVALID_HANDLE_VALUE != h)) {
        *Handle = h;
        *ExternalHandle = TRUE;
        return NO_ERROR;
    }

    if (NULL == pSubjectInfo->pwsFileName) {
        return ERROR_INVALID_PARAMETER;
    }

    if (WriteAccess) {
        h = CreateFileW(pSubjectInfo->pwsFileName,
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);

    } else {
        h = CreateFileW(pSubjectInfo->pwsFileName,
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    }

    if (INVALID_HANDLE_VALUE == h) {
        return GetLastError();
    }

    *Handle = h;
    *ExternalHandle = FALSE;
    return NO_ERROR;
}

_Success_(return == 0)
static
DWORD
DtSippLoadContentsFromSubjectInfo (
    _In_ SIP_SUBJECTINFO* pSubjectInfo,
    _Outptr_result_bytebuffer_(*ByteSize) PBYTE* Contents,
    _Out_ PDWORD ByteSize
    )
{

    DWORD Error;
    HANDLE Handle = INVALID_HANDLE_VALUE;
    BOOL ExternalHandle = FALSE;

    if ((pSubjectInfo->cbSize >= sizeof(SIP_SUBJECTINFO)) &&
        (MSSIP_ADDINFO_BLOB == pSubjectInfo->dwUnionChoice) &&
        (NULL != pSubjectInfo->psBlob) &&
        (pSubjectInfo->psBlob->cbStruct >= sizeof(MS_ADDINFO_BLOB)) &&
        (NULL != pSubjectInfo->psBlob->pbMemObject) &&
        (0 != pSubjectInfo->psBlob->cbMemObject)) {

        *Contents = DtSippHeapAlloc(pSubjectInfo->psBlob->cbMemObject);
        if (NULL == *Contents) {
            Error = ERROR_NOT_ENOUGH_MEMORY;
            goto exit;
        }

        CopyMemory(*Contents,
                   pSubjectInfo->psBlob->pbMemObject,
                   pSubjectInfo->psBlob->cbMemObject);

        *ByteSize = pSubjectInfo->psBlob->cbMemObject;
        Error = NO_ERROR;
        goto exit;
    }

    Error = DtSippOpenSubjectInfoFile(pSubjectInfo,
                                      FALSE,
                                      &Handle,
                                      &ExternalHandle);
    if (NO_ERROR != Error) {
        goto exit;
    }

    Error = DtSippLoadFileContents(Handle, Contents, ByteSize);

exit:
    if (!ExternalHandle && (INVALID_HANDLE_VALUE != Handle)) {
        CloseHandle(Handle);
    }

    return Error;
}

_Success_(return == 0)
static
DWORD
DtSippHashFile (
    _In_reads_bytes_(ByteSize) PBYTE Contents,
    _In_ DWORD ByteSize,
    _In_ HCRYPTHASH Hash
    )
{

    const BYTE* SigText;
    DWORD Error;

    SigText = DtSippFindSignature(Contents, ByteSize);
    if (NULL != SigText) {
        ByteSize = (DWORD)(SigText - Contents);
    }

    //
    // Hash contents.
    //

    if (!CryptHashData(Hash, Contents, ByteSize, 0)) {
        Error = GetLastError();
        goto exit;
    }

    //
    // Mix in the file size (same as the signature position).
    //

    if (!CryptHashData(Hash, (const BYTE*)&ByteSize, sizeof(DWORD), 0)) {
        Error = GetLastError();
        goto exit;
    }

    Error = NO_ERROR;

exit:
    return Error;
}

_Success_(return == 0)
static
DWORD
DtSippOpenSubjectInfoProvider (
    _In_ SIP_SUBJECTINFO* pSubjectInfo,
    _Out_ HCRYPTPROV* Provider,
    _Out_ PBOOL ExternalProvider
    )

{

    if (pSubjectInfo->hProv) {
        *Provider = pSubjectInfo->hProv;
        *ExternalProvider = TRUE;
        return NO_ERROR;
    }

    //
    // No provider provided.
    // Acquire default RSA CSP.
    //

    if (!CryptAcquireContextW(Provider,
                              NULL,
                              MS_DEF_PROV_W,
                              PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT)) {

        return GetLastError();
    }

    *ExternalProvider = FALSE;
    return NO_ERROR;
}

static
DWORD
DtSippOidAlgIdToAlgId (
    _In_ LPCSTR szOidAlgId
    )

/*++

Routine Description:

    This routine determines algorithm Id to use for hash functions. Takes into
    account if information indicates a CNG alg id which means we will have
    to manually set the SHA-2 algorithms since CryptFindOIDInfo doesn't
    support CAPI alg ids. SHA-2 support is new in Windows 7

Arguments:

    szOidAlgId - the OID associated with this algorithm id.

Return Value:

    (1) Return 0 on failure
    (2) if CALG_OID_INFO_CNG_ONLY, use strcmp to manually set SHA-2 algms

--*/

{
    DWORD dwAlgId = 0;
    PCCRYPT_OID_INFO pCryptOidInfo = NULL;

    //
    // Use 0 for CryptFindOIDInfo to search all groups. This preserves the
    // original functionality of the call to CertOIDToAlgId
    //

    pCryptOidInfo = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (PSTR)szOidAlgId, 0);
    if (NULL == pCryptOidInfo) {
        return dwAlgId;
    }

    if (CALG_OID_INFO_CNG_ONLY == pCryptOidInfo->Algid) {

        //
        // OIDInfo indicates a CNG alg id - CryptFindOIDInfo doesn't support
        // CAPI alg ids for SHA2 (Algid is set to CALG_OID_INFO_CNG_ONLY in
        // these instances, which is a bit of an overstatement) so we have
        // to set them manually
        //

        if (0 == wcscmp(pCryptOidInfo->pwszCNGAlgid, BCRYPT_SHA256_ALGORITHM)) {
            dwAlgId = CALG_SHA_256;
        } else if (0 == wcscmp(pCryptOidInfo->pwszCNGAlgid, BCRYPT_SHA512_ALGORITHM)) {
            dwAlgId = CALG_SHA_512;
        } else if (0 == wcscmp(pCryptOidInfo->pwszCNGAlgid, BCRYPT_SHA384_ALGORITHM)) {
            dwAlgId = CALG_SHA_384;
        } else {
            dwAlgId = 0;
        }

    } else {
        dwAlgId = pCryptOidInfo->Algid;
    }

    return dwAlgId;
}

__success(NO_ERROR == return)
static
DWORD
DtSippDecodeSIPVersion (
    _In_ CRYPT_OBJID_BLOB* pCryptBlob,
    _Out_ DWORD *pdwSIPVersion
    )

/*++

Routine Description:

    This routine Decodes a CRYPT_OBJID_BLOB into an SPC_SIGINFO object
    and extracts the SIP Version from it.

Arguments:

    pCryptBlob - Encrypted SPC_SIGINFO object

    pdwSIPVersion - Pointer to the DWORD where the extracted
        SIP Version will be recorded

Return Value:

    DWORD - Win32 error code.

--*/

{

    DWORD Error;
    DWORD cbDecoded;
    PBYTE pbDecoded;
    DWORD cbEncoded;
    PBYTE pbEncoded;

    pbDecoded = NULL;

    if (!ARGUMENT_PRESENT(pCryptBlob)) {
        Error = ERROR_BAD_FORMAT;
        goto exit;
    }

    pbEncoded = pCryptBlob->pbData;
    cbEncoded = pCryptBlob->cbData;
    cbDecoded = 0;

    if (!CryptDecodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                           SPC_SIGINFO_OBJID,
                           pbEncoded,
                           cbEncoded,
                           CRYPT_DECODE_NOCOPY_FLAG,
                           pbDecoded,
                           &cbDecoded)) {

        Error = GetLastError();
        goto exit;
    }

    if  (0 == cbDecoded) {
        Error = ERROR_BAD_FORMAT;
        goto exit;
    }

    pbDecoded = (PBYTE)DtSippHeapAlloc(cbDecoded);
    if (NULL == pbDecoded) {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }

    if (!CryptDecodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                           SPC_SIGINFO_OBJID,
                           pbEncoded,
                           cbEncoded,
                           CRYPT_DECODE_NOCOPY_FLAG,
                           pbDecoded,
                           &cbDecoded)) {

        Error = GetLastError();
        goto exit;
    }

    if (cbDecoded < sizeof(SPC_SIGINFO)) {
        Error = ERROR_BAD_FORMAT;
        goto exit;
    }

    *pdwSIPVersion = ((SPC_SIGINFO*)(pbDecoded))->dwSipVersion;
    Error = NO_ERROR;

exit:
    if (NULL != pbDecoded) {
        DtSippHeapFree(pbDecoded);
    }

    return Error;
}

//
//----------------------------------------------- SIP routines.
//

DTSIP_EXPORT(DtSipGetCaps, 8)
_Success_(return != FALSE)
BOOL
WINAPI
DtSipGetCaps (
    _In_ SIP_SUBJECTINFO* pSubjectInfo,
    _Inout_ PSIP_CAP_SET_V2 pCaps
    )

/*++

Routine Description:

    The pCryptSIPGetCaps function is implemented by an
    subject interface package (SIP) to report capabilities.

Arguments:

    pSubjInfo - Pointer to a SIP_SUBJECTINFO structure that
        specifies subject information data to the SIP APIs.

    pCaps - Pointer to a SIP_CAP_SET structure that defines the
        capabilities of an SIP.

Return Value:

    BOOL - TRUE if succeeded, FALSE if not.

--*/

{

    UNREFERENCED_PARAMETER(pSubjectInfo);

    //
    // Verify input parameters.
    //

    if (ARGUMENT_PRESENT(pCaps) || (pCaps->cbSize < sizeof(SIP_CAP_SET_V2))) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    //
    // Fill in caps and return
    // success to the caller.
    //

    pCaps->cbSize = sizeof(SIP_CAP_SET_V2);
    pCaps->dwVersion = SIP_CAP_SET_VERSION_2;
    pCaps->isMultiSign = TRUE; // Format supports multiple signatures.
    pCaps->dwReserved = 0;

    return TRUE;
}

DTSIP_EXPORT(DtSipIsMyFileType, 8)
_Success_(return != FALSE)
BOOL
WINAPI
DtSipIsMyFileType (
    _In_ PCWSTR pwszFileName,
    _Out_ GUID* pgSubject
    )

/*++

Routine Description:

    This routine determine if this SIP can handle the file the trust system is trying to manipulate.
    Implements the SIP interface pfnIsFileSupportedName:
    http://msdn.microsoft.com/en-us/library/cc542640(VS.85).aspx

Arguments:

    pwszFileName - Full name of the file to check support for.

    pgSubject - The GUID of the SIP if the file is supported.

Return Value:

    TRUE if the SIP supports the specified file, FALSE otherwise.
    GetLastError will return extended error information in the FALSE case.
        - ERROR_NOT_SUPPORTED: Specified fileName is not supported by this SIP.
        - ERROR_INVALID_PARAMETER: Specified parameters are NULL or otherwise invalid.
        - ERROR_INVALID_DATA: The file is not a supported target file.

--*/

{

    DWORD Error;
    PCWSTR Ext;

    //
    // Verify input parameters.
    //

    if (!ARGUMENT_PRESENT(pwszFileName) || !ARGUMENT_PRESENT(pgSubject)) {
        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    //
    // Filter by the extension.
    // Only .d files are supported.
    //

    Ext = wcsrchr(pwszFileName, L'.');
    if ((NULL == Ext) || (0 != _wcsicmp(Ext, L".d"))) {
        Error = ERROR_INVALID_DATA;
        goto exit;
    }

    *pgSubject = DtSipGUID;
    Error = NO_ERROR;

exit:
    SetLastError(Error);
    return NO_ERROR == Error;
}

DTSIP_EXPORT(DtSipGetSignature, 20)
_Success_(return != FALSE)
BOOL
WINAPI
DtSipGetSignature (
    _In_ SIP_SUBJECTINFO* pSubjectInfo,
    _Out_ DWORD* pdwEncodingType,
    _In_ DWORD dwIndex,
    _Inout_ DWORD* pdwDataLen,
    _Out_writes_bytes_opt_(*pdwDataLen) BYTE* pbData
    )

/*++

Routine Description:

    This routine retrieves the Authenticode signature from a file.
    If no output buffer was provided, returns the size of the signature buffer required.
    Implements the SIP interface CryptSIPGetSignedDataMsg:
    http://msdn.microsoft.com/en-us/library/cc542585(v=VS.85).aspx

Arguments:

    pSubjectInfo - SIP subject information

    pdwEncodingType - Encoding type used for the signature (e.g. X509_ASN_ENCODING)

    dwIndex - Reserved parameter. Must be set to 0.

    pdwDataLen - Length in bytes of the signature

    pbData - A byte buffer containing the Authenticode signature.

Return Value:

    TRUE if the function succeeded, FALSE otherwise. GetLastError will return extended error information.
        - ERROR_BAD_FORMAT: Specified data or file format of the SIP is invalid.
        - ERROR_INVALID_PARAMETER: Specified parameters are NULL or otherwise invalid, or subject has no signature.
        - ERROR_INSUFFICIENT_BUFFER: The signature buffer was too small; signatureSize is set to the required size.
        - CRYPT_E_NO_MATCH: The signature index is invalid.
--*/

{

    DWORD Error;
    const BYTE* SigText;
    DWORD ByteSize;
    PBYTE Contents;

    Contents = NULL;
    ByteSize = 0;

    //
    // Verify input parameters.
    //

    if (!ARGUMENT_PRESENT(pSubjectInfo) ||
        !ARGUMENT_PRESENT(pdwEncodingType) ||
        !ARGUMENT_PRESENT(pdwDataLen)) {

        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    //
    // Only one signature per file is supported.
    //

    if (0 != dwIndex) {
        Error = ERROR_NOT_FOUND;
        goto exit;
    }

    //
    // Get the data blob either as provided by the caller
    // or by reading file contents.
    //

    Error = DtSippLoadContentsFromSubjectInfo(pSubjectInfo,
                                              &Contents,
                                              &ByteSize);
    if (NO_ERROR != Error) {
        goto exit;
    }

    SigText = DtSippFindSignature(Contents, ByteSize);
    if (NULL == SigText) {
        Error = (ULONG)TRUST_E_NOSIGNATURE;
        goto exit;
    }

    Error = DtSippDecodeSignature(SigText,
                                  (ByteSize - (SigText - Contents)),
                                  pbData,
                                  *pdwDataLen,
                                  pdwDataLen);

    if (NO_ERROR != Error) {
        goto exit;
    }

    *pdwEncodingType = DTSIP_ENCODING;
    Error = NO_ERROR;

exit:
    if (NULL != Contents) {
        DtSippHeapFree(Contents);
    }

    SetLastError(Error);
    return NO_ERROR == Error;
}

DTSIP_EXPORT(DtSipPutSignature, 20)
_Success_(return != FALSE)
BOOL
WINAPI
DtSipPutSignature (
    _In_ SIP_SUBJECTINFO* pSubjectInfo,
    _In_ DWORD dwEncodingType,
    _Out_ DWORD* pdwIndex,
    _In_ DWORD dwDataLen,
    _In_reads_bytes_(dwDataLen) PBYTE pbData
    )

/*++

Routine Description:

    This routine adds an Authenticode signature to a file.
    Implements the SIP interface CryptSIPPutSignedDataMsg:
    http://msdn.microsoft.com/en-us/library/cc542587(v=VS.85).aspx

Arguments:

    pSubjectInfo - SIP subject information

    dwEncodingType - Encoding type used for the signature (e.g. X509_ASN_ENCODING)

    pdwIndex - Index of the added signature. This is always 0 for this SIP.

    dwDataLen - Length in bytes of the signature

    pbData - A byte buffer containing the Authenticode signature to add.

Return Value:

    TRUE if the function succeeded, FALSE otherwise. GetLastError will return extended error information.
    Possible error codes include:
    - TRUST_E_SUBJECT_FORM_UNKNOWN: Specified subject type is invalid.
    - ERROR_BAD_FORMAT: Specified data or file format of the SIP is invalid.
    - ERROR_INVALID_PARAMETER: Specified parameters are NULL or otherwise invalid.

--*/

{

    DWORD Error;
    HANDLE FileHandle;
    BOOL ExternalHandle;
    DWORD BytesDone;
    const BYTE* ExistingSigText;
    PBYTE SigText;
    DWORD SigTextSize;
    DWORD ByteSize;
    PBYTE Contents;

    ExternalHandle = FALSE;
    FileHandle = INVALID_HANDLE_VALUE;
    Contents = NULL;
    SigText = NULL;

    //
    // Verify input parameters.
    //

    if (!ARGUMENT_PRESENT(pSubjectInfo) ||
        (0 == dwDataLen) ||
        !ARGUMENT_PRESENT(pbData) ||
        !ARGUMENT_PRESENT(pdwIndex)) {

        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    //
    // Verify the encoding type.
    //

    if (DTSIP_ENCODING != dwEncodingType) {
        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    //
    // Open the file for write.
    // This open mode disallows write sharing, so contents cannot change
    //

    Error = DtSippOpenSubjectInfoFile(pSubjectInfo,
                                      TRUE, // Write access
                                      &FileHandle,
                                      &ExternalHandle);

    if (NO_ERROR != Error) {
        goto exit;
    }

    //
    // Add the signature block.
    //

    Error = DtSippLoadFileContents(FileHandle, &Contents, &ByteSize);
    if (NO_ERROR != Error) {
        goto exit;
    }

    ExistingSigText = DtSippFindSignature(Contents, ByteSize);
    if (NULL != ExistingSigText) {
        Error = ERROR_NOT_SUPPORTED; // There must be only one.
        goto exit;
    }

    Error = DtSippEncodeSignature(pbData, dwDataLen, &SigText, &SigTextSize);
    if (NO_ERROR != Error) {
        goto exit;
    }

    if (INVALID_SET_FILE_POINTER ==
        SetFilePointer(FileHandle, ByteSize, NULL, FILE_BEGIN)) {

        Error = GetLastError();
        goto exit;
    }

    if (!WriteFile(FileHandle, SigText, SigTextSize, &BytesDone, NULL)) {
        Error = GetLastError();
        goto exit;
    }

    *pdwIndex = 0;
    Error = NO_ERROR;

exit:
    if (NULL != Contents) {
        DtSippHeapFree(Contents);
    }

    if (NULL != SigText) {
        DtSippHeapFree(SigText);
    }


    if (!ExternalHandle && (INVALID_HANDLE_VALUE != FileHandle)) {
        CloseHandle(FileHandle);
    }

    SetLastError(Error);
    return NO_ERROR == Error;
}

DTSIP_EXPORT(DtSipDelSignature, 8)
_Success_(return != FALSE)
BOOL
WINAPI
DtSipDelSignature (
    _In_ SIP_SUBJECTINFO* pSubjectInfo,
    _In_ DWORD dwIndex
    )

/*++

Routine Description:

    This routine removes an Authenticode signature from a file.
    Implements the SIP interface CryptSIPRemoveSignedDataMsg:
    http://msdn.microsoft.com/en-us/library/cc542589(v=VS.85).aspx

Arguments:

    pSubjectInfo - SIP subject information

    dwIndex - Index of the added signature. This is always 0 for this SIP.

Return Value:

    TRUE if the function succeeded, FALSE otherwise. GetLastError will return extended error information.
    Possible error codes include:
        - TRUST_E_SUBJECT_FORM_UNKNOWN: Specified subject type is invalid.
        - ERROR_BAD_FORMAT: Specified data or file format of the SIP is invalid.
        - ERROR_INVALID_PARAMETER: Specified parameters are NULL or otherwise invalid.
        - CRYPT_E_NO_MATCH: The signature index is invalid.

--*/

{

    DWORD Error;
    const BYTE* SigText;
    DWORD ByteSize;
    PBYTE Contents;
    HANDLE FileHandle;
    BOOL ExternalHandle;

    ExternalHandle = FALSE;
    FileHandle = INVALID_HANDLE_VALUE;
    Contents = NULL;

    //
    // Verify input parameters.
    //

    if (!ARGUMENT_PRESENT(pSubjectInfo)) {
        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    //
    // Only a single signature per file is supported.
    //

    if (0 != dwIndex) {
        Error = ERROR_NOT_FOUND;
        goto exit;
    }

    //
    // Open the file for write, then find and trim the file to cut off the
    // signature.
    //

    Error = DtSippOpenSubjectInfoFile(pSubjectInfo,
                                      TRUE, // Write access
                                      &FileHandle,
                                      &ExternalHandle);

    if (NO_ERROR != Error) {
        goto exit;
    }

    Error = DtSippLoadFileContents(FileHandle, &Contents, &ByteSize);
    if (NO_ERROR != Error) {
        goto exit;
    }

    SigText = DtSippFindSignature(Contents, ByteSize);
    if (NULL == SigText) {
        Error = ERROR_NOT_FOUND;
        goto exit;
    }

    if (INVALID_SET_FILE_POINTER ==
        SetFilePointer(FileHandle, (LONG)(SigText - Contents), NULL, FILE_BEGIN)) {

        Error = GetLastError();
        goto exit;
    }

    if (!SetEndOfFile(FileHandle)) {
        Error = GetLastError();
        goto exit;
    }

    Error = NO_ERROR;

exit:
    if (NULL != Contents) {
        DtSippHeapFree(Contents);
    }

    if (!ExternalHandle && (INVALID_HANDLE_VALUE != FileHandle)) {
        CloseHandle(FileHandle);
    }

    SetLastError(Error);
    return NO_ERROR == Error;
}

DTSIP_EXPORT(DtSipCreateHash, 12)
_Success_(return != FALSE)
BOOL
WINAPI
DtSipCreateHash (
    _In_ SIP_SUBJECTINFO* pSubjectInfo,
    _Inout_ DWORD* pdwDataLen,
    _Out_writes_bytes_opt_(*pdwDataLen) SIP_INDIRECT_DATA* psData
    )

/*++

Routine Description:

    This routine creates a cryptographic hash of the file.
    Implements the SIP interface CryptSIPPutSignedDataMsg:
    http://msdn.microsoft.com/en-us/library/bb736358(v=vs.85).aspx

Arguments:

    pSubjectInfo - SIP subject information

    pdwDataLen - indirectDataSize Length in bytes of the SIP indirect data strucutre

    psData - SIP indirect data structure containing resulting hash data of the package.

Return Value:

    TRUE if the SIP supports the specified file, FALSE otherwise.
    GetLastError will return extended error information in the FALSE case.
        - ERROR_NOT_SUPPORTED: Specified fileName is not supported by this SIP.
        - ERROR_INVALID_PARAMETER: Specified parameters are NULL or otherwise invalid.

--*/

{

    DWORD Error;
    PBYTE Contents;
    DWORD ByteSize;
    HCRYPTPROV Csp;
    BOOL ExternalCsp;
    PCSTR pszAlgId;
    DWORD dwAlgId;
    HCRYPTHASH Hash;
    PBYTE HashBuffer;
    DWORD HashSize;
    DWORD HashSizeSize;

    Contents = NULL;
    ExternalCsp = FALSE;
    Csp = 0;
    Hash = 0;
    HashBuffer = NULL;

    //
    // Verify the input.
    //

    if (!ARGUMENT_PRESENT(pSubjectInfo) ||
        !ARGUMENT_PRESENT(pdwDataLen)) {

        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    //
    // Calculate the algorithm ID.
    // It will either be a hash data or, if one does not exist,
    // the hashing algorithm of a signature.
    //

    pszAlgId = pSubjectInfo->DigestAlgorithm.pszObjId;
    if (NULL == pszAlgId) {
        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    dwAlgId = DtSippOidAlgIdToAlgId(pszAlgId);
    if (0 == dwAlgId) {
        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    //
    // Open crypto algorithm provider.
    //

    Error = DtSippOpenSubjectInfoProvider(pSubjectInfo,
                                          &Csp,
                                          &ExternalCsp);

    if (NO_ERROR != Error) {
        goto exit;
    }

    //
    // Calculate a hash.
    // This routine can be called w/o the data buffer
    // to calculate required buffer size rather than compute a real
    // hash.
    //

    if (!CryptCreateHash(Csp, dwAlgId, 0, 0, &Hash)) {
        Error = GetLastError();
        goto exit;
    }

    if (ARGUMENT_PRESENT(psData)) {
        Error = DtSippLoadContentsFromSubjectInfo(pSubjectInfo,
                                                  &Contents,
                                                  &ByteSize);
        if (NO_ERROR != Error) {
            goto exit;
        }

        Error = DtSippHashFile(Contents, ByteSize, Hash);
        if (NO_ERROR != Error) {
            goto exit;
        }
    }

    //
    // Query the result of a clculated hash.
    // When caller is only asking for the size, there is no
    // need to query the hash data itself.
    //

    HashSize = 0;
    HashSizeSize = sizeof(HashSize);
    if (!CryptGetHashParam(Hash,
                           HP_HASHSIZE,
                           (PBYTE)&HashSize,
                           &HashSizeSize,
                           0)) {

        Error = GetLastError();
        goto exit;
    }

    if (ARGUMENT_PRESENT(psData)) {
        HashBuffer = (PBYTE)DtSippHeapAlloc(HashSize);
        if (NULL == HashBuffer) {
            Error = ERROR_NOT_ENOUGH_MEMORY;
            goto exit;
        }

        if (!CryptGetHashParam(Hash,
                               HP_HASHVAL,
                               HashBuffer,
                               &HashSize,
                               0)) {

            Error = GetLastError();
            goto exit;
        }
    }

    //
    // Encode siginfo.
    //

    BYTE  SigInfoBuffer[sizeof(SPC_SIGINFO) * 2];   // 2X worst case growth
    DWORD dwSigInfoSize = sizeof(SigInfoBuffer);
    SPC_SIGINFO SigInfo = {0};
    SigInfo.dwSipVersion = DTSIP_VERSION;
    SigInfo.gSIPGuid = DtSipGUID;

    if (!CryptEncodeObject(DTSIP_ENCODING,
                           SPC_SIGINFO_OBJID,
                           &SigInfo,
                           SigInfoBuffer,
                           &dwSigInfoSize)) {

        Error = GetLastError();
        goto exit;
    }

    //
    //  Write psData members and append referenced fields
    //

    DWORD dwOffsetSigId   = sizeof(SIP_INDIRECT_DATA);
    DWORD dwSizeSigId     = sizeof(SPC_SIGINFO_OBJID); // includes terminator
    DWORD dwOffsetSigInfo = dwOffsetSigId + dwSizeSigId;
    DWORD dwOffsetSzAlgId = dwOffsetSigInfo + dwSigInfoSize;
    DWORD dwSizeSzAlgId   = (DWORD)strlen(pszAlgId) + 1;
    DWORD dwOffsetHash    = dwOffsetSzAlgId + dwSizeSzAlgId;
    DWORD dwTotalSize     = dwOffsetHash + HashSize;
    DWORD dwBufferSize    = *pdwDataLen;

    *pdwDataLen           = dwTotalSize;    // returned length

    if (ARGUMENT_PRESENT(psData)) {
        if (dwTotalSize > dwBufferSize) {
            Error = ERROR_INSUFFICIENT_BUFFER;
            goto exit;
        }

        psData->Data.pszObjId     = (PCHAR)psData + dwOffsetSigId;
        psData->Data.Value.pbData = (PBYTE)psData + dwOffsetSigInfo;
        psData->Data.Value.cbData = dwSigInfoSize;

        psData->DigestAlgorithm.pszObjId = (PCHAR)psData + dwOffsetSzAlgId;
        psData->DigestAlgorithm.Parameters.pbData = NULL;
        psData->DigestAlgorithm.Parameters.cbData = 0;

        psData->Digest.pbData = (PBYTE)psData + dwOffsetHash;
        psData->Digest.cbData = HashSize;

        RtlCopyMemory((PBYTE)psData + dwOffsetSigId,   SPC_SIGINFO_OBJID, dwSizeSigId  );
        RtlCopyMemory((PBYTE)psData + dwOffsetSigInfo, SigInfoBuffer,     dwSigInfoSize);
        RtlCopyMemory((PBYTE)psData + dwOffsetSzAlgId, pszAlgId,          dwSizeSzAlgId);
        RtlCopyMemory((PBYTE)psData + dwOffsetHash,    HashBuffer,        HashSize     );
    }


    Error = NO_ERROR;

exit:
    if (NULL != HashBuffer) {
        DtSippHeapFree(HashBuffer);
    }

    if (NULL != Contents) {
        DtSippHeapFree(Contents);
    }

    if (0 != Hash) {
        CryptDestroyHash(Hash);
    }

    if (!ExternalCsp && (0 != Csp)) {
        CryptReleaseContext(Csp, 0);
    }

    SetLastError(Error);
    return NO_ERROR == Error;
}


DTSIP_EXPORT(DtSipVerifyHash, 8)
_Success_(return != FALSE)
BOOL
WINAPI
DtSipVerifyHash (
    _In_ SIP_SUBJECTINFO* pSubjectInfo,
    _In_ SIP_INDIRECT_DATA* psData
    )

/*++

Routine Description:

    This routine verifies the cryptographic hash of the file
    Implements the SIP interface CryptSIPVerifyIndirectData:
    http://msdn.microsoft.com/en-us/library/cc542591(v=VS.85).aspx

Arguments:

    pSubjectInfo - SIP subject information

    psData - SIP indirect data structure containing the hash data of the package.

Return Value:

    TRUE if the function succeeded, FALSE otherwise. GetLastError will return extended error information.
    Possible error codes include:
        - TRUST_E_SUBJECT_FORM_UNKNOWN: Specified subject type is invalid.
        - TRUST_E_BAD_DIGEST: Digests in the indirectData do not match expected values.
        - ERROR_BAD_FORMAT: Specified data or file format of the SIP is invalid.
        - ERROR_INVALID_PARAMETER: Specified parameters are NULL or otherwise invalid.
        - ERROR_OUTOFMEMORY: Error allocating memory

--*/

{

    DWORD Error;
    PBYTE Contents;
    DWORD ByteSize;
    HCRYPTPROV Csp;
    BOOL ExternalCsp;
    PCSTR pszAlgId;
    DWORD dwAlgId;
    HCRYPTHASH Hash;
    PBYTE HashBuffer;
    DWORD HashSize;
    DWORD DecodedSIPVersion;

    Contents = NULL;
    ExternalCsp = FALSE;
    Csp = 0;
    Hash = 0;
    HashBuffer = NULL;

    //
    // Verify the input.
    //

    if (!ARGUMENT_PRESENT(pSubjectInfo) ||
        !ARGUMENT_PRESENT(psData)) {

        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    //
    // Check the SIP version.
    //

    Error = DtSippDecodeSIPVersion(&psData->Data.Value, &DecodedSIPVersion);
    if (NO_ERROR != Error) {
        goto exit;
    }

    //
    // Calculate the algorithm ID.
    // It will either be a hash data or, if one does not exist,
    // the hashing algorithm of a signature.
    //

    pszAlgId = pSubjectInfo->DigestAlgorithm.pszObjId;
    if (NULL == pszAlgId) {
        pszAlgId = psData->DigestAlgorithm.pszObjId;
    }

    if (NULL == pszAlgId) {
        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    dwAlgId = DtSippOidAlgIdToAlgId(pszAlgId);
    if (0 == dwAlgId) {
        Error = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    //
    // Open crypto algorithm provider.
    //

    Error = DtSippOpenSubjectInfoProvider(pSubjectInfo,
                                          &Csp,
                                          &ExternalCsp);

    if (NO_ERROR != Error) {
        goto exit;
    }

    //
    // Get subject contents.
    //

    Error = DtSippLoadContentsFromSubjectInfo(pSubjectInfo,
                                              &Contents,
                                              &ByteSize);
    if (NO_ERROR != Error) {
        goto exit;
    }

    //
    // Prepare a hasher and calculate a hash.
    //

    if (!CryptCreateHash(Csp, dwAlgId, 0, 0, &Hash)) {
        Error = GetLastError();
        goto exit;
    }

    Error = DtSippHashFile(Contents, ByteSize, Hash);
    if (NO_ERROR != Error) {
        goto exit;
    }

    HashSize = 0;
    if (!CryptGetHashParam(Hash,
                           HP_HASHVAL,
                           NULL,
                           &HashSize,
                           0)) {

        Error = GetLastError();
        goto exit;
    }

    HashBuffer = (PBYTE)DtSippHeapAlloc(HashSize);
    if (NULL == HashBuffer) {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }

    if (!CryptGetHashParam(Hash,
                           HP_HASHVAL,
                           HashBuffer,
                           &HashSize,
                           0)) {

        Error = GetLastError();
        goto exit;
    }

    //
    // Compare the calculated hash to what was stored in the signature.
    //

    if ((HashSize != psData->Digest.cbData ) ||
        !RtlEqualMemory(HashBuffer, psData->Digest.pbData, HashSize)) {

        Error = (DWORD)TRUST_E_BAD_DIGEST;
        goto exit;
    }

    //
    // Succeeded.
    //

    Error = NO_ERROR;

exit:
    if (NULL != HashBuffer) {
        DtSippHeapFree(HashBuffer);
    }

    if (NULL != Contents) {
        DtSippHeapFree(Contents);
    }

    if (0 != Hash) {
        CryptDestroyHash(Hash);
    }

    if (!ExternalCsp && (0 != Csp)) {
        CryptReleaseContext(Csp, 0);
    }

    SetLastError(Error);
    return NO_ERROR == Error;
}

#if defined(DTSIP_STANDALONE)

//
// Following routines are here to support this SIP discovery through the
// registry mechanism of wintrust.dll
//

EXTERN_C PVOID __ImageBase;

DTSIP_EXPORT(DllRegisterServer, 0);
STDAPI
DllRegisterServer (
    VOID
    )
{
    SIP_ADD_NEWPROVIDER Provider;
    HRESULT hr;
    WCHAR Path[MAX_PATH + 1];

    //
    // We need to use the full path of the module because the file
    // may not be inbox so loader may not find the file by default.
    //

    if (0 == GetModuleFileNameW((HMODULE)&__ImageBase, Path, RTL_NUMBER_OF(Path))) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto exit;
    }

    //
    // Register the provider with SIP.
    //

    RtlZeroMemory(&Provider, sizeof(SIP_ADD_NEWPROVIDER));
    Provider.cbStruct               = sizeof(SIP_ADD_NEWPROVIDER);
    Provider.pgSubject              = (GUID*)&DtSipGUID; // const_cast
    Provider.pwszDLLFileName        = Path;
    Provider.pwszGetFuncName        = L"DtSipGetSignature";
    Provider.pwszPutFuncName        = L"DtSipPutSignature";
    Provider.pwszCreateFuncName     = L"DtSipCreateHash";
    Provider.pwszVerifyFuncName     = L"DtSipVerifyHash";
    Provider.pwszRemoveFuncName     = L"DtSipDelSignature";
    Provider.pwszIsFunctionNameFmt2 = L"DtSipIsMyFileType";
    Provider.pwszGetCapFuncName     = L"DtSipGetCaps";

    if (!CryptSIPAddProvider(&Provider)) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto exit;
    }

    hr = S_OK;

exit:
    return hr;
}

DTSIP_EXPORT(DllUnregisterServer, 0);
STDAPI
DllUnregisterServer (
    VOID
    )
{
    (void)CryptSIPRemoveProvider((GUID*)&DtSipGUID);  // const_cast
    return S_OK;
}

DTSIP_EXPORT(DllCanUnloadNow, 0);
STDAPI
DllCanUnloadNow (
    VOID
    )
{
    return S_OK;
}

#endif


