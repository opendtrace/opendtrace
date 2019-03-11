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

    dt_security.c

Abstract:

    This module contains the implementation of the DTrace security
    support.

    The security is based on group policy settings to require
    a .d script to be properly signed when enforced.

    Script signing enforcement is mirrors the same implemented by PowerShell.

    Matching PowerShell documentation on execution policies can be found here:
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies

    Value sources (in the order of decreased priority):
    - GP Machine:
        HKLM\\Software\\Policies\\OpenDTrace\\Dtrace, ExecutionPolicy, REG_SZ
    - GP User:
        HKCU\\Software\\Policies\\OpenDTrace\\Dtrace, ExecutionPolicy, REG_SZ
    - Env variable:
        DTRACE_EXECUTION_POLICY
    - HKCU:
        HKCU\\Software\\OpenDTrace\\Dtrace, ExecutionPolicy, REG_SZ
    - HKLM:
        HKLM\\Software\\OpenDTrace\\Dtrace, ExecutionPolicy, REG_SZ

    Values:
    - "Bypass": do not perform signature checks
    - "Unrestricted" - Do not perform checks on local files, allow user's
        contest to use unsigned remote files.
    - "RemoteSigned" - Do not perform checks on local files, require valid
        and trusted signature for remote files.
    - "AllSigned" - Require valid and trusted signature for all files.
    - "Restricted" - Script file must be installed as a system component, and
        have a signature from the trusted source.

--*/

#include <ntcompat.h>
#include "dt_impl.h"

#include <wintrust.h>
#include <softpub.h>

extern const GUID DtSipGUID;

//
// Execution policy value type.
//

enum dt_execution_policy_value {
    // Require signing on files originating from remote locations, prompt override.
    dt_execution_policy_value_Unrestricted = 0,
    // Require signing on files originating from remote locations.
    dt_execution_policy_value_RemoteSigned = 1,
    // Require signatures.
    dt_execution_policy_value_AllSigned    = 2,
    // Require signed file to be at the trusted protected local location.
    dt_execution_policy_value_Restricted   = 3,
    // No files must be signed.
    dt_execution_policy_value_Bypass       = 4,
    // Not specified at this scope
    dt_execution_policy_value_Undefined    = 5,

    // Default value in case if none was found.
    dt_execution_policy_value_Default = dt_execution_policy_value_Restricted
};

//
// Execution policy scope type.
// Arranged in the order of decreased priority.
//

enum dt_execution_policy_scope {
    // Machine GP setting.
    dt_execution_policy_scope_MachinePolicy = 0,
    // Current user GP setting.
    dt_execution_policy_scope_UserPolicy    = 1,
    // 'DTRACE_EXECUTION_POLICY' env value.
    dt_execution_policy_scope_Process       = 2,
    // 'HKEY_CURRENT_USER'
    dt_execution_policy_scope_CurrentUser   = 3,
    // 'HKEY_LOCAL_MACHINE'
    dt_execution_policy_scope_LocalMachine  = 4,
};

static
PCSTR
dtw32_execution_policy_value_string (
    _In_ enum dt_execution_policy_value value
    )
{
    switch (value) {
    case dt_execution_policy_value_Bypass:       return "Bypass";
    case dt_execution_policy_value_Unrestricted: return "Unrestricted";
    case dt_execution_policy_value_RemoteSigned: return "RemoteSigned";
    case dt_execution_policy_value_AllSigned:    return "AllSigned";
    case dt_execution_policy_value_Restricted:   return "Restricted";
    default: return NULL;
    }
}

static
PCSTR
dtw32_execution_policy_scope_string (
    _In_ enum dt_execution_policy_value value
    )
{
    switch (value) {
    case dt_execution_policy_scope_MachinePolicy: return "MachinePolicy";
    case dt_execution_policy_scope_UserPolicy:    return "UserPolicy";
    case dt_execution_policy_scope_Process:       return "Process";
    case dt_execution_policy_scope_CurrentUser:   return "CurrentUser";
    case dt_execution_policy_scope_LocalMachine:  return "LocalMachine";
    default: return NULL;
    }
}

static
PCSTR
dtw32_execution_scope_path_string (
    _In_ enum dt_execution_policy_scope scope
    )
{
    switch (scope) {
    case dt_execution_policy_scope_MachinePolicy:
    case dt_execution_policy_scope_UserPolicy:
        return "Software\\Policies\\OpenDTrace\\Dtrace";

    case dt_execution_policy_scope_CurrentUser:
    case dt_execution_policy_scope_LocalMachine:
        return "Software\\OpenDTrace\\Dtrace";

    default:
        return NULL;
    }
}

static
HKEY
dtw32_execution_scope_path_root (
    _In_ enum dt_execution_policy_scope scope
    )
{
    switch (scope) {
    case dt_execution_policy_scope_MachinePolicy:
    case dt_execution_policy_scope_LocalMachine:
        return HKEY_LOCAL_MACHINE;

    case dt_execution_policy_scope_UserPolicy:
    case dt_execution_policy_scope_CurrentUser:
        return HKEY_CURRENT_USER;

    default:
        return NULL;
    }
}

static
enum dt_execution_policy_value
dtw32_execution_policy_parse (
    _In_opt_ PSTR policy_string
    )
{
    if ((NULL == policy_string) || ('\0' == *policy_string)) {
        return dt_execution_policy_value_Undefined;
    }

    for (enum dt_execution_policy_value v = 0;
         v < dt_execution_policy_value_Undefined;
         v += 1) {

        if (0 == _stricmp(policy_string, dtw32_execution_policy_value_string(v))) {
            return v;
        }
    }

    return dt_execution_policy_value_Default;
}

static
BOOL
dtw32_get_execution_policy_for_scope (
    _In_ enum dt_execution_policy_scope scope,
    _Out_ enum dt_execution_policy_value* value
    )
{
    CHAR buf[20];

    switch (scope) {
    case dt_execution_policy_scope_Process: {
        DWORD len = GetEnvironmentVariableA("DTRACE_EXECUTION_POLICY", buf, sizeof(buf));
        if ((0 == len) || (len >= sizeof(buf))) {
            buf[0] = '\0';
        }

        break;
    }

    case dt_execution_policy_scope_CurrentUser:
    case dt_execution_policy_scope_LocalMachine:
    case dt_execution_policy_scope_UserPolicy:
    case dt_execution_policy_scope_MachinePolicy: {
        HKEY hk;
        LONG error;
        error = RegOpenKeyExA(dtw32_execution_scope_path_root(scope),
                              dtw32_execution_scope_path_string(scope),
                              0,
                              KEY_QUERY_VALUE,
                              &hk);

        if (ERROR_FILE_NOT_FOUND == error) {
            buf[0] = '\0';
            break;
        }

        if (NO_ERROR != error) {
            return FALSE;
        }

        DWORD bufSize = sizeof(buf) - 1;
        DWORD type;
        error = RegQueryValueExA(hk,
                                 "ExecutionPolicy",
                                 NULL,
                                 &type,
                                 (PBYTE)&buf[0],
                                 &bufSize);

        if (ERROR_FILE_NOT_FOUND == error) {
            buf[0] = '\0';
            break;
        }

        if (NO_ERROR != error) {
            return FALSE;
        }

        if (REG_SZ != type) {
            *value = dt_execution_policy_value_Default;
            return TRUE;
        }

        buf[bufSize] = '\0';
        break;
    }

    default:
        *value = dt_execution_policy_value_Default;
        return TRUE;
    }

    *value = dtw32_execution_policy_parse(buf);
    return TRUE;
}

static
BOOL
dtw32_is_local_file (
    _In_ FILE* fp
    )
{

    HANDLE h =  (HANDLE)_get_osfhandle(_fileno(fp));
    if (INVALID_HANDLE_VALUE == h) {
        return FALSE;
    }

    //
    // Query remoting protocol information.
    // This call will determine if network interface is in the
    // path.
    //

    FILE_REMOTE_PROTOCOL_INFO rinfo;
    ZeroMemory(&rinfo, sizeof(rinfo));
    rinfo.StructureSize = sizeof(FILE_REMOTE_PROTOCOL_INFO);
    if (GetFileInformationByHandleEx(h,
                                     FileRemoteProtocolInfo,
                                     &rinfo,
                                     sizeof(rinfo))) {

        return FALSE;
    }

    //
    // TODO:
    //    - Exclude removable media.
    //    - Check urlmon stream and exclude files marked as originating
    //      from a remote location.
    //

    return TRUE;
}

static
BOOL
dtw32_is_system_location_file (
    _In_ FILE* fp
    )
{
    // TODO:
    fp;
    return FALSE;
}

static
BOOL
dtw32_prompt_cert_ok (
    _In_opt_ PCCERT_CONTEXT Cert
    )
{

    // TODO:
    Cert;
    return FALSE;
}

static
BOOL
dtw32_is_trusted_publisher (
    _In_ PCCERT_CONTEXT Cert
    )
{

    HCERTSTORE Store = NULL;;
    PCCERT_CONTEXT FoundCert = NULL;
    BOOL CheckOk = FALSE;
    BYTE* Thumbprint = NULL;
    DWORD ThumbprintSize;
    CRYPT_HASH_BLOB HashBlob;

    //
    // Get thumbprint of this certificate.
    //

    if (!CertGetCertificateContextProperty(Cert,
                                           CERT_SHA1_HASH_PROP_ID,
                                           NULL,
                                           &ThumbprintSize)) {

        goto exit;
    }

    Thumbprint = malloc(ThumbprintSize);
    if (NULL == Thumbprint) {
        goto exit;
    }

    if (!CertGetCertificateContextProperty(Cert,
                                           CERT_SHA1_HASH_PROP_ID,
                                           Thumbprint,
                                           &ThumbprintSize)) {

        goto exit;
    }

    //
    // Look it up in a trusted store.
    //

    Store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
                          (X509_ASN_ENCODING |
                           PKCS_7_ASN_ENCODING),
                          (HCRYPTPROV)NULL,
                          (CERT_STORE_OPEN_EXISTING_FLAG |
                           CERT_STORE_READONLY_FLAG |
                           CERT_SYSTEM_STORE_CURRENT_USER),
                          L"TrustedPublisher");
    if (NULL == Store) {
        goto exit;
    }

    HashBlob.pbData = Thumbprint;
    HashBlob.cbData = ThumbprintSize;
    FoundCert = CertFindCertificateInStore(Store,
                                           (PKCS_7_ASN_ENCODING |
                                            X509_ASN_ENCODING),
                                           0,
                                           CERT_FIND_HASH,
                                           &HashBlob,
                                           NULL);

    if (NULL == FoundCert) {
        dt_dprintf("Execution policy: publisher is not on the trusted list.\n");
        goto exit;
    }

    CertFreeCertificateContext(FoundCert);
    FoundCert = NULL;
    CertCloseStore(Store, 0);
    Store = NULL;

    //
    // Look it up in untrusted store.
    //

    Store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
                          (X509_ASN_ENCODING |
                           PKCS_7_ASN_ENCODING),
                          (HCRYPTPROV)NULL,
                          (CERT_STORE_OPEN_EXISTING_FLAG |
                           CERT_STORE_READONLY_FLAG |
                           CERT_SYSTEM_STORE_CURRENT_USER),
                          L"Disallowed");
    if (NULL == Store) {
        goto exit;
    }

    HashBlob.pbData = Thumbprint;
    HashBlob.cbData = ThumbprintSize;
    FoundCert = CertFindCertificateInStore(Store,
                                           (PKCS_7_ASN_ENCODING |
                                            X509_ASN_ENCODING),
                                           0,
                                           CERT_FIND_HASH,
                                           &HashBlob,
                                           NULL);

    if (NULL != FoundCert) {
        dt_dprintf("Execution policy: publisher is on the untrusted list.\n");
        goto exit;
    }

    //
    // All checks are ok at this point.
    //

    CheckOk = TRUE;

exit:
    if (NULL != FoundCert) {
        CertFreeCertificateContext(FoundCert);
    }

    if (NULL != Store) {
        CertCloseStore(Store, 0);
    }

    if (NULL != Thumbprint) {
        free(Thumbprint);
    }

    return CheckOk;
}


//
// This module uses wintrust.dll, that is not a part of the universal
// API surface.
//

static BOOL wtLoaded;
static HMODULE wtModule;
static LONG (WINAPI* wtWinVerifyTrustEx)(HWND hwnd, GUID *pgActionID, LPVOID pWVTData);
static CRYPT_PROVIDER_DATA* (WINAPI* wtWTHelperProvDataFromStateData)(HANDLE hStateData);
static CRYPT_PROVIDER_SGNR* (WINAPI* wtWTHelperGetProvSignerFromChain)(CRYPT_PROVIDER_DATA *pProvData,
                  DWORD idxSigner, BOOL fCounterSigner, DWORD idxCounterSigner);
static CRYPT_PROVIDER_CERT* (WINAPI* wtWTHelperGetProvCertFromChain)(CRYPT_PROVIDER_SGNR *pSgnr,
                  DWORD idxCert);

static
BOOL
dtw32_load_wintrust (
    void
    )
{
    if (wtLoaded) {
        return NULL != wtModule;
    }

    wtLoaded = TRUE;
    wtModule = LoadLibraryW(L"wintrust.dll");
    if (NULL == wtModule) {
        return FALSE;
    }

    *(PULONG_PTR)&wtWinVerifyTrustEx =
        (ULONG_PTR)GetProcAddress(wtModule, "WinVerifyTrustEx");
    *(PULONG_PTR)&wtWTHelperProvDataFromStateData =
        (ULONG_PTR)GetProcAddress(wtModule, "WTHelperProvDataFromStateData");
    *(PULONG_PTR)&wtWTHelperGetProvSignerFromChain =
        (ULONG_PTR)GetProcAddress(wtModule, "WTHelperGetProvSignerFromChain");
    *(PULONG_PTR)&wtWTHelperGetProvCertFromChain =
        (ULONG_PTR)GetProcAddress(wtModule, "WTHelperGetProvCertFromChain");

    if ((NULL == wtWinVerifyTrustEx) ||
        (NULL == wtWTHelperProvDataFromStateData) ||
        (NULL == wtWTHelperGetProvSignerFromChain) ||
        (NULL == wtWTHelperGetProvCertFromChain)) {

        FreeLibrary(wtModule);
        wtModule = NULL;
        return FALSE;
    }

    return TRUE;
}

static
BOOL
dtw32_check_signature_of (
    _In_reads_bytes_(ByteCount) PBYTE Data,
    _In_ DWORD ByteCount
    )
{

    WINTRUST_DATA wtd;
    WINTRUST_BLOB_INFO wbi;
    GUID Action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    BOOL CloseWtd = FALSE;
    BOOL CheckOk = FALSE;
    HRESULT hr;

    ZeroMemory(&wtd, sizeof(wtd));
    ZeroMemory(&wbi, sizeof(wbi));

    if (!dtw32_load_wintrust()) {
        dt_dprintf("Execution policy: wintrust.dll is not available.\n");
        goto exit;
    }

    //
    // Call WinVerifyTrust to check the signature.
    //

    wbi.cbStruct = sizeof(wbi);
    wbi.gSubject = DtSipGUID;
    wbi.pcwszDisplayName = L"DTrace script";
    wbi.cbMemObject = ByteCount;
    wbi.pbMemObject = Data;

    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwUnionChoice = WTD_CHOICE_BLOB;
    wtd.pBlob = &wbi;

    hr = wtWinVerifyTrustEx(INVALID_HANDLE_VALUE, &Action, &wtd);
    if (FAILED(hr)) {
        dt_dprintf("Execution policy: signature check failed, hr=%08lx.\n", hr);
        goto exit;
    }

    dt_dprintf("Execution policy: script is signed.\n");
    CloseWtd = TRUE;

    //
    // The file is signed, and signature checked ok.
    // See if it is trusted.
    //

    CRYPT_PROVIDER_DATA* pd =
        wtWTHelperProvDataFromStateData(wtd.hWVTStateData);

    if (NULL == pd) {
        goto exit;
    }

    CRYPT_PROVIDER_SGNR* sgnr =
        wtWTHelperGetProvSignerFromChain(pd, 0, FALSE, 0);

    if (NULL == sgnr) {
        goto exit;
    }

    CRYPT_PROVIDER_CERT* cert =
        wtWTHelperGetProvCertFromChain(sgnr, 0);

    if (NULL == cert) {
        goto exit;
    }

    CheckOk = dtw32_is_trusted_publisher(cert->pCert);
    if (CheckOk) {
        goto exit;
    }

    //
    // Prompt to trust this publisher.
    // If TRUE is returned, then user allowed the trust override.
    //

    if (dtw32_prompt_cert_ok(cert->pCert)) {
        dt_dprintf("Execution policy: user override of certificate trust\n");
        CheckOk = TRUE;
    }

exit:
    if (CloseWtd) {
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        wtWinVerifyTrustEx(INVALID_HANDLE_VALUE, &Action, &wtd);
    }

    return CheckOk;
}

int dt_execution_policy(FILE** fp, char** s)
{

    int noexec = 1;

    //
    // Calculate effective execution policy value.
    //

    enum dt_execution_policy_scope value;

    for (enum dt_execution_policy_scope scope = 0;
         scope <= dt_execution_policy_scope_LocalMachine;
         scope += 1) {

        if (!dtw32_get_execution_policy_for_scope(scope, &value)) {
            value = dt_execution_policy_value_Default;
            break;
        }

        if (dt_execution_policy_value_Undefined != value) {
            dt_dprintf("Execution policy: '%s' from scope '%s'\n",
                       dtw32_execution_policy_value_string(value),
                       dtw32_execution_policy_scope_string(scope));
            break;
        }
    }

    if (dt_execution_policy_value_Undefined == value) {
        value = dt_execution_policy_value_Default;
        dt_dprintf("Execution policy: '%s' (default)\n",
                   dtw32_execution_policy_value_string(value));
    }

    //
    // Completely bypass if policy said to.
    //

    if (dt_execution_policy_value_Bypass == value) {
        noexec = 0;
        goto exit;
    }

    //
    // 'Restricted' requires script file to be in the system-controled
    // location.
    //

    if (dt_execution_policy_value_Restricted == value) {
        if ((NULL == *fp) || !dtw32_is_system_location_file(*fp)) {
            dt_dprintf("Execution policy: 'Restricted' requires file to be at the system location\n");
            goto exit;
        }
    }

    //
    // If checks are only enforced for remote files,
    // check if file is local and trusted.
    // If string is passed to this routine, the code is treated
    // as local (i.e. provided at the command line).
    //

    if ((dt_execution_policy_value_Unrestricted == value) ||
        (dt_execution_policy_value_RemoteSigned == value)) {

        if ((NULL == *fp) || dtw32_is_local_file(*fp)) {
            dt_dprintf("Execution policy: '%s' allows bypass for local files.\n",
                       dtw32_execution_policy_value_string(value));
            noexec = 0;
            goto exit;
        }
    }

    //
    // Future checks will require a signature.
    // For this, the code along with the signature will be loaded
    // into memory, so any chnge to on-disk data will not be able to
    // compromize the check results.
    //

    if (NULL == *s) {
        HANDLE h = (HANDLE)_get_osfhandle(_fileno(*fp));
        DWORD cb = GetFileSize(h, NULL);
        if (INVALID_FILE_SIZE == cb) {
            goto exit;
        }

        char* b = malloc(cb + 1);
        if (NULL == b) {
            goto exit;
        }

        DWORD BytesDone;
        if (!ReadFile(h, b, cb, &BytesDone, NULL) || (BytesDone != cb)) {
            free(b);
            goto exit;
        }

        b[cb] = '\0';

        *s = b;
        *fp = NULL;
    }

    if (dtw32_check_signature_of((PBYTE)*s, (DWORD)strlen(*s))) {
        dt_dprintf("Execution policy: signature check succeeded.\n");
        noexec = 0;
        goto exit;
    }

    if (dt_execution_policy_value_Unrestricted == value) {
        if (dtw32_prompt_cert_ok(NULL)) {
            dt_dprintf("Execution policy: user override of failed signature check\n");
            noexec = 0;
            goto exit;
        }
    }

exit:
    return noexec;
}

