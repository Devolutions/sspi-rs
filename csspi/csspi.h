#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef int32_t (*Test2)(void);

typedef struct FunctionTable {
  Test2 test;
} FunctionTable;

typedef struct ConstTable {
  int32_t a;
  int32_t b;
} ConstTable;

typedef unsigned short SEC_WCHAR;

typedef struct SecPkgInfoW {
  unsigned long fCapabilities;
  unsigned short wVersion;
  unsigned short wRPCID;
  unsigned long cbMaxToken;
  SEC_WCHAR *Name;
  SEC_WCHAR *Comment;
} SecPkgInfoW;

typedef struct SecPkgInfoW *PSecPkgInfoW;

typedef void (*HELPER_FN)(PSecPkgInfoW);

typedef int32_t SecurityStatus;

typedef SecurityStatus (*ENUMERATE_SECURITY_PACKAGES_FN_W)(unsigned long*, PSecPkgInfoW*);

typedef struct SecHandle {
  unsigned long dwLower;
  unsigned long dwUpper;
} SecHandle;

typedef struct SecHandle *PCredHandle;

typedef SecurityStatus (*QUERY_CREDENTIALS_ATTRIBUTES_FN_W)(PCredHandle, unsigned long, void*);

typedef const SEC_WCHAR *LPCWSTR;

typedef void (*SEC_GET_KEY_FN)(void*, void*, uint32_t, void**, int32_t*);

typedef struct SecurityInteger {
  unsigned long LowPart;
  long HighPart;
} SecurityInteger;

typedef const struct SecurityInteger *PTimeStamp;

typedef SecurityStatus (*ACQUIRE_CREDENTIALS_HANDLE_FN_W)(LPCWSTR, LPCWSTR, unsigned long, const void*, const void*, SEC_GET_KEY_FN, const void*, PCredHandle, PTimeStamp);

typedef SecurityStatus (*FREE_CREDENTIALS_HANDLE_FN)(PCredHandle);

typedef struct SecHandle *PCtxtHandle;

typedef struct SecurityString {
  unsigned short Length;
  unsigned short MaximumLength;
  unsigned short *Buffer;
} SecurityString;

typedef const struct SecurityString *PSecurityString;

typedef struct SecurityBuffer {
  unsigned long cbBuffer;
  unsigned long BufferType;
  char *pvBuffer;
} SecurityBuffer;

typedef struct SecurityBuffer *PSecurityBuffer;

typedef struct SecBufferDesc {
  unsigned long ulVersion;
  unsigned long cBuffers;
  PSecurityBuffer pBuffers;
} SecBufferDesc;

typedef struct SecBufferDesc *PSecBufferDesc;

typedef SecurityStatus (*INITIALIZE_SECURITY_CONTEXT_FN_W)(PCredHandle, PCtxtHandle, PSecurityString, unsigned long, unsigned long, unsigned long, PSecBufferDesc, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long*, PTimeStamp);

typedef SecurityStatus (*ACCEPT_SECURITY_CONTEXT_FN)(PCredHandle, PCtxtHandle, PSecBufferDesc, unsigned long, unsigned long, PCtxtHandle, PSecBufferDesc, unsigned long*, PTimeStamp);

typedef SecurityStatus (*COMPLETE_AUTH_TOKEN_FN)(PCtxtHandle, PSecBufferDesc);

typedef SecurityStatus (*DELETE_SECURITY_CONTEXT_FN)(PCtxtHandle);

typedef SecurityStatus (*APPLY_CONTROL_TOKEN_FN)(PCtxtHandle, PSecBufferDesc);

typedef SecurityStatus (*QUERY_CONTEXT_ATTRIBUTES_FN_W)(PCtxtHandle, unsigned long, void*);

typedef SecurityStatus (*IMPERSONATE_SECURITY_CONTEXT_FN)(PCtxtHandle);

typedef SecurityStatus (*REVERT_SECURITY_CONTEXT_FN)(PCtxtHandle);

typedef SecurityStatus (*MAKE_SIGNATURE_FN)(PCtxtHandle, unsigned long, PSecBufferDesc, unsigned long);

typedef SecurityStatus (*VERIFY_SIGNATURE_FN)(PCtxtHandle, PSecBufferDesc, unsigned long, unsigned long*);

typedef SecurityStatus (*FREE_CONTEXT_BUFFER_FN)(void*);

typedef SecurityStatus (*QUERY_SECURITY_PACKAGE_INFO_FN_W)(PSecurityString, PSecPkgInfoW*);

typedef SecurityStatus (*EXPORT_SECURITY_CONTEXT_FN)(PCtxtHandle, unsigned long, PSecurityBuffer, void**);

typedef SecurityStatus (*IMPORT_SECURITY_CONTEXT_FN_W)(PSecurityString, PSecurityBuffer, void*, PCtxtHandle);

typedef SecurityStatus (*ADD_CREDENTIALS_FN_W)(void);

typedef SecurityStatus (*QUERY_SECURITY_CONTEXT_TOKEN_FN)(PCtxtHandle, void**);

typedef SecurityStatus (*ENCRYPT_MESSAGE_FN)(PCtxtHandle, unsigned long, PSecBufferDesc, unsigned long);

typedef SecurityStatus (*DECRYPT_MESSAGE_FN)(PCtxtHandle, PSecBufferDesc, unsigned long, unsigned long*);

typedef SecurityStatus (*SET_CONTEXT_ATTRIBUTES_FN_W)(PCtxtHandle, unsigned long, void*, unsigned long);

typedef SecurityStatus (*SET_CREDENTIALS_ATTRIBUTES_FN_W)(PCtxtHandle, unsigned long, void*, unsigned long);

typedef SecurityStatus (*CHANGE_PASSWORD_FN_W)(SEC_WCHAR*, SEC_WCHAR*, SEC_WCHAR*, SEC_WCHAR*, SEC_WCHAR*, bool, unsigned long, PSecBufferDesc);

typedef SecurityStatus (*QUERY_CONTEXT_ATTRIBUTES_EX_FN_W)(PCtxtHandle, unsigned long, void*, unsigned long);

typedef SecurityStatus (*QUERY_CREDENTIALS_ATTRIBUTES_EX_FN_W)(PCredHandle, unsigned long, void*, unsigned long);

typedef struct SecurityFunctionTableW {
  HELPER_FN helper;
  unsigned long dwVersion;
  ENUMERATE_SECURITY_PACKAGES_FN_W EnumerateSecurityPackagesW;
  QUERY_CREDENTIALS_ATTRIBUTES_FN_W QueryCredentialsAttributesW;
  ACQUIRE_CREDENTIALS_HANDLE_FN_W AcquireCredentialsHandleW;
  FREE_CREDENTIALS_HANDLE_FN FreeCredentialsHandle;
  const void *Reserved2;
  INITIALIZE_SECURITY_CONTEXT_FN_W InitializeSecurityContextW;
  ACCEPT_SECURITY_CONTEXT_FN AcceptSecurityContext;
  COMPLETE_AUTH_TOKEN_FN CompleteAuthToken;
  DELETE_SECURITY_CONTEXT_FN DeleteSecurityContext;
  APPLY_CONTROL_TOKEN_FN ApplyControlToken;
  QUERY_CONTEXT_ATTRIBUTES_FN_W QueryContextAttributesW;
  IMPERSONATE_SECURITY_CONTEXT_FN ImpersonateSecurityContext;
  REVERT_SECURITY_CONTEXT_FN RevertSecurityContext;
  MAKE_SIGNATURE_FN MakeSignature;
  VERIFY_SIGNATURE_FN VerifySignature;
  FREE_CONTEXT_BUFFER_FN FreeContextBuffer;
  QUERY_SECURITY_PACKAGE_INFO_FN_W QuerySecurityPackageInfoW;
  const void *Reserved3;
  const void *Reserved4;
  EXPORT_SECURITY_CONTEXT_FN ExportSecurityContext;
  IMPORT_SECURITY_CONTEXT_FN_W ImportSecurityContextW;
  ADD_CREDENTIALS_FN_W AddCredentialsW;
  const void *Reserved8;
  QUERY_SECURITY_CONTEXT_TOKEN_FN QuerySecurityContextToken;
  ENCRYPT_MESSAGE_FN EncryptMessage;
  DECRYPT_MESSAGE_FN DecryptMessage;
  SET_CONTEXT_ATTRIBUTES_FN_W SetContextAttributesW;
  SET_CREDENTIALS_ATTRIBUTES_FN_W SetCredentialsAttributesW;
  CHANGE_PASSWORD_FN_W ChangeAccountPasswordW;
  const void *Reserved9;
  QUERY_CONTEXT_ATTRIBUTES_EX_FN_W QueryContextAttributesExW;
  QUERY_CREDENTIALS_ATTRIBUTES_EX_FN_W QueryCredentialsAttributesExW;
} SecurityFunctionTableW;

void rust_function(void);

int32_t test_2(void);

struct FunctionTable init(void);

struct ConstTable init_const(void);

struct SecurityFunctionTableW InitSecurityInterfaceW(void);

SecurityStatus FreeCredentialsHandle(PCredHandle phCredential);

SecurityStatus AcceptSecurityContext(PCredHandle phCredential,
                                     PCtxtHandle phContext,
                                     PSecBufferDesc pInput,
                                     unsigned long fContextReq,
                                     unsigned long TargetDataRep,
                                     PCtxtHandle phNewContext,
                                     PSecBufferDesc pOutput,
                                     unsigned long *pfContextAttr,
                                     PTimeStamp ptsExpiry);

SecurityStatus CompleteAuthToken(PCtxtHandle phContext, PSecBufferDesc pToken);

SecurityStatus DeleteSecurityContext(PCtxtHandle phContext);

SecurityStatus ApplyControlToken(PCtxtHandle phContext, PSecBufferDesc pInput);

SecurityStatus ImpersonateSecurityContext(PCtxtHandle phContext);

SecurityStatus RevertSecurityContext(PCtxtHandle phContext);

SecurityStatus MakeSignature(PCtxtHandle phContext,
                             unsigned long fQOP,
                             PSecBufferDesc pMessage,
                             unsigned long MessageSeqNo);

SecurityStatus VerifySignature(PCtxtHandle phContext,
                               PSecBufferDesc message,
                               unsigned long MessageSeqNo,
                               unsigned long *pfQOP);

SecurityStatus FreeContextBuffer(void *pvContextBuffer);

SecurityStatus ExportSecurityContext(PCtxtHandle phContext,
                                     unsigned long fFlags,
                                     PSecurityBuffer pPackedContext,
                                     void **pToken);

SecurityStatus QuerySecurityContextToken(PCtxtHandle phContext, void **Token);

SecurityStatus EncryptMessage(PCtxtHandle phContext,
                              unsigned long fQOP,
                              PSecBufferDesc pMessage,
                              unsigned long MessageSeqNo);

SecurityStatus DecryptMessage(PCtxtHandle phContext,
                              PSecBufferDesc pMessage,
                              unsigned long MessageSeqNo,
                              unsigned long *pfQOP);

void helper(PSecPkgInfoW p_info);

SecurityStatus EnumerateSecurityPackagesW(unsigned long *pcPackages, PSecPkgInfoW *ppPackageInfo);

SecurityStatus QueryCredentialsAttributesW(PCredHandle phCredential,
                                           unsigned long ulAttribute,
                                           void *pBuffer);

SecurityStatus AcquireCredentialsHandleW(LPCWSTR pszPrincipal,
                                         LPCWSTR pszPackage,
                                         unsigned long fCredentialUse,
                                         const void *pvLogonId,
                                         const void *pAuthData,
                                         SEC_GET_KEY_FN pGetKeyFn,
                                         const void *pvGetKeyArgument,
                                         PCredHandle phCredential,
                                         PTimeStamp ptsExpiry);

SecurityStatus InitializeSecurityContextW(PCredHandle phCredential,
                                          PCtxtHandle phContext,
                                          PSecurityString pTargetName,
                                          unsigned long fContextReq,
                                          unsigned long Reserved1,
                                          unsigned long TargetDataRep,
                                          PSecBufferDesc pInput,
                                          unsigned long Reserved2,
                                          PCtxtHandle phNewContext,
                                          PSecBufferDesc pOutput,
                                          unsigned long *pfContextAttr,
                                          PTimeStamp ptsExpiry);

SecurityStatus QueryContextAttributesW(PCtxtHandle phContext,
                                       unsigned long ulAttribute,
                                       void *pBuffer);

SecurityStatus QuerySecurityPackageInfoW(PSecurityString pPackageName, PSecPkgInfoW *ppPackageInfo);

SecurityStatus ImportSecurityContextW(PSecurityString pszPackage,
                                      PSecurityBuffer pPackedContext,
                                      void *Token,
                                      PCtxtHandle phContext);

SecurityStatus AddCredentialsW(void);

SecurityStatus SetContextAttributesW(PCtxtHandle phContext,
                                     unsigned long ulAttribute,
                                     void *pBuffer,
                                     unsigned long cbBuffer);

SecurityStatus SetCredentialsAttributesW(PCtxtHandle phContext,
                                         unsigned long ulAttribute,
                                         void *pBuffer,
                                         unsigned long cbBuffer);

SecurityStatus ChangeAccountPasswordW(SEC_WCHAR *pszPackageName,
                                      SEC_WCHAR *pszDomainName,
                                      SEC_WCHAR *pszAccountName,
                                      SEC_WCHAR *pszOldPassword,
                                      SEC_WCHAR *pszNewPassword,
                                      bool bImpersonating,
                                      unsigned long dwReserved,
                                      PSecBufferDesc pOutput);

SecurityStatus QueryContextAttributesExW(PCtxtHandle phContext,
                                         unsigned long ulAttribute,
                                         void *pBuffer,
                                         unsigned long cbBuffer);

SecurityStatus QueryCredentialsAttributesExW(PCredHandle phCredential,
                                             unsigned long ulAttribute,
                                             void *pBuffer,
                                             unsigned long cBuffers);
