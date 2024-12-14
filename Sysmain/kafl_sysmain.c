#include <windows.h>
#include "nyx_api.h"
#include <stdio.h>
#include "sysmain_h.h"
#include <rpcdce.h>
#include <rpc.h>
#include <rpcndr.h>

#define PAYLOAD_SIZE 128 * 1024
#define PE_CODE_SECTION_NAME ".text"
#pragma comment(lib, "rpcrt4.lib")
#define RPC_SUCCESS(x) (x == RPC_S_OK)
#define PROC_FORMAT_STRING_SIZE   49

void trigger();
void submit_ip_ranges();
kAFL_payload* kafl_agent_init(void);

typedef long (*proc0)(handle_t, unsigned char*, long*);
proc0 func;
HMODULE adr;


/////////////////////////////////////////////sysmain_c.c

/* this ALWAYS GENERATED file contains the RPC client stubs */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 12:14:07 2038
 */
/* Compiler settings for sysmain.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#if defined(_M_AMD64)


#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning( disable: 4211 )  /* redefine extern to static */
#pragma warning( disable: 4232 )  /* dllimport identity*/
#pragma warning( disable: 4024 )  /* array to pointer mapping*/

#include <string.h>

#define TYPE_FORMAT_STRING_SIZE   19                                
#define PROC_FORMAT_STRING_SIZE   49                                
#define EXPR_FORMAT_STRING_SIZE   1                                 
#define TRANSMIT_AS_TABLE_SIZE    0            
#define WIRE_MARSHAL_TABLE_SIZE   0            

typedef struct _sysmain_MIDL_TYPE_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ TYPE_FORMAT_STRING_SIZE ];
    } sysmain_MIDL_TYPE_FORMAT_STRING;

typedef struct _sysmain_MIDL_PROC_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ PROC_FORMAT_STRING_SIZE ];
    } sysmain_MIDL_PROC_FORMAT_STRING;

typedef struct _sysmain_MIDL_EXPR_FORMAT_STRING
    {
    long          Pad;
    unsigned char  Format[ EXPR_FORMAT_STRING_SIZE ];
    } sysmain_MIDL_EXPR_FORMAT_STRING;


static const RPC_SYNTAX_IDENTIFIER  _RpcTransferSyntax_2_0 = 
{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}};

static const RPC_SYNTAX_IDENTIFIER  _NDR64_RpcTransferSyntax_1_0 = 
{{0x71710533,0xbeba,0x4937,{0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36}},{1,0}};

#if defined(_CONTROL_FLOW_GUARD_XFG)
#define XFG_TRAMPOLINES(ObjectType)\
NDR_SHAREABLE unsigned long ObjectType ## _UserSize_XFG(unsigned long * pFlags, unsigned long Offset, void * pObject)\
{\
return  ObjectType ## _UserSize(pFlags, Offset, (ObjectType *)pObject);\
}\
NDR_SHAREABLE unsigned char * ObjectType ## _UserMarshal_XFG(unsigned long * pFlags, unsigned char * pBuffer, void * pObject)\
{\
return ObjectType ## _UserMarshal(pFlags, pBuffer, (ObjectType *)pObject);\
}\
NDR_SHAREABLE unsigned char * ObjectType ## _UserUnmarshal_XFG(unsigned long * pFlags, unsigned char * pBuffer, void * pObject)\
{\
return ObjectType ## _UserUnmarshal(pFlags, pBuffer, (ObjectType *)pObject);\
}\
NDR_SHAREABLE void ObjectType ## _UserFree_XFG(unsigned long * pFlags, void * pObject)\
{\
ObjectType ## _UserFree(pFlags, (ObjectType *)pObject);\
}
#define XFG_TRAMPOLINES64(ObjectType)\
NDR_SHAREABLE unsigned long ObjectType ## _UserSize64_XFG(unsigned long * pFlags, unsigned long Offset, void * pObject)\
{\
return  ObjectType ## _UserSize64(pFlags, Offset, (ObjectType *)pObject);\
}\
NDR_SHAREABLE unsigned char * ObjectType ## _UserMarshal64_XFG(unsigned long * pFlags, unsigned char * pBuffer, void * pObject)\
{\
return ObjectType ## _UserMarshal64(pFlags, pBuffer, (ObjectType *)pObject);\
}\
NDR_SHAREABLE unsigned char * ObjectType ## _UserUnmarshal64_XFG(unsigned long * pFlags, unsigned char * pBuffer, void * pObject)\
{\
return ObjectType ## _UserUnmarshal64(pFlags, pBuffer, (ObjectType *)pObject);\
}\
NDR_SHAREABLE void ObjectType ## _UserFree64_XFG(unsigned long * pFlags, void * pObject)\
{\
ObjectType ## _UserFree64(pFlags, (ObjectType *)pObject);\
}
#define XFG_BIND_TRAMPOLINES(HandleType, ObjectType)\
static void* ObjectType ## _bind_XFG(HandleType pObject)\
{\
return ObjectType ## _bind((ObjectType) pObject);\
}\
static void ObjectType ## _unbind_XFG(HandleType pObject, handle_t ServerHandle)\
{\
ObjectType ## _unbind((ObjectType) pObject, ServerHandle);\
}
#define XFG_TRAMPOLINE_FPTR(Function) Function ## _XFG
#define XFG_TRAMPOLINE_FPTR_DEPENDENT_SYMBOL(Symbol) Symbol ## _XFG
#else
#define XFG_TRAMPOLINES(ObjectType)
#define XFG_TRAMPOLINES64(ObjectType)
#define XFG_BIND_TRAMPOLINES(HandleType, ObjectType)
#define XFG_TRAMPOLINE_FPTR(Function) Function
#define XFG_TRAMPOLINE_FPTR_DEPENDENT_SYMBOL(Symbol) Symbol
#endif



extern const sysmain_MIDL_TYPE_FORMAT_STRING sysmain__MIDL_TypeFormatString;
extern const sysmain_MIDL_PROC_FORMAT_STRING sysmain__MIDL_ProcFormatString;
extern const sysmain_MIDL_EXPR_FORMAT_STRING sysmain__MIDL_ExprFormatString;

#define GENERIC_BINDING_TABLE_SIZE   0            


/* Standard interface: DefaultIfName, ver. 1.0,
   GUID={0xb58aa02e,0x2884,0x4e97,{0x81,0x76,0x4e,0xe0,0x6d,0x79,0x41,0x84}} */

 extern const MIDL_STUBLESS_PROXY_INFO DefaultIfName_ProxyInfo;


static const RPC_CLIENT_INTERFACE DefaultIfName___RpcClientInterface =
    {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0xb58aa02e,0x2884,0x4e97,{0x81,0x76,0x4e,0xe0,0x6d,0x79,0x41,0x84}},{1,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    0,
    0,
    0,
    &DefaultIfName_ProxyInfo,
    0x02000000
    };
RPC_IF_HANDLE DefaultIfName_v1_0_c_ifspec = (RPC_IF_HANDLE)& DefaultIfName___RpcClientInterface;
#ifdef __cplusplus
namespace {
#endif

extern const MIDL_STUB_DESC DefaultIfName_StubDesc;
#ifdef __cplusplus
}
#endif

static RPC_BINDING_HANDLE DefaultIfName__MIDL_AutoBindHandle;


long Proc0_PfRpcServerExecuteCommand( 
    /* [in] */ handle_t IDL_handle,
    /* [size_is][out][in] */ unsigned char arg_1[  ],
    /* [out][in] */ long *arg_2)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall3(
                  ( PMIDL_STUBLESS_PROXY_INFO  )&DefaultIfName_ProxyInfo,
                  0,
                  0,
                  IDL_handle,
                  arg_1,
                  arg_2);
    return ( long  )_RetVal.Simple;
    
}


#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif

const sysmain_MIDL_PROC_FORMAT_STRING sysmain__MIDL_ProcFormatString =
    {
        0,
        {

	/* Procedure Proc0_PfRpcServerExecuteCommand */

			0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 14 */	NdrFcShort( 0x1c ),	/* 28 */
/* 16 */	NdrFcShort( 0x24 ),	/* 36 */
/* 18 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x3,		/* 3 */
/* 20 */	0xa,		/* 10 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 22 */	NdrFcShort( 0x1 ),	/* 1 */
/* 24 */	NdrFcShort( 0x1 ),	/* 1 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
/* 28 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter arg_1 */

/* 30 */	NdrFcShort( 0x1b ),	/* Flags:  must size, must free, in, out, */
/* 32 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 34 */	NdrFcShort( 0x2 ),	/* Type Offset=2 */

	/* Parameter arg_2 */

/* 36 */	NdrFcShort( 0x158 ),	/* Flags:  in, out, base type, simple ref, */
/* 38 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 40 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Return value */

/* 42 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 44 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 46 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
    };

const sysmain_MIDL_TYPE_FORMAT_STRING sysmain__MIDL_TypeFormatString =
    {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/*  4 */	NdrFcShort( 0x1 ),	/* 1 */
/*  6 */	0x28,		/* Corr desc:  parameter, FC_LONG */
			0x54,		/* FC_DEREFERENCE */
/*  8 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 10 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 12 */	0x2,		/* FC_CHAR */
			0x5b,		/* FC_END */
/* 14 */	
			0x11, 0x8,	/* FC_RP [simple_pointer] */
/* 16 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */

			0x0
        }
    };

static const unsigned short DefaultIfName_FormatStringOffsetTable[] =
    {
    0
    };



#endif /* defined(_M_AMD64)*/



/* this ALWAYS GENERATED file contains the RPC client stubs */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 12:14:07 2038
 */
/* Compiler settings for sysmain.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#if defined(_M_AMD64)




#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif


#include "ndr64types.h"
#include "pshpack8.h"
#ifdef __cplusplus
namespace {
#endif


typedef 
NDR64_FORMAT_CHAR
__midl_frag8_t;
const __midl_frag8_t __midl_frag8;

typedef 
struct _NDR64_POINTER_FORMAT
__midl_frag6_t;
extern const __midl_frag6_t __midl_frag6;

typedef 
NDR64_FORMAT_CHAR
__midl_frag5_t;
extern const __midl_frag5_t __midl_frag5;

typedef 
struct 
{
    NDR64_FORMAT_UINT32 frag1;
    struct _NDR64_EXPR_OPERATOR frag2;
    struct _NDR64_EXPR_VAR frag3;
}
__midl_frag4_t;
extern const __midl_frag4_t __midl_frag4;

typedef 
struct 
{
    struct _NDR64_CONF_ARRAY_HEADER_FORMAT frag1;
    struct _NDR64_ARRAY_ELEMENT_INFO frag2;
}
__midl_frag3_t;
extern const __midl_frag3_t __midl_frag3;

typedef 
struct 
{
    struct _NDR64_PROC_FORMAT frag1;
    struct _NDR64_BIND_AND_NOTIFY_EXTENSION frag2;
    struct _NDR64_PARAM_FORMAT frag3;
    struct _NDR64_PARAM_FORMAT frag4;
    struct _NDR64_PARAM_FORMAT frag5;
}
__midl_frag2_t;
extern const __midl_frag2_t __midl_frag2;

typedef 
NDR64_FORMAT_UINT32
__midl_frag1_t;
extern const __midl_frag1_t __midl_frag1;

const __midl_frag8_t __midl_frag8 =
0x5    /* FC64_INT32 */;

const __midl_frag6_t __midl_frag6 =
{ 
/* *long */
    0x20,    /* FC64_RP */
    (NDR64_UINT8) 8 /* 0x8 */,
    (NDR64_UINT16) 0 /* 0x0 */,
    &__midl_frag8
};

const __midl_frag5_t __midl_frag5 =
0x10    /* FC64_CHAR */;

const __midl_frag4_t __midl_frag4 =
{ 
/*  */
    (NDR64_UINT32) 0 /* 0x0 */,
    { 
    /* struct _NDR64_EXPR_OPERATOR */
        0x4,    /* FC_EXPR_OPER */
        0x5,    /* OP_UNARY_INDIRECTION */
        0x5,    /* FC64_INT32 */
        (NDR64_UINT8) 0 /* 0x0 */
    },
    { 
    /* struct _NDR64_EXPR_VAR */
        0x3,    /* FC_EXPR_VAR */
        0x7,    /* FC64_INT64 */
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT32) 16 /* 0x10 */  /* Offset */
    }
};

const __midl_frag3_t __midl_frag3 =
{ 
/*  */
    { 
    /* struct _NDR64_CONF_ARRAY_HEADER_FORMAT */
        0x41,    /* FC64_CONF_ARRAY */
        (NDR64_UINT8) 0 /* 0x0 */,
        { 
        /* struct _NDR64_CONF_ARRAY_HEADER_FORMAT */
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        },
        (NDR64_UINT8) 0 /* 0x0 */,
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag4
    },
    { 
    /* struct _NDR64_ARRAY_ELEMENT_INFO */
        (NDR64_UINT32) 1 /* 0x1 */,
        &__midl_frag5
    }
};

const __midl_frag2_t __midl_frag2 =
{ 
/* Proc0_PfRpcServerExecuteCommand */
    { 
    /* Proc0_PfRpcServerExecuteCommand */      /* procedure Proc0_PfRpcServerExecuteCommand */
        (NDR64_UINT32) 23986240 /* 0x16e0040 */,    /* explicit handle */ /* IsIntrepreted, ServerMustSize, ClientMustSize, HasReturn, ServerCorrelation, ClientCorrelation, HasExtensions */
        (NDR64_UINT32) 32 /* 0x20 */ ,  /* Stack size */
        (NDR64_UINT32) 32 /* 0x20 */,
        (NDR64_UINT32) 40 /* 0x28 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 0 /* 0x0 */,
        (NDR64_UINT16) 3 /* 0x3 */,
        (NDR64_UINT16) 8 /* 0x8 */
    },
    { 
    /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
        { 
        /* struct _NDR64_BIND_AND_NOTIFY_EXTENSION */
            0x72,    /* FC64_BIND_PRIMITIVE */
            (NDR64_UINT8) 0 /* 0x0 */,
            0 /* 0x0 */,   /* Stack offset */
            (NDR64_UINT8) 0 /* 0x0 */,
            (NDR64_UINT8) 0 /* 0x0 */
        },
        (NDR64_UINT16) 0 /* 0x0 */      /* Notify index */
    },
    { 
    /* arg_1 */      /* parameter arg_1 */
        &__midl_frag3,
        { 
        /* arg_1 */
            1,
            1,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* MustSize, MustFree, [in], [out] */
        (NDR64_UINT16) 0 /* 0x0 */,
        8 /* 0x8 */,   /* Stack offset */
    },
    { 
    /* arg_2 */      /* parameter arg_2 */
        &__midl_frag8,
        { 
        /* arg_2 */
            0,
            0,
            0,
            1,
            1,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [in], [out], Basetype, SimpleRef */
        (NDR64_UINT16) 0 /* 0x0 */,
        16 /* 0x10 */,   /* Stack offset */
    },
    { 
    /* long */      /* parameter long */
        &__midl_frag8,
        { 
        /* long */
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            (NDR64_UINT16) 0 /* 0x0 */,
            0
        },    /* [out], IsReturn, Basetype, ByValue */
        (NDR64_UINT16) 0 /* 0x0 */,
        24 /* 0x18 */,   /* Stack offset */
    }
};

const __midl_frag1_t __midl_frag1 =
(NDR64_UINT32) 0 /* 0x0 */;
#ifdef __cplusplus
}
#endif


#include "poppack.h"


static const FormatInfoRef DefaultIfName_Ndr64ProcTable[] =
    {
    &__midl_frag2
    };


#ifdef __cplusplus
namespace {
#endif
const MIDL_STUB_DESC DefaultIfName_StubDesc = 
    {
    (void *)& DefaultIfName___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &DefaultIfName__MIDL_AutoBindHandle,
    0,
    0,
    0,
    0,
    sysmain__MIDL_TypeFormatString.Format,
    1, /* -error bounds_check flag */
    0x60001, /* Ndr library version */
    0,
    0x8010274, /* MIDL Version 8.1.628 */
    0,
    0,
    0,  /* notify & notify_flag routine table */
    0x2000001, /* MIDL flag */
    0, /* cs routines */
    (void *)& DefaultIfName_ProxyInfo,   /* proxy/server info */
    0
    };
#ifdef __cplusplus
}
#endif

static const MIDL_SYNTAX_INFO DefaultIfName_SyntaxInfo [  2 ] = 
    {
    {
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    sysmain__MIDL_ProcFormatString.Format,
    DefaultIfName_FormatStringOffsetTable,
    sysmain__MIDL_TypeFormatString.Format,
    0,
    0,
    0
    }
    ,{
    {{0x71710533,0xbeba,0x4937,{0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36}},{1,0}},
    0,
    0 ,
    (unsigned short *) DefaultIfName_Ndr64ProcTable,
    0,
    0,
    0,
    0
    }
    };

const MIDL_STUBLESS_PROXY_INFO DefaultIfName_ProxyInfo =
    {
    &DefaultIfName_StubDesc,
    sysmain__MIDL_ProcFormatString.Format,
    DefaultIfName_FormatStringOffsetTable,
    (RPC_SYNTAX_IDENTIFIER*)&_RpcTransferSyntax_2_0,
    2,
    (MIDL_SYNTAX_INFO*)DefaultIfName_SyntaxInfo
    
    };

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif


#endif /* defined(_M_AMD64)*/
/////////////////////////////////////////////sysmain_c.c

/////////////////////////////////////////////sysmain_h.h


/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 12:14:07 2038
 */
/* Compiler settings for sysmain.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif


#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __sysmain_h_h__
#define __sysmain_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __DefaultIfName_INTERFACE_DEFINED__
#define __DefaultIfName_INTERFACE_DEFINED__

/* interface DefaultIfName */
/* [version][uuid] */ 

#endif /* __DefaultIfName_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif

/////////////////////////////////////////////sysmain_h.h



static inline void panic(void) {
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
    while (1) {}; /* halt */
}

RPC_BINDING_HANDLE GetBindingHandle(void)
{
    RPC_STATUS          status = RPC_S_OK;
    RPC_WSTR            stringBinding = NULL;
    RPC_BINDING_HANDLE  hBinding = NULL;

    status = RpcStringBindingComposeW(
        NULL,
        (RPC_WSTR)L"ncalrpc",
        NULL,
        NULL,
        NULL,
        &stringBinding
    );
    if (!RPC_SUCCESS(status)) {
        printf("[-] RpcStringBindingCompose Error : 0x%08X\n", status);
        goto out;
    }
    status = RpcBindingFromStringBindingW(
        stringBinding,
        &hBinding
    );
    if (!RPC_SUCCESS(status)) {
        printf("[-] RpcBindingFromStringBinding Error : 0x%08X\n", status);
        goto out;
    }

out:
    if (stringBinding)
        RpcStringFree(&stringBinding);

    return hBinding;
}


BOOL EnablePrivilege(LPCWSTR privilege) {
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
    CloseHandle(hToken);

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        return FALSE;

    return TRUE;
}
void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
    return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
    free(p);
}

/* forward exceptions to panic handler */
LONG CALLBACK exc_handle(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
    DWORD exception_code = ExceptionInfo->ExceptionRecord->ExceptionCode;
    //hprintf("Exception caught: %lx\n", exception_code);

    if((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
       (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
       //(exception_code == STATUS_HEAP_CORRUPTION) ||
       (exception_code == 0xc0000374) ||
       (exception_code == EXCEPTION_STACK_OVERFLOW) ||
       (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
       (exception_code == STATUS_FATAL_APP_EXIT))
    {
        panic();
    }

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        trigger();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void trigger(){
    hprintf("[+] DLL attached, starting initialization...\n");

    hprintf("[+] Creating snapshot...\n");
    kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);

    if (AddVectoredExceptionHandler(1, exc_handle) == 0)
    {
        hprintf("[-] WARNING: Cannot add veh handler %u\n", (UINT32)GetLastError());
    }

    kAFL_payload* payload_buffer = kafl_agent_init();

    kAFL_ranges* range_buffer = (kAFL_ranges*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if (range_buffer == NULL) {
        hprintf("[!] Failed to allocate range buffer\n");
        return FALSE;
    }
    memset(range_buffer, 0xff, 0x1000);

    hprintf("[+] range buffer %lx...\n", (UINT64)range_buffer);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (UINT64)range_buffer);
    
    for(int i = 0; i < 4; i++){
        hprintf("[+] Range %d enabled: %x\t(%p-%p)\n", i, (uint8_t)range_buffer->enabled[i], range_buffer->ip[i], range_buffer->size[i]);
        if (range_buffer->ip[i] != 0)
        {
            if (!VirtualLock((LPVOID)range_buffer->ip[i], range_buffer->size[i]))
            {
                hprintf("[-] WARNING: VirtualLock failed on range %d (%u)\n", (uint8_t)range_buffer->enabled[i], (UINT32)GetLastError());
                kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
            }
            else
            {
                hprintf("[+] Range %d locked\n", (uint8_t)range_buffer->enabled[i]);
            }
        }
    }
    submit_ip_ranges();

    RPC_BINDING_HANDLE      hBinding = NULL;
    hBinding = GetBindingHandle();
    if (!hBinding) {
        hprintf("[-] Acquired RPC Binding Handle Error : %d\n", GetLastError());
        return 0;
    }
    hprintf("[+] Acquired RPC Binding Handle : 0x%llx\n", (ULONG64)hBinding);

    RPC_STATUS status = RPC_S_OK;
    DWORD* arg1 = (DWORD*)malloc(0x200);
    long* arg2 = (long*)malloc(0x20);
    
    memset(arg1, 0, 0x200);
    //*(DWORD*)(arg1) = 0x1;
    //*(DWORD*)(arg1 + 8) = 0xFFFFFFFF;
    //*arg2 = 0x100;
    *arg2 = 0x24;
    // start
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    //

    //hprintf("value ... 0x%lx\n", *(DWORD*)payload_buffer->data);
	//*(DWORD*)(arg1) = *(DWORD*)payload_buffer->data
    //*(DWORD*)(arg1+1) = *((DWORD*)(payload_buffer->data)+1);
    //*(DWORD*)(arg1+8) = *((DWORD*)(payload_buffer->data)+2);
    DWORD ssize = payload_buffer->size;
    Proc0_PfRpcServerExecuteCommand(hBinding, (unsigned char *)payload_buffer->data, &ssize);

    // revive
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    //
    VirtualFree(range_buffer, 0, MEM_RELEASE);
}

void submit_ip_ranges() {
    if (!EnablePrivilege(SE_LOCK_MEMORY_NAME)) {
        hprintf("Failed to enable SE_LOCK_MEMORY_NAME privilege.\n");
    }
    SIZE_T minWorkingSetSize = 0;
    SIZE_T maxWorkingSetSize = 0;
    if (!GetProcessWorkingSetSize(GetCurrentProcess(), &minWorkingSetSize, &maxWorkingSetSize)) {
        hprintf("GetProcessWorkingSetSize failed. Error: %lu\n", GetLastError());
    }
    hprintf("[*] Before : minWorkingSetSize = %lu\n", minWorkingSetSize);
    hprintf("[*] Before : maxWorkingSetSize = %lu\n", maxWorkingSetSize);
    if (!SetProcessWorkingSetSize(GetCurrentProcess(), minWorkingSetSize*30, maxWorkingSetSize * 30)) {
        hprintf("SetProcessWorkingSetSize failed. Error: %lu\n", GetLastError());
    }
    if (!GetProcessWorkingSetSize(GetCurrentProcess(), &minWorkingSetSize, &maxWorkingSetSize)) {
        hprintf("GetProcessWorkingSetSize failed. Error: %lu\n", GetLastError());
    }
    hprintf("[*] After : minWorkingSetSize = %lu\n", minWorkingSetSize);
    hprintf("[*] After : maxWorkingSetSize = %lu\n", maxWorkingSetSize);
    // Get the module handle for the current process.
    //HMODULE hModule = GetModuleHandle(NULL);
    HMODULE hModule1 = GetModuleHandleW(L"sysmain.dll");
    if (hModule1 == NULL) {
        habort("Cannot get module handle\n");
    }
    hprintf("[*] sysmain DLL whole addr : %p \n", (uint64_t)hModule1);
    
    PIMAGE_DOS_HEADER pDOSHeader1 = (PIMAGE_DOS_HEADER)hModule1;
    PIMAGE_NT_HEADERS pNTHeaders1 = (PIMAGE_NT_HEADERS)((BYTE*)hModule1 + pDOSHeader1->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader1 = IMAGE_FIRST_SECTION(pNTHeaders1);
    
    for (int i = 0; i < pNTHeaders1->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSectionHeader1->Name, ".text", 5) == 0) {
            
            LPVOID codeStart1 = (LPVOID)((BYTE*)hModule1 + pSectionHeader1->VirtualAddress);
            LPVOID codeEnd1 = codeStart1 + pSectionHeader1->Misc.VirtualSize;
            
            hprintf("[*] DLL text section start addr : %p \n", codeStart1);
            hprintf("[*] DLL text section end addr : %p \n", codeEnd1);
            hprintf("[*] DLL text section size is... %lx \n", pSectionHeader1->Misc.VirtualSize);

            uint64_t buffer[3] = { 0 };
            buffer[0] = codeStart1; // low range
            buffer[1] = codeEnd1; // high range
            buffer[2] = 0; // IP filter index [0-3]
            kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uint64_t)buffer);

            if (!VirtualLock(codeStart1, pSectionHeader1->Misc.VirtualSize)) {
                hprintf("Failed to lock .text section of target Module. Error: %d\n", GetLastError());
                break;
            }
            hprintf("Successfully locked .text section of sysmain.dll\n");
            
            break;
        }
        pSectionHeader1++;
    }
    HMODULE hModule2 = GetModuleHandleW(L"kafl_sysmain.dll");
    if (hModule2 == NULL) {
        habort("Cannot get module handle\n");
    }
    hprintf("[*] kafl_sysmain DLL whole addr : %p \n", (uint64_t)hModule2);
    
    PIMAGE_DOS_HEADER pDOSHeader2 = (PIMAGE_DOS_HEADER)hModule2;
    PIMAGE_NT_HEADERS pNTHeaders2 = (PIMAGE_NT_HEADERS)((BYTE*)hModule2 + pDOSHeader2->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader2 = IMAGE_FIRST_SECTION(pNTHeaders2);
    
    for (int i = 0; i < pNTHeaders2->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSectionHeader2->Name, ".text", 5) == 0) {
            
            LPVOID codeStart2 = (LPVOID)((BYTE*)hModule2 + pSectionHeader2->VirtualAddress);
            LPVOID codeEnd2 = codeStart2 + pSectionHeader2->Misc.VirtualSize;
            
            hprintf("[*] DLL text section start addr : %p \n", codeStart2);
            hprintf("[*] DLL text section end addr : %p \n", codeEnd2);
            hprintf("[*] DLL text section size is... %lx \n", pSectionHeader2->Misc.VirtualSize);

            if (!VirtualLock(codeStart2, pSectionHeader2->Misc.VirtualSize)) {
                hprintf("Failed to lock .text section of target Module. Error: %d\n", GetLastError());
                return;
            }
            hprintf("Successfully locked .text section of kafl_sysmain.dll\n");
            
            return;
        }
        pSectionHeader2++;
    }
    habort("Couldn't locate .text section in PE image\n");
}

kAFL_payload* kafl_agent_init(void) {
    // initial fuzzer handshake
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // submit mode
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    // get host config
    host_config_t host_config = { 0 };
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    hprintf("[host_config] bitmap sizes = <0x%x,0x%x>\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
    hprintf("[host_config] payload size = %dKB\n", host_config.payload_buffer_size / 1024);
    hprintf("[host_config] worker id = %02u\n", host_config.worker_id);

    // allocate buffer
    hprintf("[+] Allocating buffer for kAFL_payload struct\n");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, host_config.payload_buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // ensure really present in resident pages
    if (!VirtualLock(payload_buffer, host_config.payload_buffer_size)) {
        habort("[+] WARNING: Virtuallock failed to lock payload buffer\n");
    }

    // submit buffer
    hprintf("[+] Submitting buffer address to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    // filters
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // submit agent config
    agent_config_t agent_config = {
        .agent_magic = NYX_AGENT_MAGIC,
        .agent_version = NYX_AGENT_VERSION,
    };
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

    return payload_buffer;
}