#include <limits.h>
#include <stdlib.h>
#include <tcl.h>
#include <util.h>

Tcl_Command handle_tcl_bcrypt_pbkdf = NULL;

enum TCL_BCRYPT_PBKDF_ARGS
{
	BPBKDF_CMD = 0,
	BPBKDF_PASS,
	BPBKDF_SALT,
	BPBKDF_KEYLEN,
	BPBKDF_ROUNDS,
	BPBKDF_NUM_ARGS
};

int tcl_bcrypt_pbkdf(ClientData clientData, Tcl_Interp *interp,
                     int objc, Tcl_Obj *const objv[])
{
	const char *pass;
	unsigned char *salt;
	unsigned int rounds;
	Tcl_WideInt rounds_raw;
	unsigned char *key;
	int pass_len;
	int salt_len;
	size_t key_len;
	Tcl_WideInt key_len_raw;

	if (objc != BPBKDF_NUM_ARGS)
	{
		Tcl_WrongNumArgs(interp, 1, objv, "pass salt keylen rounds");
		return TCL_ERROR;
	}

	pass = Tcl_GetStringFromObj(objv[BPBKDF_PASS], &pass_len);
	salt = Tcl_GetByteArrayFromObj(objv[BPBKDF_SALT], &salt_len);

	if (Tcl_GetWideIntFromObj(interp, objv[BPBKDF_KEYLEN], &key_len_raw) != TCL_OK
		|| key_len_raw < 1)
	{
		Tcl_Obj *tmp = Tcl_NewWideIntObj(LLONG_MAX);
		Tcl_SetObjResult(interp, Tcl_Format(interp,
		                                    "bad keylen: should be between 0 and %d",
		                                    1, &tmp));
		return TCL_ERROR;
	} else
	{
		key_len = key_len_raw;
	}

	if (Tcl_GetWideIntFromObj(interp, objv[BPBKDF_ROUNDS], &rounds_raw) != TCL_OK
		|| rounds_raw < 1 || rounds_raw > UINT_MAX)
	{
		Tcl_Obj *tmp = Tcl_NewWideIntObj(UINT_MAX);
		Tcl_SetObjResult(interp, Tcl_Format(interp,
		                                    "bad # rounds: should be between 0 and %d",
		                                    1, &tmp));
		return TCL_ERROR;
	} else
	{
		rounds = rounds_raw;
	}

	if ((key = malloc(key_len)) == NULL)
	{
		Tcl_SetObjResult(interp, Tcl_NewStringObj("couldn't allocate memory to hold the key", -1));
		return TCL_ERROR;
	}

	if (bcrypt_pbkdf(pass, pass_len, salt, salt_len, key, key_len, rounds) != 0)
	{
		Tcl_SetObjResult(interp, Tcl_NewStringObj("bcrypt_pbkdf() reports an error condition", -1));
		return TCL_ERROR;
	}

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(key, key_len));
	free(key);
	return TCL_OK;
}

int Bpbkdf_Init(Tcl_Interp *interp)
{
#ifdef USE_TCL_STUBS
	if (!Tcl_InitStubs(interp, "8", 0))
	{
		return TCL_ERROR;
	}
#endif

	if ((handle_tcl_bcrypt_pbkdf = Tcl_CreateObjCommand(
	         interp, "bcrypt_pbkdf", tcl_bcrypt_pbkdf, NULL, NULL)) == NULL)
	{
		return TCL_ERROR;
	}

	return Tcl_PkgProvide(interp, "bcrypt_pbkdf", "0.1");
}
