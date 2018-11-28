import analyzer

def c_hit_if_null(hit):
    return
def c_buffer(hit):
    return
def c_strncat(hit):
    return
def c_printf(hit):
    return
def c_sprintf(hit):
    return
def c_scanf(hit):
    return
def c_multi_byte_to_wide_char(hit):
    return
def c_static_array(hit):
    return
def normal(hit):
    return
def ms_banned(hit):
    #Output to outfile/stderr:
    message = "This function is on the Microsoft 'banned list' due to known security flaws. See https://msdn.microsoft.com/en-us/library/bb288454.aspx for a suggested replacement"
    return

c_ruleset = {
    "strcpy":
    (ms_banned, None, None, None, None, None),
    "strcpyA|strcpyW|StrCpy|StrCpyA|lstrcpyA|lstrcpyW|_tccpy|_mbccpy|_ftcscpy|_mbsncpy|StrCpyN|StrCpyNA|StrCpyNW|StrNCpy|strcpynA|StrNCpyA|StrNCpyW|lstrcpynA|lstrcpynW":
    (ms_banned, None, None, None, None, None),
    "lstrcpy|wcscpy|_tcscpy|_mbscpy":
    (ms_banned, None, None, None, None, None),
    "strcat":
    (ms_banned, None, None, None, None, None),
    "lstrcat|wcscat|_tcscat|_mbscat":
    (ms_banned, None, None, None, None, None),
    "StrCat|StrCatA|StrcatW|lstrcatA|lstrcatW|strCatBuff|StrCatBuffA|StrCatBuffW|StrCatChainW|_tccat|_mbccat|_ftcsat|StrCatN|StrCatNA|StrCatNW|StrNCat|StrNCatA|StrNCatW|lstrncat|lstrcatnA|lstrcatnW":
    (ms_banned, None, None, None, None, None),
    "strncpy":
    (ms_banned, None, None, None, None, None),
    "lstrcpyn|wcsncpy|_tcsncpy|_mbsnbcpy":
    (ms_banned, None, None, None, None, None),
    "strncat":
    (ms_banned, None, None, None, None, None),
    "lstrcatn|wcsncat|_tcsncat|_mbsnbcat":
    (ms_banned, None, None, None, None, None),
}