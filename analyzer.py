import logging
import argparse
import getopt
import sys
import re

infiles = None
outfile = None

PAGE_SIZE = 4096 # changes depending on architecture
# TODO add page size flag

#look for variable declaration: 'type name;'
declaration = re.compile(r'\b(?P<type>(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|size_t\s*|'
    r'volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|'
    r'complex\s*)+(?:\*?\*?\s*))(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[(?P<size>\w+)\])?\s*;') 
#look for variable initialization: 'type name = value'
initialization = re.compile(r'\b(?P<type>(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|size_t\s*|'
    r'volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|complex\s*)'
    r'+(?:\*?\*?\s*))(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[(?P<size>\w+)\])?\s*=\s*(?P<value>\w*)') 
#TODO: declaration/initialization do not catch multiple variables on one line
#eg: int i, j;
#TODO: does not catch some pointer declarations: void* c -> good, void *c -> not good

#look for variable reassignment: (name [+-/*]= value)
reassignment = re.compile(r'\b^(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[(?P<subscript>\w+)\])?\s*[+\-/\*]?=\s*(?P<value>\w*)')
#TODO: does not catch: x = x+1 properly

#look for function call: [type var =] funct(args)
function_match = re.compile(r'(?P<type>(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|size_t\s*|volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|complex\s*)*(?:\*?\*?\s*))(?P<var>([\w]*?))\s*(?:\[(\w+)\])?\s*([=]?|\s*?)\s*(?P<funct>([\w]*))\s*\((?P<args>(.*))\)')

var_dict = {} #entries look like: {name: (type, value, line of first appearance, isModified, line_modified (if modified) size (if buffer/array))}
function_dict = {} #entries look like {function: param_list, user_defined?}

pairs = [('mmap','munmap'),('malloc','free'), ('calloc','free'), ('realloc', 'free')] 

c_keywords = ['auto', 'const', 'double', 'float', 'int', 'short', 
                'struct', 'unsigned', 'break', 'continue', 'else', 
                'for', 'long', 'signed', 'switch', 'void', 'case',
                'default', 'enum', 'goto', 'register', 'sizeof', 
                'typedef', 'volatile', 'char', 'do', 'extern', 
                'return', 'static', 'union'] # specifically keeping 'if' and 'while' 
#functions banned by microsoft
ms_banned = ["strcpy", "strcpyA", "strcpyW", "StrCpy", "StrCpyA", "lstrcpyA", 
                "lstrcpyW", "_tccpy", "_mbccpy", "_ftcscpy", "_mbsncpy", "StrCpyN", 
                "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", 
                "lstrcpynA", "lstrcpynW","lstrcpy", "wcscpy", "_tcscpy", "_mbscpy", 
                "strcat", "lstrcat", "wcscat", "_tcscat", "_mbscat", "StrCat", "StrCatA",
                "StrcatW", "lstrcatA", "lstrcatW", "strCatBuff", "StrCatBuffA", "StrCatBuffW", 
                "StrCatChainW", "_tccat", "_mbccat", "_ftcsat", "StrCatN", "StrCatNA", 
                "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", "lstrncat", "lstrcatnA", 
                "lstrcatnW", "strncpy", "lstrcpyn", "wcsncpy", "_tcsncpy", "_mbsnbcpy",
                "strncat","lstrcatn", "wcsncat", "_tcsncat", "_mbsnbcat"]
#functions checked by clang analyzer: https://clang-analyzer.llvm.org/available_checks.html
clang_banned = {"bcmp": ("memcmp", "is depreciated."), 
                    "bcopy": ("memcpy or memmove", "is depreciated."), 
                    "bzero": ("memset", "is depreciated."), 
                    "getpw": ("getpwid", "can cause a buffer overflow."), 
                    "gets": ("fgets", "can cause a buffer overflow."), 
                    "mktemp": ("mkstemp or mkdtemp", "is insecure due to a race condition")}

print_functions = ['printf', 'printf', 'sprintf', 'snprintf', 'vfprintf',
                        'vprintf', 'vsprintf', 'vsnprintf']

#TODO: check functions that require check of return value
ret_check = ['setuid', 'setgid', 'seteuid', 'setegid', 'setreuid', 'setregid']

def parse_args():
    parser = argparse.ArgumentParser(description='Process c source code.')
    parser.add_argument('infiles', nargs='+', type=argparse.FileType('r'), default=sys.stdin)
    parser.add_argument('-o', dest='outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout)
    args = parser.parse_args()
    return args.infiles, args.outfile

def single_comment_remover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " 
        else:
            return s
    pattern = re.compile(r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"', re.DOTALL | re.MULTILINE)
    return re.sub(pattern, replacer, text)

#returns a list of cleaned tuples
def multi_comment_remover(code_tuple):
    clean_code = []
    in_comment = False
    for line in code_tuple:
        line  = [single_comment_remover(line[0]), line[1]] # string, line#
        #if in between comment
        if '*/' not in line[0] and in_comment:
            line = [' \n', line[1]]
        #if code before comment
        if '/*' in line[0]:
            in_comment = True
            line = [line[0][:line[0].find('/*',0)], line[1]]
        #if code after comment
        if '*/' in line[0] and in_comment:
            line = [line[0][line[0].find('*/',0)+2:], line[1]]
            in_comment = False

        #remove leading whitespace from line
        for char in line[0]:
            if char in '\t\n\f\r\v ':
                line[0] = line[0][1:]
            else:
                break
                
        clean_code.append(line)
    return clean_code

def find_vars(line, linenum):
    d = declaration.match(line)
    m = initialization.match(line)
    r = reassignment.match(line)
    
    if d:
        size = d.group('size')
        if uninit_size(line, linenum, size):
            size = var_dict[size][-1]

        var_dict[d.group('name')] = (d.group('type').strip(), None, linenum, False, None, size)
    
    elif m:
        size = m.group('size')
        if uninit_size(line, linenum, size):
            size = var_dict[size][-1]
        value = m.group('value')
        if value in var_dict:
            value = var_dict[value][1]
        var_dict[m.group('name')] = (m.group('type').strip(), value, linenum, False, None, size)
    
    elif r and r.group('name') in var_dict:
        name = r.group('name')
        var_type = var_dict[name][0]
        first_line = var_dict[name][2]
        var_size = var_dict[name][-1]
        value = r.group('value')
        if value in var_dict:
            value = var_dict[value][1]
        var_dict[name] = (var_type, value, first_line, True, linenum, var_size)

def find_functions(line, linenum):
    f = function_match.match(line)
    if f:
        arguments = f.group('args').split(',')
        argts = [item.strip() for item in arguments]
        function = f.group('funct')
        
        if argts == "":
            argts = None
        
        user_defined = False
        if f.group('type') and '=' not in line:
            user_defined = True

        #temporarily disabling keywords check
        #if function not in c_keywords:     #create a key entry for the function function_line#_char#
        key = function+"_"+str(linenum)+"_"+str(line.find(function))
        function_dict[key] = (argts, user_defined)

        #check for banned/problematic functions
        if function in ms_banned:
            outfile.writelines("Line " + str(linenum) + ": " + function + "\n")
            outfile.writelines("WARNING: This function is on the Microsoft 'banned list' due to known "
                            "security flaws. See https://msdn.microsoft.com/en-us/library/bb288454.aspx"
                            "for a suggested replacement.\n")
        elif function in clang_banned:
            outfile.writelines("Line " + str(linenum) + ": " + function + "\n")
            outfile.writelines("WARNING: This function " + clang_banned[function][1] + " Please use " + clang_banned[function][0] + " instead.\n")
        elif function in ret_check and '=' not in line: # should assign return value to variable, or check == condition
            outfile.writelines("Line " + str(linenum) + ": " + function + "\n")
            outfile.writelines("WARNING: Code does not check the return value of '" + function + "'. This could create vulnerabilities. See CWE 252 for more detail.\n")
        #specific checks for mmap
        elif function == 'mmap':
            mmap_check(line, linenum, key, f.group('var'))
        elif function in print_functions:
            print_check(line, linenum, key)
        

def uninit_size(line, linenum, var):
    if var in var_dict:
        if var_dict[var][1] == '0':
            outfile.writelines("Line " + str(linenum) + ": " + line)
            outfile.writelines("WARNING: Using variable with value 0 '" + var + "' to initialize array\n")
        elif var_dict[var][1] == None:
            outfile.writelines("Line " + str(linenum) + ": " + line)
            outfile.writelines("WARNING: Using uninitialized value '" + var + "' to initialize/subscript array\n")
        return True # variable in var_dict
    else:
        if var == '0':
            outfile.writelines("Line " + str(linenum) + ": " + line)
            outfile.writelines("WARNING: Initializing array with size 0\n")
    return False

def mmap_check(line, linenum, key, var):
    params = function_dict[key][0]
    offset = int(params[-1])
    buffersize = None
    if var in var_dict and var_dict[var][-1]:
        buffersize = int(var_dict[var][-1])

    # check for secure flags, correct bounds on region
    if 'PROT_WRITE' in line and 'PROT_EXEC' in line:
        outfile.writelines("Line " + str(linenum) + ": " + line)
        outfile.writelines("WARNING: Both PROT_WRITE and PROT_EXEC flags are set."
            " This can lead to exploitable memory regions,"
            " which could be overwritten with malicious code\n")
    if 'MAP_FIXED' in line:
        #TODO: search function dict for previous call clearing same mapping
        outfile.writelines("Line " + str(linenum) + ": " + line)
        outfile.writelines("WARNING: Using MAP_FIXED is only safe when the address range specified"
            "by addr " + params[0] + " and length " + params[1] + 
            " was previously reserved using another mapping. Also ensure that " + 
            params[0] + " is divisible by " + str(PAGE_SIZE) + "\n")
    if offset < 0:
        outfile.writelines("Line " + str(linenum) + ": " + line)
        outfile.writelines("WARNING: Offset parameter of mmap should be a positive value.\n")
    if buffersize and offset > buffersize:
        outfile.writelines("Line " + str(linenum) + ": " + line)
        outfile.writelines("WARNING: Offset parameter of mmap should be less than the size of the buffer.\n")
    return

def print_check(line, linenum, key):
    params = function_dict[key][0]
    for param in params:
        if param in var_dict:
            param = var_dict[param][1]
        if 'argv' in param:
            outfile.writelines("Line " + str(linenum) + ": " + line)
            outfile.writelines("WARNING: Passing user input to this function makes code "
                "susceptible to a format string attack (CWE 134).\n")

def analyze(clean_code):
    for line in clean_code:
        find_vars(line[0], line[1])
        find_functions(line[0], line[1])
    return clean_code

# returns the line number of the mmap and munmap, as well as the variable that
# is associated
#def word_scope(function_name, exit_name, start_line, end_line, code, funct_dict):
def word_scope(dictionary, code, funct_dict):
    for keys in dictionary:
        variable = keys
        start_name = dictionary[keys][0]
        exit_name = dictionary[keys][1]
        start_line = dictionary[keys][2]
        end_line = dictionary[keys][3]

        stack = []
        try:
            segment = code[int(start_line):int(end_line)-1] #code block except for the close/munmap call
            close_re = r".+\W" + exit_name + r"\W.+"
            check_ifStr = 'if'+'_'+str(end_line)+'_'+str(0)
            check_whileStr = 'while'+'_'+str(end_line)+'_'+str(0)
            try:
                if funct_dict[check_ifStr]:
                    last_str = funct_dict[check_ifStr]
                elif funct_dict[check_whileStr]:
                    last_str = funct_dict[check_whileStr]
            except KeyError:
                last_str = code[int(end_line)-1]
            
            open_brackets = "{("
            close_brackets = "})"
            segment.append((str(last_str),end_line))
            
            for tup in segment:
                for letter in tup[0]:
                    if letter in open_brackets:
                        stack.append(letter)
                    if letter in close_brackets:
                        if letter == "}" and stack[-1] == "{":
                            stack.pop()
                        if letter == ")" and stack[-1] == "(":
                            stack.pop()

            if re.match(close_re, tup[0]) != None:  # found an instance of munmap 
                #tup[0] is the line with the closing operator 
                if (len(stack) == 0):
                    continue
            else:
                logging.warning('Parentheses may not match for '+ start_name+"/"+exit_name)
        except ValueError: #open but not closed
            logging.warning('Memory allocated for variable %s on line %s but no call to free memory found.', variable, start_line)
            continue

def start_end(var_dict, function_dict, start_word, end_word):
    opened = {} #(start,end, var)
    for keys in function_dict:
        if start_word in keys:
            foo = keys.split('_')
            for variable, attributes in var_dict.items():
                if str(attributes[2]) == (foo[1]):
                    opened[variable] = (foo[0],foo[1])
    closed = {}
    for keys in function_dict:
        if end_word in keys:
            bar = keys.split('_')
            for variable, attributes in var_dict.items():
                for items in opened:
                    if str(variable) == items and function_dict[keys][0][0] == str(variable):
                        closed[str(variable)] = (opened[items][0],bar[0],opened[items][1], bar[1])
        else:
            continue
    #returns list of variables and shit that are opened and closed
    '''
    print(opened)# in format {var,  open_function, line#}
    print(closed)# in format {var:closed_function, line#opened, line#closed}
    '''
    for keys in opened:
        if keys not in closed.keys():
            closed[keys] = (opened[keys][0],'', opened[keys][1],'')
    
    #print(closed)# in format {var:open_function, closed_function, line#opened, line#closed}
    return closed

def check_user_defined():
    unused = []
    for function in function_dict:
        f_name = function.split('_')[0] + '()'
        if function_dict[function][1] and f_name != 'main()':
            unused.append(f_name)
        elif f_name in unused:
            unused.remove(f_name)
    outfile.writelines("WARNING: The following function(s): ")
    outfile.writelines(unused)
    outfile.writelines("\nare defined but never used. Consider removing from code.\n")


if __name__ == "__main__":
    infiles, outfile = parse_args()

    logging.basicConfig(level=logging.WARNING)
    for infile in infiles:
        logging.warning("started analysis of '" + infile.name + "'")
        code_tuple = [] 
        code = infile.readlines()
        length = 0
        for line in code:
            length += 1
            code_tuple.append([line,length])
            clean_code = multi_comment_remover(code_tuple) #all comments now ignored
        analyze(clean_code)
        check_user_defined()
    
        for x in pairs:
            mapping = start_end(var_dict, function_dict,x[0], x[1])
            word_scope(mapping,clean_code, function_dict) # for text1
        var_dict = {}
        function_dict = {}
        logging.warning("done with analysis of '" + infile.name + "'")
