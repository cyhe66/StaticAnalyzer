import logging
import argparse
import getopt
import sys
import re

infiles = None
outfile = None

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

#look for variable reassignment: (name [+-/*]= value)
reassignment = re.compile(r'\b^(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[(?P<subscript>\w+)\])?\s*[+\-/\*]?=\s*(?P<value>\w*)')

#look for function call: var = function(params)
function_match = re.compile(r'(?P<type>[\w|*]*?)\s*(?P<var>([\w]*?))\s*([=]?|\s*?)\s*(?P<funct>([\w]*))\s*\((?P<args>(.*))\)')

var_dict = {} #entries look like: {name: (type, value, line of first appearance, isModified, line_modified (if modified) size (if buffer/array))}
function_dict = {} #entries look like {function: (# of params, param_list)}

c_keywords = ['auto', 'const', 'double', 'float', 'int', 'short', 
                'struct', 'unsigned', 'break', 'continue', 'else', 
                'for', 'long', 'signed', 'switch', 'void', 'case',
                'default', 'enum', 'goto', 'register', 'sizeof', 
                'typedef', 'volatile', 'char', 'do', 'extern', 'if', 
                'return', 'static', 'union', 'while']
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

#TODO: check functions that require check of return value
ret_check = ['setuid', 'setgid', 'seteuid', 'setegid', 'setreuid', 'setregid']

def parse_args():
    parser = argparse.ArgumentParser(description='Process c source code.')
    parser.add_argument('infile', nargs='+', type=argparse.FileType('r'), default=sys.stdin)
    parser.add_argument('-o', dest='outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout)
    args = parser.parse_args()
    return args.infile, args.outfile

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
    if d:
        size = d.group('size')
        if uninit_size(line, linenum, size):
            size = var_dict[size][-1]

        var_dict[d.group('name')] = (d.group('type').strip(), None, linenum, False, None, size)

    m = initialization.match(line)
    if m:
        size = m.group('size')
        if uninit_size(line, linenum, size):
            size = var_dict[size][-1]
        value = m.group('value')
        if value in var_dict:
            value = var_dict[value][1]
        var_dict[m.group('name')] = (m.group('type').strip(), value, linenum, False, None, size)

    r = reassignment.match(line)
    if r and r.group('name') in var_dict:
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
        
        #temporarily disabling keywords check
        #if function not in c_keywords:     #create a key entry for the function function_line#_char#
        key = function+"_"+str(linenum)+"_"+str(line.find(function))
        function_dict[key] = argts

def find_banned(line, linenum):     #TODO: implement in find_functions instead???
    #check for ms_banned functions
    for word in re.split(r'\W+', line):
        if word in ms_banned:
            outfile.writelines("Line " + str(linenum) + ": " + word + "\n")
            outfile.writelines("WARNING: This function is on the Microsoft 'banned list' due to known "
                            "security flaws. See https://msdn.microsoft.com/en-us/library/bb288454.aspx"
                            "for a suggested replacement.\n")
        elif word in clang_banned:
            outfile.writelines("Line " + str(linenum) + ": " + word + "\n")
            outfile.writelines("WARNING: This function " + clang_banned[word][1] + " Please use " + clang_banned[word][0] + " instead.\n")

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

def analyze():
    for infile in infiles:
        code_tuple = [] 
        code = infile.readlines()
        length = 0
        for line in code:
            length += 1
            code_tuple.append([line,length])
    clean_code = multi_comment_remover(code_tuple) #all comments now ignored

    for line in clean_code:
        find_vars(line[0], line[1])
        find_functions(line[0], line[1])
        find_banned(line[0], line[1])
        
    #print(var_dict)
    #print(function_dict)
    return clean_code

# returns the line number of the mmap and munmap, as well as the variable that
# is associated
def word_scope(function_name, exit_name, start_line, end_line, code, funct_dict):
    stack = []
    #end_line = 75
    segment = code[start_line:end_line-1] #code block except for the close/munmap call
    close_re = r".+\W" + exit_name + r"\W.+"
    #print(code[end_line-1]) print the close/munmap call
    #check for if and while
    check_ifStr = 'if'+'_'+str(end_line)+'_'+str(0)
    check_whileStr = 'while'+'_'+str(end_line)+'_'+str(0)
    if funct_dict[check_ifStr]:
        last_str = funct_dict[check_ifStr]
    elif funct_dict[check_whileStr]:
        last_str = funct_dict[check_whileStr]
    #not if or else, can just be normal
    else:
        last_str = code[end_line-1]

    open_brackets = "{("
    close_brackets = "})"
    segment.append(last_str)
    for tup in segment:
        for letter in tup[0]:
            if letter in open_brackets:
                stack.append(letter)
            if letter in close_brackets:
                if letter == "}" and stack[-1] == "{":
                    stack.pop()
                if letter == ")" and stack[-1] == "(":
                    stack.pop()
        #but this could just be any instance of munmap

    #if the call to unmap is normal, the stack structure shoud be ok
    #if the call to unmap is in an if statement, we have to strip the if statement to only use the argument
        #this can be done by checking the function dictionary and the lines for which are called
    #print(code[75][0])
    if re.match(close_re, tup[0]) != None:  # found an instance of munmap 
        #tup[0] is the line with the closing operator 
        print(tup[0])
        if (len(stack) == 0):
            print('empty stack. We gucci.')
        print(stack)


        '''
        if len(stack) == 0:
            print(tup[1])
        else:
            print('Stack unresolved: ', stack,' at line :', tup[1])
            print(tup[0])
            print(tup[0].find('munmap'))
        '''
if __name__ == "__main__":
    # infiles = parse_args()
    # rules = c_ruleset.ruleset()
    infiles, outfile = parse_args()
    #print(outfile.readall())
    logging.basicConfig(level=logging.WARNING)
    logging.warning('started analysis')

    clean_code = analyze()
    logging.warning('done with analysis.')
    #pair_finder(clean_code)
    #word_scope('mmap','munmap',60,75,clean_code, function_dict)
    #print (clean_code)

