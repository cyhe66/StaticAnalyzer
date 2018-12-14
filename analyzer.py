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
reassignment = re.compile(r'\b^(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[(?P<size>\w+)\])?\s*[+\-/\*]?=\s*(?P<value>\w*)')

#look for function call: var = function(params)
#function_match = re.compile(r'(?P<type>[\w|*]*)\s*(?P<var>([\w]*?))\s*([=]?|\s*?)\s*(?P<funct>([\w]*))\s*\((?P<args>[^)]+)\)')
function_match = re.compile(r'\s*(?P<var>([\w]*?))\s*([=]?|\s*?)\s*(?P<funct>([\w]*))\s*\((?P<args>(.+))\)')

var_dict = {} #entries look like: {name: (type, value, line of first appearance, isModified, line_modified (if modified) size (if buffer/array))}
function_dict = {} #entries look like {function: (# of params, param_list)}

c_keywords = ['auto', 'const', 'double', 'float', 'int', 'short', 
                'struct', 'unsigned', 'break', 'continue', 'else', 
                'for', 'long', 'signed', 'switch', 'void', 'case',
                'default', 'enum', 'goto', 'register', 'sizeof', 
                'typedef', 'volatile', 'char', 'do', 'extern', 'if', 
                'return', 'static', 'union', 'while']

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
        size = None
        if d.group('size'):
            size = d.group('size')
            uninit_subscript(line, linenum, size)

        var_dict[d.group('name')] = (d.group('type').strip(), None, linenum, False, None, size)

    m = initialization.match(line)
    if m:
        size = None
        if m.group('size'):
            size = d.group('size')
            uninit_subscript(line, linenum, size)
        var_dict[m.group('name')] = (m.group('type').strip(), m.group('value'), linenum, False, None, size)

    r = reassignment.match(line)
    if r and r.group('name') in var_dict:
        name = r.group('name')
        var_type = var_dict[name][0]
        first_line = var_dict[name][2]
        var_size = var_dict[name][-1]
        var_dict[name] = (var_type, r.group('value').strip(), first_line, True, linenum, var_size)

def find_functions(line, linenum):
    f = function_match.match(line)
    if f:
        arguments = f.group('args').split(',')
        argts = [item.strip() for item in arguments]
        function = f.group('funct')
        # print("funtion: ", function, "line: ", linenum)
        if function not in c_keywords:
            #create a key entry for the function function_line#_char#
            key = function+"_"+str(linenum)+"_"+str(line.find(function))
            function_dict[key] = argts

def find_banned(line, linenum):
    #check for ms_banned funcitons
    for word in re.split(r'\W+', line):
        if word in ms_banned:
            outfile.writelines("Line " + str(linenum) + ": " + word + "\n")
            outfile.writelines("WARNING: This function is on the Microsoft 'banned list' due to known security flaws. See https://msdn.microsoft.com/en-us/library/bb288454.aspx for a suggested replacement.\n")

def uninit_subscript(line, linenum, var):
    if var in var_dict and var_dict[var][1] == None:
        outfile.writelines("Line " + str(linenum) + ": " + line)
        outfile.writelines("WARNING: Using uninitialized value '" + var + "' to initialize array\n")

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
        
            
    print(var_dict)
    print(function_dict)
    return clean_code

# returns the line number of the mmap and munmap, as well as the variable that
# is associated
def word_scope(function_name, exit_name, start_line, end_line, code):
    stack = []
    #end_line = 75
    segment = code[start_line:end_line]
    open_brackets = "{("
    close_brackets = "})"
    for tup in segment:
        for letter in tup[0]:
            if letter in open_brackets:
                stack.append(letter)
            if letter in close_brackets:
                if letter == "}" and stack[-1] == "{":
                    stack.pop()
                if letter == ")" and stack[-1] == "(":
                    stack.pop()
        close_re = r".+\W" + exit_name + r"\W.+"
        #but this could just be any instance of munmap
    if re.match(close_re, tup[0]) != None:  # found an instance of munmap 
        if len(stack) == 0:
            print(tup[1])
        else:
            print('Stack unresolved: ', stack,' at line :', tup[1])
            print(tup[0])
            print(tup[0].find('munmap'))

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
    # word_scope('mmap','munmap',60,75,clean_code)
    #print (clean_code)

