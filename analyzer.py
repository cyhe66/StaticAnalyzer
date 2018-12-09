import logging
import argparse
import getopt
import sys
import re
import c_ruleset

vars = {} #entries look like: {name: (type, value, isModified, size (if buffer/array))}

def parse_args():
    parser = argparse.ArgumentParser(description='Process c source code.')
    parser.add_argument('infile', nargs='+', type=argparse.FileType('r'), default=sys.stdin)
    #parser.add_argument('-o', dest='outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout)
    args = parser.parse_args()
    return args.infile #args.outfile

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
        #remove leading whitespace from line
        for char in line[0]:
            if char in '\t\n\f\r\v ':
                line[0] = line[0][1:]
            else:
                break
        #if in between comment
        if '*/' not in line[0] and in_comment:
            line = (' \n', line[1])
        #if code before comment
        if '/*' in line[0]:
            in_comment = True
            line = (line[0][:line[0].find('/*',0)], line[1])
        #if code after comment
        if '*/' in line[0] and in_comment:
            line = (line[0][line[0].find('*/',0)+2:], line[1])
            in_comment = False
        clean_code.append(line)
    return clean_code 

def analyze(infiles, rules):
    for infile in infiles:
        code_tuple = [] 
        code = infile.readlines()
        length = 0
        for line in code:
            length += 1
            code_tuple.append([line,length])
    clean_code = multi_comment_remover(code_tuple) #all comments now ignored
    
    #look for variable declaration: 'type name;'
    declaration = re.compile(r'\b(?P<type>(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|size_t\s*|volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|complex\s*)+(?:\*?\*?\s*))(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[\d+\])?\s*;') 
    #look for variable initialization: 'type name = value'
    initialization = re.compile(r'\b(?P<type>(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|size_t\s*|volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|complex\s*)+(?:\*?\*?\s*))(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[\d+\])?\s*=\s*(?P<value>\w*)') 
    #look for variable reassignment: (name [+-/*]= value)
    reassignment = re.compile(r'\b^(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[\d+\])?\s*[+\-/\*]?=\s*(?P<value>\w*)')
   
    for line in clean_code:
        init_dict = {}
        declar_dict = {}
        #line_number = line[1]
        '''
        if declaration.match(line[0]):
            print (declaration.match(line[0]), line[1])
        '''
        #if initialization.match(line[0]):
            #init fits the mould of - 
            #print (initialization.match(line[0]).group(0).split())
        #print(initialization.match(line[0]))    #print(line))
        '''
        code = re.split(r'\W+', line[0])
        for word in code:
            if word in rules:
                logging.warning('line '+str(line_number)+': '+word+' used.')
        '''
        """
            if m = assignment.match(word):
                type = m.group(1)
                name = word after type (if not a declaration/initialization, skip)
                if name followed by [ (array/buffer):
                    size = number after [ (if variable, lookup value)
                if next is =:
                    value = number after '='
                elif next is ;:
                    value = 0
                vars[name] = (type, value, False, size?)
        """
    return clean_code

# returns the line number of the mmap and munmap, as well as the variable that
# is associated
'''
NOTE: unneccessary if line dictionary works rn
def pair_finder(code_tuple):
    open_var = 'mmap'
    close_var = 'munmap'

    for tup in code_tuple:
        #print(re.match(r'.+\Wmmap\W.+', tup[0]))
        open_re = r".+\W" + open_var + r"\W.+"
        close_re = r".+\W" + close_var + r"\W.+"
       
        open_line = tup[1] if re.match(open_re, tup[0]) != None else next
        close_line = tup[1] if re.match(close_re, tup[0]) != None else next
    print(open_line, close_line)

function_name -- mmap, malloc
exit_name -- munmap, free
start_line -- # to start checking parentheses
code -- the code tuple [string, line#]
'''

def word_scope(function_name, exit_name, start_line, code):
    stack = []
    end_line = 35
    segment = code[start_line:end_line]
    open_brackets = "{("
    close_brackets = "})"
    for tup in segment:
        for letter in tup[0]:
            if letter in open_brackets:
                stack.append(letter)
            if letter in close_brackets:
                print(letter)
                if letter == "}" and stack[-1] == "{":
                    stack.pop()
                if letter == ")" and stack[-1] == "(":
                    stack.pop()
        if 'munmap' in tup[0]:
            print(tup)
    print(stack)

if __name__ == "__main__":
    infiles = parse_args()
    rules = c_ruleset.ruleset()
    #infiles, outfile = parse_args()
    #print(outfile.readall())
    logging.basicConfig(level=logging.WARNING)
    logging.warning('started analysis')
    clean_code = analyze(infiles, rules)
    logging.warning('done with analysis.')
    #pair_finder(clean_code)
    word_scope('mmap','munmap',30,clean_code)
    #print (clean_code)

