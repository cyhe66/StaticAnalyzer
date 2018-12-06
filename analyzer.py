import logging
import argparse
import getopt
import sys
import re
import c_ruleset

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
        line  = (single_comment_remover(line[0]), line[1]) # string, line#
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
            code_tuple.append((line,length))
    clean_code = multi_comment_remover(code_tuple) #all comments now ignored
    
    vars = {} #entries look like: {name: (type, value, isModified, size (if buffer/array))}
    
    #look for variable declaration: 'type name;'
    declaration = re.compile(r'\b(?P<type>(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|complex\s*)+(?:\*?\*?\s*))(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[\d+\])?\s*;') 
    #look for variable initialization: 'type name = value'
    initialization = re.compile(r'\b(?P<type>(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|complex\s*)+(?:\*?\*?\s*))(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[\d+\])?\s*=\s*(?P<value>\w*)') 
    #look for variable reassignment: (name [+-/*]= value)
    reassignment = re.compile(r'\b^(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[\d+\])?\s*[+\-/\*]?=\s*(?P<value>\w*)')
    
    for line in clean_code:
        line_number = line[1]
        #print(line)
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
def pair_finder(code_tuple):
    open_var = 'mmap'
    close_var = 'munmap'

    for tup in code_tuple:
        #print(re.match(r'.+\Wmmap\W.+', tup[0]))
        regex_str = r".+\W" + open_var + r"\W.+"
        print(re.match(regex_str, tup[0]))
    

'''
function_name -- mmap, malloc
exit_name -- munmap, free
start_line -- # to start checking parentheses
code -- the code tuple [string, line#]
'''

def word_scope(function_name, exit_name, start_line, code):
    stack = []
    print(stack[-1:])
    segment = code[start_line:]
    brackets = "{}()"
    for tup in segment:
        print(tup[0])
        for letter in tup[0]:
            if letter in brackets:
                stack.append(letter)
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
    pair_finder(clean_code)
    #word_scope(1,2,28,clean_code)


