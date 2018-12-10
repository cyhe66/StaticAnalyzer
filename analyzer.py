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
    declaration = re.compile(r'\b(?P<type>(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|size_t\s*|'
        r'volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|'
        r'complex\s*)+(?:\*?\*?\s*))(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[(?P<size>\d+)\])?\s*;') 
    #look for variable initialization: 'type name = value'
    initialization = re.compile(r'\b(?P<type>(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|size_t\s*|'
        r'volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|complex\s*)'
        r'+(?:\*?\*?\s*))(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[(?P<size>\d+)\])?\s*=\s*(?P<value>\w*)') 
    #look for variable reassignment: (name [+-/*]= value)
    reassignment = re.compile(r'\b^(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[(?P<size>\d+)\])?\s*[+\-/\*]?=\s*(?P<value>\w*)')
   
    #look for function call: function(params)
    function_match = re.compile(r'[\w]*\s*(?P<var>([\w]*))\s*[=]*\s*(?P<funct>([\w]*))\s*\((?P<args>[^)]+)\)')

    print('entries look like: {variable: (type, value, line of first appearance, isModified, line_modified (if modified) size (if buffer/array))}')
    var_dict = {} #entries look like: {name: (type, value, line of first appearance, isModified, line_modified (if modified) size (if buffer/array))}
    function_dict = {} #entries look like {function: (# of params, param_list)}

    for line in clean_code:
        d = declaration.match(line[0])
        if d:
            size = None
            val = 0
            if d.group('size'):
                size = d.group('size')
                val = [0]*size

            var_dict[d.group('name')] = (d.group('type'), val, line[1], False, None, size, [])

        m = initialization.match(line[0])
        if m:
            # print ("type: ", m.group('type'), ", variable: ", m.group('name'), ", value: ", m.group('value'))
            size = None
            if m.group('size'):
                size = d.group('size')
            var_dict[m.group('name')] = (m.group('type'), m.group('value'), line[1], False, None, size, [])

        r = reassignment.match(line[0])
        if r and r.group('name') in var_dict:
            name = r.group('name')
            var_type = var_dict[name][0]
            first_line = var_dict[name][2]
            var_size = var_dict[name][-1]
            var_dict[name] = (var_type, r.group('value'), first_line, True, line[1], var_size, [])

        f = function_match.match(line[0])
        if f:
            print('var:',f.group('var'), '| function:',f.group('funct'), '| args:',f.group('args'))
            arguments = f.group('args').split(',')
            print(arguments)

        
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
    print(var_dict)
    return clean_code

# returns the line number of the mmap and munmap, as well as the variable that
# is associated
def word_scope(function_name, exit_name, start_line, code):
    stack = []
    end_line = 36
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

