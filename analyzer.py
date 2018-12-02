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

# removes single line comments // and /* */
# replaces it with an empty space ' \n'
def single_comment_remover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
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
            print('commented line ', line)
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
    return code_tuple 

def analyze(infiles):
    for infile in infiles:
        code_tuple = [] 
        code = infile.readlines()
        length = 0
        for line in code:
            length += 1
            code_tuple.append((line,length))
    clean_code = multi_comment_remover(code_tuple) 
    print(clean_code)
    print('done with analysis.')

if __name__ == "__main__":
    infiles = parse_args()
    rules = c_ruleset.ruleset()
    '''
    for key in rules:
        print(key)
    '''
    #infiles, outfile = parse_args()
    #print(outfile.readall())
    logging.basicConfig(level=logging.WARNING)
    analyze(infiles)


