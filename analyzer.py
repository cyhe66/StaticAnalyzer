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

def comment_remover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    pattern = re.compile(r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"', re.DOTALL | re.MULTILINE)
    return re.sub(pattern, replacer, text)

def analyze(infiles):
    for infile in infiles:
        code_tuple = [] 
        code = infile.readlines()
        length = 0
        for line in code:
            length += 1
            #print(line + str(length))
            code_tuple.append((line,length))
        #print(code_tuple)

        for line in code_tuple:
            line  = (comment_remover(line[0]), line[1])
            print(line)
        '''
        code = "".join(infile.readlines())
        clean_code = comment_remover(code)
        line_number = 0
        for line in clean_code.split('\n'):
            print(line)
            line_number += 1
            line = re.split(r'\W+',line)
            for word in line:
                if word in rules:
                    logging.warning("Line " + str(line_number) + ": " + word + "\n")
        '''
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
