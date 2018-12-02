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
    
    for line in clean_code:
        line_number = line[1]
        code = re.split(r'\W+', line[0])
        for word in code:
            if word in rules:
                logging.warning('line '+str(line_number)+': '+word+' used.')


if __name__ == "__main__":
    infiles = parse_args()
    rules = c_ruleset.ruleset()
    #infiles, outfile = parse_args()
    #print(outfile.readall())
    logging.basicConfig(level=logging.WARNING)
    logging.warning('started analysis')
    analyze(infiles, rules)
    logging.warning('done with analysis.')


