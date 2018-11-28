import argparse
import sys
import re
import c_ruleset

def parse_args():
	parser = argparse.ArgumentParser(description='Process c source code.')
	parser.add_argument('infile', nargs='+', type=argparse.FileType('r'), default=sys.stdin)
	parser.add_argument('-o', dest='outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout)
	args = parser.parse_args()
	return args.infile, args.outfile

def analyze(infiles, outfile):
	for infile in infiles:
		i = 0
		outfile.writelines("Analyzing " + infile.name + "...\n")
		for line in infile:
			i+=1
			line = re.split(r'\W+', line)
			for foo in line:
				if foo in c_ruleset.c_ruleset:
					outfile.writelines("Line " + str(i) + ": " + foo + "\n")
					outfile.writelines(c_ruleset.c_ruleset[foo][2] + "\n")

if __name__ == "__main__":
	infiles, outfile = parse_args()
	analyze(infiles, outfile)