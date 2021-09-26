NAME	:= oversight

### OPTIONS ###
VULN_STACK			:= -fno-stack-protector

CC		:= gcc
OPTIONS	:= -O3 $(VULN_STACK) -fno-omit-frame-pointer -fno-optimize-sibling-calls

all: challenge

challenge:
	$(CC) -o $(NAME) $(OPTIONS) $(NAME).c
